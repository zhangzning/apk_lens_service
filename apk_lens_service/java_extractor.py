"""Java 源码结构化提取器。

用 javalang 把单个反编译 .java 文件解析成结构化 dict：
类（含 super/interfaces/access_flags/ast_json）→ 方法（签名/参数/行号/方法体）→ 字段。

设计要点（javalang 实测坑点）：
- 构造函数在 .constructors，不在 .methods
- .position 只有 start_line，无 end_line（按成员 start 排序推算）
- 一个 FieldDeclaration 可含多个 declarator（int a,b,c; → 3 行）
- extends/implements 是 ReferenceType，需遍历 .sub_type 拼限定名
- 反编译代码偶有不规范语法，解析失败走 fallback（仅存结构）
"""

import logging
from pathlib import Path

import javalang
from javalang.tree import (
    ClassDeclaration,
    ConstructorDeclaration,
    EnumDeclaration,
    InterfaceDeclaration,
    MethodDeclaration,
    Node,
)

logger = logging.getLogger("apk_lens_service.java_extractor")

# JVM/Android access flags 位掩码
MODIFIER_BITS = {
    "public": 0x1,
    "private": 0x2,
    "protected": 0x4,
    "static": 0x8,
    "final": 0x10,
    "synchronized": 0x20,
    "volatile": 0x40,
    "transient": 0x80,
    "native": 0x100,
    "interface": 0x200,
    "abstract": 0x400,
    "strict": 0x800,
    "synthetic": 0x1000,
    "annotation": 0x2000,
    "enum": 0x4000,
}


def _modifiers_to_access_flags(modifiers) -> int:
    """把 javalang modifiers（set[str]）转成 JVM 位掩码整数。"""
    flags = 0
    for m in modifiers or []:
        flags |= MODIFIER_BITS.get(m, 0)
    return flags


def _reference_type_to_name(ref_type) -> str:
    """遍历 ReferenceType.sub_type 链拼限定名（如 com.b.Bar）。泛型可能不准，简单名兜底。"""
    if ref_type is None:
        return ""
    parts = []
    cur = ref_type
    seen = 0
    while cur is not None and seen < 10:  # 防环
        name = getattr(cur, "name", None)
        if name:
            parts.append(name)
        cur = getattr(cur, "sub_type", None)
        seen += 1
    return ".".join(parts) if parts else getattr(ref_type, "name", "") or ""


def _serialize_ast(node, depth: int = 0):
    """递归把 javalang AST 节点转成 JSON-safe 结构。

    每个递归点独立 try：单点失败返回 None，不拖垮整体（避免一个异常节点让整个 ast 丢失）。
    """

    def safe(value, d):
        try:
            return _inner(value, d)
        except Exception:
            return None

    def _inner(node, d):
        if d > 24:
            return "..."
        if node is None or isinstance(node, (str, int, float, bool)):
            return node
        if isinstance(node, list):
            return [safe(x, d + 1) for x in node]
        # Position 对象（有 line/column，非 Node）
        if hasattr(node, "line") and hasattr(node, "column") and not isinstance(node, Node):
            return {"line": getattr(node, "line", None), "column": getattr(node, "column", None)}
        if isinstance(node, Node):
            result = {"_type": type(node).__name__}
            for attr in node.attrs:  # node.attrs 是属性（list），不是方法
                result[attr] = safe(getattr(node, attr, None), d + 1)
            return result
        return str(node)

    return safe(node, depth)


def _build_signature(name: str, params) -> str:
    """构造方法签名 name(type1,type2)。"""
    types = []
    for p in params or []:
        t = getattr(p, "type", None)
        types.append(_reference_type_to_name(t) or getattr(t, "name", "?") if t else "?")
    return f"{name}({','.join(types)})"


def _extract_params(params) -> list[dict]:
    """提取参数列表 [{name, type}]。"""
    out = []
    for p in params or []:
        t = getattr(p, "type", None)
        out.append({
            "name": getattr(p, "name", "") or "",
            "type": _reference_type_to_name(t) or (getattr(t, "name", "") if t else ""),
        })
    return out


def _member_start_line(member) -> int:
    """取成员的 start_line（position 可能为 None）。"""
    pos = getattr(member, "position", None)
    return pos.line if pos else 0


def _slice_lines(source_lines: list[str], start: int, end: int) -> str:
    """按 1-based 行号切片源码。"""
    if start <= 0:
        start = 1
    if end <= 0 or end > len(source_lines):
        end = len(source_lines)
    if start > end:
        start = end
    return "\n".join(source_lines[start - 1:end])


def _extract_method(member, source_lines: list[str], end_line: int, is_ctor: bool) -> dict:
    """提取单个方法/构造函数。"""
    start = _member_start_line(member)
    return_type = "" if is_ctor else _reference_type_to_name(getattr(member, "return_type", None))
    name = getattr(member, "name", "")
    return {
        "method_name": name,
        "signature": _build_signature(name, getattr(member, "parameters", None)),
        "return_type": return_type,
        "parameters": _extract_params(getattr(member, "parameters", None)),
        "access_flags": _modifiers_to_access_flags(getattr(member, "modifiers", None)),
        "start_line": start,
        "end_line": end_line,

        "is_constructor": is_ctor,
    }


def _extract_fields(field_decl) -> list[dict]:
    """展开 FieldDeclaration 的多个 declarator 为多行。"""
    ftype = _reference_type_to_name(getattr(field_decl, "type", None)) or \
        (getattr(getattr(field_decl, "type", None), "name", "") or "")
    flags = _modifiers_to_access_flags(getattr(field_decl, "modifiers", None))
    out = []
    for decl in getattr(field_decl, "declarators", []) or []:
        init = getattr(decl, "initializer", None)
        init_val = ""
        if init is not None:
            # 简单字面量取 value，复杂表达式取类型名
            val = getattr(init, "value", None)
            if val is not None:
                init_val = str(val)
            else:
                init_val = type(init).__name__
        out.append({
            "field_name": getattr(decl, "name", "") or "",
            "field_type": ftype,
            "access_flags": flags,
            "initial_value": init_val[:2000],  # 截断超长初始化
        })
    return out


def _extract_class(type_node, source_lines: list[str], source_file: str) -> dict:
    """提取单个顶层类/接口/枚。"""
    modifiers = getattr(type_node, "modifiers", None) or set()
    class_type = "class"
    if isinstance(type_node, InterfaceDeclaration):
        class_type = "interface"
        modifiers = set(modifiers) | {"interface"}
    elif isinstance(type_node, EnumDeclaration):
        class_type = "enum"
        modifiers = set(modifiers) | {"enum"}
    elif "abstract" in modifiers:
        class_type = "abstract"

    access_flags = _modifiers_to_access_flags(modifiers)
    class_name = getattr(type_node, "name", "") or ""
    package = ""  # 由 extract_java_file 填充
    super_class = _reference_type_to_name(getattr(type_node, "extends", None))
    interfaces = [
        _reference_type_to_name(r) for r in (getattr(type_node, "implements", None) or [])
    ]

    # 收集所有有 position 的成员（方法+构造函数）用于推算 end_line
    methods_raw = list(getattr(type_node, "methods", None) or [])
    constructors = list(getattr(type_node, "constructors", None) or [])
    fields_decl = list(getattr(type_node, "fields", None) or [])

    # 构造成员列表（带 start_line）用于 end_line 推算
    members_for_line = [
        (m, _member_start_line(m), False) for m in methods_raw
    ] + [
        (c, _member_start_line(c), True) for c in constructors
    ]
    members_for_line = [m for m in members_for_line if m[1] > 0]
    members_for_line.sort(key=lambda x: x[1])
    class_last_line = len(source_lines)

    methods = []
    for i, (member, start, is_ctor) in enumerate(members_for_line):
        end = members_for_line[i + 1][1] - 1 if i + 1 < len(members_for_line) else class_last_line
        methods.append(_extract_method(member, source_lines, end, is_ctor))

    fields = []
    for fd in fields_decl:
        fields.extend(_extract_fields(fd))

    # ast_json：精简结构化（类元数据 + 成员签名树）。
    # 完整 javalang AST 序列化 + 递归清洗太慢（4765 类 × 几十KB AST），改存精简结构，
    # 够后续分析用且快；需要完整语法树时从文件系统重新读取。
    ast_json = {
        "class_type": class_type,
        "super_class": super_class,
        "interfaces": interfaces,
        "access_flags": access_flags,
        "method_count": len(methods),
        "field_count": len(fields),
        "methods": [{"n": m["method_name"], "s": m["signature"], "r": m["return_type"],
                     "f": m["access_flags"], "sl": m["start_line"], "el": m["end_line"],
                     "c": m["is_constructor"]} for m in methods],
        "fields": [{"n": f["field_name"], "t": f["field_type"], "f": f["access_flags"]} for f in fields],
    }

    return {
        "class_name": class_name,
        "package_name": package,  # 待填充
        "super_class": super_class,
        "interfaces": interfaces,
        "access_flags": access_flags,
        "class_type": class_type,
        "source_file": source_file,
        "line_count": class_last_line,

        "ast_json": ast_json,
        "methods": methods,
        "fields": fields,
    }


def _fallback(java_path: Path, source_lines: list[str], source_file: str, package: str) -> dict:
    """javalang 解析失败的兜底：仅存类名等结构，无方法/字段。"""
    class_name = java_path.stem
    return {
        "source_file": source_file,
        "package_name": package,
        "parse_status": "fallback",
        "classes": [{
            "class_name": class_name,
            "package_name": package,
            "super_class": "",
            "interfaces": [],
            "access_flags": 0,
            "class_type": "class",
            "source_file": source_file,
            "line_count": len(source_lines),
            "ast_json": None,
            "methods": [],
            "fields": [],
        }],
    }


def _infer_package_from_path(java_path: Path, sources_root: Path | None = None) -> str:
    """从路径推断包名（sources/com/example/Foo.java → com.example）。"""
    try:
        if sources_root is not None:
            rel = java_path.relative_to(sources_root).parent
            return ".".join(rel.parts) if rel.parts else ""
    except ValueError:
        pass
    return ""


def extract_java_file(java_path: Path, source_file: str | None = None,
                      sources_root: Path | None = None) -> dict:
    """解析单个 .java 文件 → 结构化 dict。

    Args:
        java_path: .java 文件绝对路径。
        source_file: 相对 sources/ 的路径（用于 source_file 字段），默认用文件名。
        sources_root: sources 根目录（用于 fallback 时推断包名）。

    Returns:
        {source_file, package_name, parse_status, classes:[...]}
        parse_status: "ok" | "fallback"
    """
    src = java_path.read_text(encoding="utf-8", errors="replace")
    source_lines = src.splitlines()
    sf = source_file or java_path.name

    try:
        tree = javalang.parse.parse(src)
    except Exception as exc:
        logger.debug("javalang 解析失败（走兜底）: %s, %s", java_path.name, exc)
        return _fallback(java_path, source_lines, sf, _infer_package_from_path(java_path, sources_root))

    package = ""
    if tree.package:
        package = getattr(tree.package, "name", "") or ""

    classes = []
    for type_node in (tree.types or []):
        try:
            cls = _extract_class(type_node, source_lines, sf)
            cls["package_name"] = package
            classes.append(cls)
        except Exception as exc:
            logger.debug("类提取失败: %s, %s", getattr(type_node, "name", "?"), exc)
            # 单个类失败不影响整体，跳过该类（兜底由文件级处理）
            continue

    # 所有类都提取失败 → 整文件兜底
    if not classes:
        return _fallback(java_path, source_lines, sf, package or _infer_package_from_path(java_path, sources_root))

    return {
        "source_file": sf,
        "package_name": package,
        "parse_status": "ok",
        "classes": classes,
    }
