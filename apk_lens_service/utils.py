"""公共工具函数模块。

从多个 endpoint 文件中提取的重复代码，统一维护。
"""

import hashlib
import os
import re
import shutil
import subprocess
import unicodedata
from pathlib import Path
from typing import Mapping


def find_readelf() -> str | None:
    """查找 GNU 或 LLVM 的 ELF 符号查看工具。"""

    return shutil.which("readelf") or shutil.which("llvm-readelf") or shutil.which("greadelf")


def run_command(
    command: list[str],
    timeout: int = 60,
    *,
    env: Mapping[str, str] | None = None,
) -> tuple[int, str, str]:
    """执行外部命令并返回 (returncode, stdout, stderr)。

    Args:
        command: 命令及参数列表。
        timeout: 超时秒数，默认 60。
        env: 可选的子进程环境变量；未提供时继承当前进程环境。

    Returns:
        (returncode, stdout, stderr)，stdout/stderr 已 strip。
        returncode=127 表示命令不存在，124 表示超时。
    """
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=dict(env) if env is not None else None,
        )
        return completed.returncode, completed.stdout.strip(), completed.stderr.strip()
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except subprocess.TimeoutExpired:
        return 124, "", "command timed out"


def java_tool_environment(
    java_home: str | Path | None,
    *,
    max_heap_mb: int | None = None,
) -> dict[str, str]:
    """为 JADX 等 Java 工具构造可审计、与 systemd 环境无关的运行环境。

    ``JAVA_HOME`` 来自外部配置；配置后会校验 ``bin/java``，并只对目标子进程
    增补 PATH，不修改服务进程的全局环境。未配置时允许沿用服务 PATH 中的 Java，
    但若同样找不到则提前给出明确错误，而不是把 Gradle/JADX 的模糊报错向上传递。
    """

    environment = os.environ.copy()
    configured_home = str(java_home or "").strip()
    if configured_home:
        home = Path(configured_home).expanduser().resolve()
        java_bin = home / "bin" / "java"
        if not java_bin.is_file() or not os.access(java_bin, os.X_OK):
            raise FileNotFoundError(
                f"JAVA_HOME 无效，找不到可执行文件: {java_bin}"
            )
        environment["JAVA_HOME"] = str(home)
        current_path = environment.get("PATH", "")
        environment["PATH"] = (
            f"{java_bin.parent}{os.pathsep}{current_path}"
            if current_path
            else str(java_bin.parent)
        )
        if max_heap_mb is not None:
            existing_opts = environment.get("JADX_OPTS", "").strip()
            environment["JADX_OPTS"] = (
                f"{existing_opts} -Xmx{int(max_heap_mb)}m "
                "-XX:+ExitOnOutOfMemoryError"
            ).strip()
        return environment

    if shutil.which("java", path=environment.get("PATH")) is None:
        raise FileNotFoundError(
            "未配置 JAVA_HOME，且服务 PATH 中找不到 java；请在系统配置中填写 Java/JDK 目录"
        )
    if max_heap_mb is not None:
        existing_opts = environment.get("JADX_OPTS", "").strip()
        environment["JADX_OPTS"] = (
            f"{existing_opts} -Xmx{int(max_heap_mb)}m "
            "-XX:+ExitOnOutOfMemoryError"
        ).strip()
    return environment


def calculate_file_md5(file_path: str | Path, chunk_size: int = 65536) -> str:
    """分块计算文件 MD5。

    Args:
        file_path: 文件路径。
        chunk_size: 读取块大小，默认 64KB。

    Returns:
        MD5 十六进制摘要字符串。
    """
    h = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_apk_path(apk_file_path: str) -> Path:
    """校验 APK 路径（存在、是文件、.apk 后缀），返回绝对路径。

    Args:
        apk_file_path: APK 文件路径。

    Returns:
        校验通过的 Path 对象。

    Raises:
        HTTPException(400): 路径不存在、不是文件、或不是 .apk 后缀。
    """
    from fastapi import HTTPException

    apk_file = Path(apk_file_path).expanduser()
    if not apk_file.exists():
        raise HTTPException(status_code=400, detail="APK 文件不存在")
    if not apk_file.is_file():
        raise HTTPException(status_code=400, detail="APK 路径不是文件")
    if apk_file.suffix.lower() != ".apk":
        raise HTTPException(status_code=400, detail="文件不是 APK 安装包")
    return apk_file


def normalize_text(value: object) -> str:
    """将值统一转换为去除首尾空白的字符串。None 返回空字符串。"""
    if value is None:
        return ""
    return str(value).strip()


ZERO_WIDTH_JOINER = "\u200d"

# 应用名称中已观察到 U+200B/U+200C/U+200D/U+2060 被插入可见字母之间，
# 用于破坏连续关键词搜索。这里同时覆盖同类的常见不可见格式控制字符；范围
# 只用于 APP 名称，不用于网络原文、文件路径等必须保持原样的证据字段。
APP_NAME_INVISIBLE_CHARACTERS = (
    "\u00ad"  # SOFT HYPHEN
    "\u200b\u200c\u200d\u200e\u200f"
    "\u202a\u202b\u202c\u202d\u202e"
    "\u2060\u2061\u2062\u2063\u2064"
    "\u2066\u2067\u2068\u2069"
    "\ufeff"
)
_APP_NAME_INVISIBLE_RE = re.compile(
    "[" + re.escape(APP_NAME_INVISIBLE_CHARACTERS) + "]"
)


def strip_zero_width_joiners(value: object) -> str:
    """将值转换为字符串并移除 U+200D 零宽连接符。

    这里只处理已确认会破坏名称搜索的 U+200D，不擅自删除其他 Unicode
    格式字符，也不应用于网络原始报文等需要逐字节保真的证据字段。
    """

    if value is None:
        return ""
    return str(value).replace(ZERO_WIDTH_JOINER, "")


def strip_app_name_invisible_characters(value: object) -> str:
    """移除会让 APP 名称连续关键词搜索失效的不可见格式字符。"""

    if value is None:
        return ""
    return _APP_NAME_INVISIBLE_RE.sub("", str(value))


def clean_md5(value: str) -> str:
    """清理 MD5 值，移除不可见 Unicode 字符（零宽空格、连接符等）。"""

    if not value:
        return value

    # 移除 Unicode 不可见字符:
    # ​ 零宽空格, ‌ 零宽非连接符, ‍ 零宽连接符
    # ⁠ 词连接符, ﻿ 零宽不换行空格, ­ 软连字符
    invisible_chars = re.compile(r'[​‌‍⁠﻿­‎‏‪-‮⁦-⁩]')
    cleaned = invisible_chars.sub('', value)

    # 只保留合法的 MD5 字符 (0-9, a-f)
    cleaned = re.sub(r'[^0-9a-fA-F]', '', cleaned)

    return cleaned.lower()


def normalize_app_name(value: object) -> str:
    """规范化应用名称，保留普通 emoji 和特殊符号。

    处理步骤：
    1. Unicode NFC 规范化
    2. 移除会破坏连续文本搜索的不可见格式字符
    3. \\r\\n\\t 替换为空格
    4. 移除 Cc 类（控制字符）
    5. 折叠连续空白为单空格
    """
    if value is None:
        return ""

    normalized = unicodedata.normalize(
        "NFC", strip_app_name_invisible_characters(value)
    )
    chars: list[str] = []
    for char in normalized:
        if char in "\r\n\t":
            chars.append(" ")
            continue
        if unicodedata.category(char) == "Cc":
            continue
        chars.append(char)

    return re.sub(r"\s+", " ", "".join(chars)).strip()


def looks_like_resource_reference(value: str) -> bool:
    """判断名称是否像未解析成功的 Android 资源引用（如 @0x7f0xxxxx）。"""
    normalized = normalize_app_name(value)
    if not normalized.startswith("@"):
        return False
    if "/" in normalized or ":" in normalized:
        return True
    return normalized in {"@null", "@empty"} or bool(
        re.fullmatch(r"@(?:0[xX])?[0-9a-fA-F]{8}", normalized)
    )


def is_garbled_text(value: str) -> bool:
    """判断字符串是否是乱码（主要由 Unicode 替换字符 U+FFFD 组成）。"""
    if not value:
        return False
    # 如果替换字符占比超过 30%，认为是乱码
    replacement_count = sum(1 for c in value if c == '�' or c == '�')
    return replacement_count / len(value) > 0.3


def is_usable_text(value: str) -> bool:
    """判断字符串是否是真正可用的解析结果（非空、非资源引用、非 'none'、非乱码）。"""
    normalized = normalize_app_name(value)
    if not normalized:
        return False
    if looks_like_resource_reference(normalized):
        return False
    if normalized.lower() == "none":
        return False
    if is_garbled_text(normalized):
        return False
    return True


def dedupe_keep_order(values: list[str]) -> list[str]:
    """按原顺序去重。"""
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            deduped.append(value)
            seen.add(value)
    return deduped


def _build_dotted_java_name(relative_path: Path) -> str:
    """将 Java 文件的相对路径转换为点分隔的类路径。"""
    parts = list(relative_path.parts)
    if parts and parts[-1].endswith(".java"):
        parts[-1] = parts[-1][:-5]
    return ".".join(parts)


def collect_java_source_structure(sources_dir: str | Path) -> dict:
    """扫描 Java 源码目录，返回文件列表、类路径、包名。

    Args:
        sources_dir: jadx 反编译输出的 sources 目录路径。

    Returns:
        {
            "sources_dir": str,
            "java_file_count": int,
            "package_count": int,
            "package_names": list[str],
            "java_files": list[str],       # 相对路径
            "java_dotted_files": list[str], # 点分隔类路径
        }
    """
    sources_dir = Path(sources_dir)
    if not sources_dir.exists():
        return {
            "sources_dir": str(sources_dir),
            "java_file_count": 0,
            "package_count": 0,
            "package_names": [],
            "java_files": [],
            "java_dotted_files": [],
        }

    java_paths = sorted(
        [p for p in sources_dir.rglob("*.java") if p.is_file()],
        key=lambda item: str(item),
    )

    java_files = [str(p.relative_to(sources_dir).as_posix()) for p in java_paths]
    java_dotted_files = [_build_dotted_java_name(p.relative_to(sources_dir)) for p in java_paths]
    package_names = sorted(
        {
            ".".join(p.relative_to(sources_dir).parent.parts)
            for p in java_paths
            if p.relative_to(sources_dir).parent.parts
        }
    )

    return {
        "sources_dir": str(sources_dir),
        "java_file_count": len(java_files),
        "package_count": len(package_names),
        "package_names": package_names,
        "java_files": java_files,
        "java_dotted_files": java_dotted_files,
    }
