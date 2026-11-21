"""APK 基础解析服务。

提供 APK 基础信息解析、图标提取、组件提取、文件树提取等能力。
从 API 层解耦，供多个上层模块复用。
"""

import logging
import re
import shutil
import tempfile
import warnings as py_warnings
import xml.etree.ElementTree as ET
from contextlib import contextmanager, nullcontext
from datetime import datetime
from io import BytesIO
from pathlib import Path
from zipfile import BadZipFile, ZIP_STORED, ZipFile

from androguard.core.apk import APK
from androguard.core.axml import AXMLPrinter
from PIL import Image

from apk_lens_service.apk_names import DISPLAY_LOCALES, Labels, name_fields, read_badging_labels, read_manifest_labels
from apk_lens_service.config import parse_tools as settings
from apk_lens_service.manifest import (
    MAX_MANIFEST_BYTES, declarations, launcher_activity, local_tag, manifest_fields, manifest_requires_streaming,
    read_binary_manifest, read_legacy_xmltree, read_permission_dump, read_streamed_manifest, read_xmltree,
    requested_permissions,
)
from apk_lens_service.utils import (
    calculate_file_md5,
    dedupe_keep_order,
    is_usable_text,
    normalize_text,
    run_command,
    strip_zero_width_joiners,
    validate_apk_path,
)

logger = logging.getLogger("apk_lens_service.apk_parser")

ICON_IMAGE_SUFFIXES = {".png", ".webp", ".jpg", ".jpeg"}
ICON_XML_SUFFIXES = {".xml"}
ICON_RESOURCE_KEYS = ("ic_launcher", "ic_launcher_round", "app_icon", "icon", "logo")
AAPT2_RESOURCE_LINE_RE = re.compile(r"^\s*resource\s+(0x[0-9a-fA-F]{8})\b")
AAPT2_MANIFEST_RESOURCE_REF_RE = re.compile(
    r"android:(?:icon|roundIcon)(?:\([^)]*\))?=@(?:0x)?([0-9a-fA-F]{8})\b"
)
AAPT2_FILE_MARKER = " (file) "
MAX_AAPT2_RESOURCE_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_METADATA_RESOURCES_BYTES = 256 * 1024 * 1024
MAX_ICON_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_ICON_DIMENSION = 4096
MAX_ICON_PIXELS = 16 * 1024 * 1024
MAX_ICON_COMPRESSION_RATIO = 200
MAX_ICON_CANDIDATES_PER_GROUP = 64
MAX_ICON_PRIMARY_GROUPS = 32
MAX_ICON_FALLBACK_CANDIDATES = 128
MAX_RESOURCE_ALIAS_DEPTH = 64
MAX_RESOURCE_ALIAS_VISITS = 4096
DENSITY_SCORES = {
    "xxxhdpi": 70,
    "xxhdpi": 60,
    "xhdpi": 50,
    "hdpi": 40,
    "mdpi": 30,
    "ldpi": 20,
    "nodpi": 10,
    "anydpi": 5,
}


def append_warning(warnings: list[str], message: str) -> None:
    """记录解析告警，避免同一条提示重复追加。"""

    if message not in warnings:
        warnings.append(message)


@contextmanager
def _aapt2_metadata_view(apk_file: Path, warnings: list[str], *, include_resources: bool = True):
    """为 ZIP 偏移畸形 APK 构造一个有界、只读的 aapt2 元数据视图。

    某些样本会在 ZIP 中间插入数据，却不修正后续 local-header/CD 偏移。
    AndroidManifest.xml 和 resources.arsc 的内容仍可能被 Python ZipFile 的
    concat-offset 容错读出，而 aapt2 会在打开原文件时直接拒绝。这里仅将这
    两个元数据条目写入临时 ZIP 供 aapt2 解析；原 APK、签名块和沙箱安装源
    均不做任何修改。

    条目数量和解压后大小均固定受限，避免对不可信 APK 做全量修复或触发
    ZIP bomb。临时文件无论成功失败都会删除。
    """

    metadata_limits = {"AndroidManifest.xml": MAX_MANIFEST_BYTES}
    if include_resources:
        metadata_limits["resources.arsc"] = MAX_METADATA_RESOURCES_BYTES
    metadata: dict[str, bytes] = {}
    temp_path: Path | None = None

    try:
        with ZipFile(apk_file, "r") as source:
            if sum(entry.filename == "AndroidManifest.xml" for entry in source.infolist()) != 1:
                raise ValueError("必须存在唯一的 AndroidManifest.xml")
            for archive_name, size_limit in metadata_limits.items():
                try:
                    info = source.getinfo(archive_name)
                except KeyError:
                    if archive_name == "AndroidManifest.xml":
                        raise ValueError("缺少 AndroidManifest.xml") from None
                    continue

                if info.is_dir():
                    raise ValueError(f"元数据条目不是文件: {archive_name}")
                if info.flag_bits & 0x1:
                    raise ValueError(f"元数据条目已加密: {archive_name}")
                if info.file_size <= 0 or info.file_size > size_limit:
                    raise ValueError(
                        f"元数据条目大小异常: {archive_name}={info.file_size}"
                    )

                content = source.read(info)
                if len(content) != info.file_size:
                    raise ValueError(
                        f"元数据条目读取不完整: {archive_name}="
                        f"{len(content)}/{info.file_size}"
                    )
                metadata[archive_name] = content

        handle = tempfile.NamedTemporaryFile(
            prefix="apk-lens-metadata-",
            suffix=".apk",
            delete=False,
        )
        temp_path = Path(handle.name)
        handle.close()
        with ZipFile(temp_path, "w", compression=ZIP_STORED, allowZip64=False) as target:
            for archive_name, content in metadata.items():
                target.writestr(archive_name, content)

    except Exception as exc:  # noqa: BLE001 - 畸形 ZIP 的异常类型不固定
        append_warning(warnings, f"aapt2 元数据恢复失败: {exc}")
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError as cleanup_exc:
                logger.warning("清理失败的 aapt2 临时元数据视图异常: %s", cleanup_exc)
        yield None
        return

    try:
        yield temp_path
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError as exc:
                logger.warning("清理 aapt2 临时元数据视图失败: %s", exc)


def safe_call(label: str, warnings: list[str], func, default=None):
    """执行单个解析动作，失败时只记录告警，不中断整体流程。"""

    try:
        return func()
    except Exception as exc:  # noqa: BLE001 - 容错需要吞掉单字段异常
        append_warning(warnings, f"{label} 解析失败: {exc}")
        return default


def resolve_resource_reference(
    apk: APK,
    resource_ref: str,
    warnings: list[str],
    seen_refs: set[str] | None = None,
) -> list[str]:
    """将资源引用解析成 APK 包内的实际文件路径候选。"""

    normalized_ref = normalize_text(resource_ref)
    if not normalized_ref:
        return []

    if seen_refs is None:
        seen_refs = set()
    if normalized_ref in seen_refs:
        return []
    seen_refs.add(normalized_ref)

    if normalized_ref.startswith("res/"):
        return [normalized_ref]

    if not normalized_ref.startswith("@"):
        return []

    res_parser = safe_call("resources.arsc", warnings, apk.get_android_resources, None)
    if not res_parser:
        return []

    try:
        res_id, package_name = res_parser.parse_id(normalized_ref)
    except Exception as exc:  # noqa: BLE001
        append_warning(warnings, f"图标资源引用解析失败: {normalized_ref} ({exc})")
        return []

    if package_name and package_name == "android":
        return []

    resolved_candidates: list[str] = []
    try:
        resolved_configs = res_parser.get_resolved_res_configs(res_id)
    except Exception as exc:  # noqa: BLE001
        append_warning(warnings, f"图标资源 ID 解析失败: {normalized_ref} ({exc})")
        return []

    for _, resolved_value in resolved_configs:
        resolved_text = normalize_text(resolved_value)
        if not resolved_text:
            continue
        if resolved_text.startswith("@"):
            resolved_candidates.extend(
                resolve_resource_reference(apk, resolved_text, warnings, seen_refs)
            )
        elif resolved_text.startswith("res/"):
            resolved_candidates.append(resolved_text)
        elif _looks_like_archive_path(resolved_text):
            # 混淆 APK 常把资源路径改写成任意字符（不含 res/ 前缀、无扩展名），
            # 只要形态是相对路径就保留为候选，由后续按魔数嗅探图片内容。
            resolved_candidates.append(resolved_text)

    return dedupe_keep_order(resolved_candidates)


def _looks_like_archive_path(value: str) -> bool:
    """判断 ARSC 解析结果是否是包内相对路径（而非颜色/字符串资源值）。"""

    if "/" not in value:
        return False
    if value.startswith(("/", "\\")) or any(ch.isspace() for ch in value):
        return False
    return True


def score_icon_candidate(archive_path: str) -> int:
    """给图标候选路径打分，优先选择更像应用图标的资源。"""

    lower_path = archive_path.lower()
    score = 0

    suffix = Path(lower_path).suffix
    if suffix in ICON_IMAGE_SUFFIXES:
        score += 200
    elif suffix in ICON_XML_SUFFIXES:
        score += 120

    if "/mipmap" in lower_path:
        score += 80
    elif "/drawable" in lower_path:
        score += 60

    if "launcher" in lower_path:
        score += 70
    if "icon" in lower_path:
        score += 60
    if "logo" in lower_path:
        score += 30
    # adaptive icon 的图层并不是可直接展示的完整应用图标。兜底扫描时
    # 应优先同目录下的 legacy 完整图标，图层仅在没有其他候选时使用。
    if "foreground" in lower_path:
        score -= 40
    if "background" in lower_path:
        score -= 200
    if "monochrome" in lower_path:
        score -= 160

    for density, density_score in DENSITY_SCORES.items():
        if density in lower_path:
            score += density_score
            break

    return score


def collect_archive_icon_candidates(apk_file: Path) -> list[str]:
    """在 APK 压缩包中兜底扫描具备明确图标语义的资源文件。

    加固 APK 常把所有资源名混淆成随机字符串。Manifest 解析失败时，不能
    从全包任取第一张图片，否则极易把按钮、电话、相机等业务图片当成应用
    图标。这里只保留名称具备 icon/launcher/logo 语义，或位于标准 mipmap
    目录中的候选；权威的混淆路径由 aapt2 单独提供。
    """

    try:
        with ZipFile(apk_file, "r") as zip_file:
            zip_names = zip_file.namelist()
    except (BadZipFile, OSError):
        return []

    candidates = []
    for name in zip_names:
        lower_name = name.lower()
        if not name.startswith("res/"):
            continue
        if Path(name).suffix.lower() not in ICON_IMAGE_SUFFIXES | ICON_XML_SUFFIXES:
            continue
        has_icon_semantics = any(key in lower_name for key in ICON_RESOURCE_KEYS)
        is_standard_mipmap = bool(
            re.match(r"^res/mipmap(?:-[^/]+)?/", lower_name)
        )
        if has_icon_semantics or is_standard_mipmap:
            candidates.append(name)

    return sorted(
        dedupe_keep_order(candidates),
        key=lambda item: (-score_icon_candidate(item), item),
    )


def extract_aapt2_icon_candidates(badging_output: str) -> list[str]:
    """从 ``aapt2 dump badging`` 中提取 Manifest 图标的原始 ZIP 路径。

    路径可能包含 Unicode、空格和反斜杠，不能使用 ``split()`` 拆分。
    Activity 显式图标优先于 application 图标，符合 Android 覆盖规则。
    """

    application_candidates: list[str] = []
    activity_candidates: list[str] = []

    for raw_line in badging_output.splitlines():
        line = raw_line.strip()
        if line.startswith("application-icon-"):
            match = re.match(r"^application-icon-[^:]+:'(.*)'$", line)
            if match and match.group(1):
                application_candidates.append(match.group(1))
            continue

        if line.startswith("application:"):
            match = re.search(r"(?:^|\s)icon='([^']*)'", line)
            if match and match.group(1):
                application_candidates.append(match.group(1))
            continue

        if line.startswith("launchable-activity:"):
            match = re.search(r"(?:^|\s)icon='([^']*)'", line)
            if match and match.group(1):
                activity_candidates.append(match.group(1))

    return dedupe_keep_order(activity_candidates + application_candidates)


def extract_aapt2_manifest_icon_resource_refs(
    xmltree_output: str,
    main_activity: str = "",
) -> list[str]:
    """从 ``aapt2 dump xmltree`` 恢复 Manifest 原始图标资源 ID。

    部分恶意/畸形 APK 把 ``android:icon`` 指向 ``type=id``。Android 的资源
    表底层仍可能保留各密度图片，但 aapt2 badging 会把 icon 输出为空，
    Androguard 的 Manifest 属性层也可能返回 ``None``。xmltree 仍会保留原始
    ``@0x7f......`` ID，因此这里仅从 application 和已确认的启动 Activity
    读取资源引用，避免把任意 Activity 的业务图片误当成应用图标。

    返回顺序遵守 Android 覆盖规则：启动 Activity 图标优先于 application
    icon，roundIcon 只作为同一节点的后备。
    """

    normalized_main_activity = normalize_text(main_activity)
    nodes: list[dict[str, object]] = []
    stack: list[tuple[int, dict[str, object]]] = []

    for raw_line in xmltree_output.splitlines():
        stripped = raw_line.strip()
        indent = len(raw_line) - len(raw_line.lstrip())
        element_match = re.match(r"^E:\s+([^\s(]+)", stripped)
        if element_match:
            while stack and stack[-1][0] >= indent:
                stack.pop()
            node: dict[str, object] = {
                "tag": element_match.group(1),
                "name": "",
                "icon_refs": [],
            }
            nodes.append(node)
            stack.append((indent, node))
            continue

        if not stack or not stripped.startswith("A:"):
            continue

        current = stack[-1][1]
        name_match = re.search(
            r'android:name(?:\([^)]*\))?="([^"]+)"',
            stripped,
        )
        if name_match:
            current["name"] = name_match.group(1)

        icon_match = AAPT2_MANIFEST_RESOURCE_REF_RE.search(stripped)
        if icon_match:
            icon_refs = current["icon_refs"]
            if isinstance(icon_refs, list):
                icon_refs.append(f"@{icon_match.group(1).lower()}")

    activity_refs: list[str] = []
    application_refs: list[str] = []
    for node in nodes:
        refs = node.get("icon_refs")
        if not isinstance(refs, list) or not refs:
            continue
        tag = str(node.get("tag", ""))
        if tag in {"activity", "activity-alias"}:
            if (
                normalized_main_activity
                and normalize_text(node.get("name", ""))
                == normalized_main_activity
            ):
                activity_refs.extend(str(ref) for ref in refs)
        elif tag == "application":
            application_refs.extend(str(ref) for ref in refs)

    return dedupe_keep_order(activity_refs + application_refs)


def collect_aapt2_manifest_icon_candidate_groups(
    apk_file: Path,
    apk: APK | None,
    warnings: list[str],
) -> list[list[str]]:
    """用 xmltree 原始资源 ID 和 ARSC 底层值恢复畸形 APK 图标。

    这是 Manifest/aapt2/Androguard 常规路径全部拿不到图标时的权威后备，
    不是全包图片猜测。只有已经成功构造 Androguard 资源表时才启用。
    """

    if apk is None:
        return []

    aapt2_path = shutil.which(settings.aapt2_bin)
    if not aapt2_path:
        return []

    code, stdout, stderr = run_command(
        [
            aapt2_path,
            "dump",
            "xmltree",
            str(apk_file),
            "--file",
            "AndroidManifest.xml",
        ],
        timeout=60,
    )
    if code != 0:
        append_warning(warnings, f"aapt2 Manifest 图标 ID 解析失败: {stderr[:200]}")
        return []

    main_activity = normalize_text(
        safe_call("主 Activity", warnings, apk.get_main_activity, "")
    )
    resource_refs = extract_aapt2_manifest_icon_resource_refs(
        stdout,
        main_activity,
    )

    groups: list[list[str]] = []
    for resource_ref in resource_refs[:MAX_ICON_PRIMARY_GROUPS]:
        resolved = resolve_resource_reference(apk, resource_ref, warnings)
        if resolved:
            groups.append(resolved[:MAX_ICON_CANDIDATES_PER_GROUP])

    if groups:
        append_warning(
            warnings,
            "Manifest 图标类型异常，已通过原始资源 ID 恢复图标",
        )
    return groups


def parse_aapt2_resource_file_groups(
    resources_output: str,
) -> dict[str, list[str]]:
    """解析 aapt2 资源表，返回 ``资源 ID -> 文件密度变体`` 映射。

    同时解析 ``资源 ID -> 别名 ID -> 文件`` 链，并通过环检测做有界递归。
    """

    groups: dict[str, list[str]] = {}
    aliases: dict[str, list[str]] = {}
    current_resource_id = ""
    current_type = ""
    type_match_re = re.compile(r"^\s*type\s+([A-Za-z0-9_]+)\s+id=")
    # 只在这些资源类型下接受无扩展名的混淆路径；字符串/颜色等值类型
    # 的带引号内容不是文件，必须排除。
    file_backed_types = {"drawable", "mipmap", "raw", "font", "xml"}

    for raw_line in resources_output.splitlines():
        resource_match = AAPT2_RESOURCE_LINE_RE.match(raw_line)
        if resource_match:
            current_resource_id = resource_match.group(1).lower()
            groups.setdefault(current_resource_id, [])
            aliases.setdefault(current_resource_id, [])
            continue

        type_match = type_match_re.match(raw_line)
        if type_match:
            current_type = type_match.group(1).lower()
            continue

        if not current_resource_id:
            continue

        archive_path = ""
        if AAPT2_FILE_MARKER in raw_line:
            archive_path = raw_line.split(AAPT2_FILE_MARKER, 1)[1].strip()
            archive_path = re.sub(
                r"\s+type=[A-Za-z0-9_]+$",
                "",
                archive_path,
            )
        else:
            # aapt2 对部分被混淆到 res/ 外的 XML/图片不打印 ``(file)``，
            # 而使用 ``(density) "raw/zip/path"`` 形式。
            quoted_path_match = re.match(
                r'^\s+\([^)]*\)\s+"(.*)"\s*$',
                raw_line,
            )
            if quoted_path_match:
                archive_path = quoted_path_match.group(1)

        if archive_path and (
            Path(archive_path).suffix.lower()
            in ICON_IMAGE_SUFFIXES | ICON_XML_SUFFIXES
            # 混淆 APK 的资源文件可能没有扩展名；drawable/mipmap 等
            # 文件型资源条目下的值必然是包内文件，交由魔数嗅探兜底。
            or current_type in file_backed_types
        ):
            groups[current_resource_id].append(archive_path)

        alias_match = re.match(
            r"^\s+\([^)]*\)\s+@(?:0x)?([0-9a-fA-F]{8})\b",
            raw_line,
        )
        if alias_match:
            aliases[current_resource_id].append(
                f"0x{alias_match.group(1).lower()}"
            )

    resolved_cache: dict[str, list[str]] = {}

    def resolve_group(resource_id: str) -> list[str]:
        """迭代解析别名，限制深度/节点数并天然终止环。"""

        if resource_id in resolved_cache:
            return resolved_cache[resource_id]

        resolved: list[str] = []
        visited: set[str] = set()
        stack: list[tuple[str, int]] = [(resource_id, 0)]
        while stack and len(visited) < MAX_RESOURCE_ALIAS_VISITS:
            current_id, depth = stack.pop()
            if current_id in visited:
                continue
            visited.add(current_id)
            resolved.extend(groups.get(current_id, []))
            if depth >= MAX_RESOURCE_ALIAS_DEPTH:
                continue
            for target_id in reversed(aliases.get(current_id, [])):
                if target_id not in visited:
                    stack.append((target_id, depth + 1))

        resolved = dedupe_keep_order(resolved)
        resolved_cache[resource_id] = resolved
        return resolved

    return {
        resource_id: resolved_paths
        for resource_id in groups
        if (resolved_paths := resolve_group(resource_id))
    }


def expand_aapt2_icon_candidate_groups(
    apk_file: Path,
    icon_candidates: list[str],
    warnings: list[str],
) -> tuple[list[list[str]], dict[str, list[str]]]:
    """把每个 badging 路径分别反查为同一资源 ID 的密度变体组。

    ``aapt2 dump badging`` 在 Android 8+ APK 上通常只返回 adaptive icon
    XML；同一资源块里仍可能存在适合 Web 展示的 legacy PNG/WebP。反查后
    可在同一权威资源组内优先选择像素最大的完整图片。不同 Manifest 属性
    保持独立，避免小尺寸 Activity 图标被更大的 application 图标覆盖。
    """

    candidates = dedupe_keep_order(icon_candidates)[:MAX_ICON_PRIMARY_GROUPS]
    if not candidates:
        return [], {}

    aapt2_path = shutil.which(settings.aapt2_bin)
    if not aapt2_path:
        append_warning(warnings, f"aapt2 不可用: {settings.aapt2_bin}")
        return [[candidate] for candidate in candidates], {}

    code, stdout, stderr = run_command(
        [aapt2_path, "dump", "resources", str(apk_file)],
        timeout=60,
    )
    if code != 0:
        append_warning(warnings, f"aapt2 图标资源解析失败: {stderr[:200]}")
        return [[candidate] for candidate in candidates], {}
    if len(stdout.encode("utf-8", errors="ignore")) > MAX_AAPT2_RESOURCE_OUTPUT_BYTES:
        append_warning(warnings, "aapt2 图标资源输出过大，已跳过资源变体展开")
        return [[candidate] for candidate in candidates], {}

    resource_groups = parse_aapt2_resource_file_groups(stdout)
    path_to_group: dict[str, list[str]] = {}
    for paths in resource_groups.values():
        for archive_path in paths:
            path_to_group.setdefault(archive_path, paths)

    expanded_groups: list[list[str]] = []
    seen_groups: set[tuple[str, ...]] = set()
    for candidate in candidates:
        group = dedupe_keep_order(path_to_group.get(candidate, [candidate]))
        group_key = tuple(group)
        if group_key in seen_groups:
            continue
        seen_groups.add(group_key)
        expanded_groups.append(group)

    return expanded_groups, resource_groups


def expand_aapt2_icon_candidates(
    apk_file: Path,
    icon_candidates: list[str],
    warnings: list[str],
) -> tuple[list[str], dict[str, list[str]]]:
    """兼容旧调用方：展平 aapt2 图标候选组。"""

    groups, resource_files = expand_aapt2_icon_candidate_groups(
        apk_file,
        icon_candidates,
        warnings,
    )
    return [candidate for group in groups for candidate in group], resource_files


def collect_aapt2_icon_candidates(
    apk_file: Path,
    warnings: list[str],
) -> list[str]:
    """单独调用 aapt2 获取 Manifest 图标候选，供重新分析流程复用。"""

    aapt2_path = shutil.which(settings.aapt2_bin)
    if not aapt2_path:
        append_warning(warnings, f"aapt2 不可用: {settings.aapt2_bin}")
        return []

    code, stdout, stderr = run_command(
        [aapt2_path, "dump", "badging", str(apk_file)],
        timeout=60,
    )
    if code != 0:
        append_warning(warnings, f"aapt2 图标定位失败: {stderr[:200]}")
        return []

    return extract_aapt2_icon_candidates(stdout)


def collect_icon_candidate_groups(
    apk: APK,
    package_name: str,
    warnings: list[str],
) -> list[list[str]]:
    """按来源优先级汇总图标候选，每组只包含同一资源引用的变体。"""

    candidate_groups: list[list[str]] = []
    seen_candidates: set[str] = set()

    def append_group(group_candidates: list[str]) -> None:
        group = [
            candidate
            for candidate in dedupe_keep_order(group_candidates)
            if candidate not in seen_candidates
        ]
        if not group:
            return
        candidate_groups.append(group)
        seen_candidates.update(group)

    def resolve_icon_reference(resource_ref: str) -> list[str]:
        if not resource_ref:
            return []
        if resource_ref.startswith("res/"):
            return [resource_ref]
        return resolve_resource_reference(apk, resource_ref, warnings)

    main_activity = normalize_text(safe_call("主 Activity", warnings, apk.get_main_activity, ""))
    # 显式 manifest 引用优先；主 Activity 若单独声明 icon，会覆盖 application icon。
    direct_icon_refs = [
        normalize_text(
            safe_call(
                "主 Activity 图标",
                warnings,
                lambda: apk.get_attribute_value("activity", "icon", name=main_activity),
                "",
            )
        ),
        normalize_text(
            safe_call(
                "application icon",
                warnings,
                lambda: apk.get_attribute_value("application", "icon"),
                "",
            )
        ),
        normalize_text(safe_call("应用图标", warnings, apk.get_app_icon, "")),
        normalize_text(
            safe_call(
                "application roundIcon",
                warnings,
                lambda: apk.get_attribute_value("application", "roundIcon"),
                "",
            )
        ),
    ]

    for resource_ref in direct_icon_refs:
        append_group(resolve_icon_reference(resource_ref))

    # 仅作为 manifest 解析不完整时的低优先级候选；不同命名资源不能
    # 与 application icon 混在一起按文件大小竞争。
    res_parser = safe_call("图标资源表", warnings, apk.get_android_resources, None)
    if res_parser and package_name:
        for resource_type in ("mipmap", "drawable"):
            for resource_key in ICON_RESOURCE_KEYS:
                resource_id = safe_call(
                    f"{resource_type}/{resource_key}",
                    warnings,
                    lambda current_type=resource_type, current_key=resource_key: res_parser.get_res_id_by_key(
                        package_name,
                        current_type,
                        current_key,
                    ),
                    None,
                )
                if resource_id:
                    append_group(
                        resolve_resource_reference(
                            apk,
                            f"@{resource_id:08x}",
                            warnings,
                        )
                    )

    return candidate_groups


def collect_icon_candidates(
    apk: APK,
    package_name: str,
    warnings: list[str],
) -> list[str]:
    """以来源优先级展平图标候选，保留旧调用方的数据格式。"""

    return [
        candidate
        for group in collect_icon_candidate_groups(apk, package_name, warnings)
        for candidate in group
    ]


def parse_icon_xml_candidates(
    apk: APK | None,
    archive_path: str,
    icon_bytes: bytes,
    warnings: list[str],
    aapt2_resource_files: dict[str, list[str]] | None = None,
) -> list[str]:
    """解析 adaptive icon 等 XML 资源，继续向下定位真实图片文件。"""

    xml_root = None

    try:
        axml_printer = AXMLPrinter(icon_bytes)
        if axml_printer.is_valid():
            xml_root = axml_printer.get_xml_obj()
    except Exception as exc:  # noqa: BLE001
        append_warning(warnings, f"二进制图标 XML 解析失败: {archive_path} ({exc})")

    if xml_root is None:
        try:
            xml_root = ET.fromstring(icon_bytes)
        except ET.ParseError as exc:
            append_warning(warnings, f"图标 XML 兜底解析失败: {archive_path} ({exc})")
            return []

    root_tag = str(xml_root.tag).rsplit("}", 1)[-1].lower()
    is_adaptive_icon = root_tag in {"adaptive-icon", "adaptive_icon"}
    nested_candidates: list[str] = []
    for element in xml_root.iter():
        element_tag = str(element.tag).rsplit("}", 1)[-1].lower()
        # background 通常只是纯色/底图，monochrome 是供系统着色的蒙版；
        # 完整 legacy 图标或 foreground 更适合作为 Web 缩略图。
        if is_adaptive_icon and element_tag in {"background", "monochrome"}:
            continue
        for attr_value in element.attrib.values():
            normalized_value = normalize_text(attr_value)
            if normalized_value.startswith("@") or normalized_value.startswith("res/"):
                resolved_candidates: list[str] = []
                if apk is not None:
                    resolved_candidates.extend(
                        resolve_resource_reference(apk, normalized_value, warnings)
                    )

                # Androguard 可能因畸形 Manifest 无法构造或无法解析资源表，
                # 此时继续使用 aapt2 dump resources 的 ID 映射解析 XML 引用。
                resource_id_match = re.fullmatch(
                    r"@(?:0x)?([0-9a-fA-F]{8})",
                    normalized_value,
                )
                if resource_id_match and aapt2_resource_files:
                    resource_id = f"0x{resource_id_match.group(1).lower()}"
                    resolved_candidates.extend(
                        aapt2_resource_files.get(resource_id, [])
                    )

                nested_candidates.extend(resolved_candidates)

    return dedupe_keep_order(nested_candidates)


def save_icon_bytes(apk_md5: str, archive_path: str, icon_bytes: bytes) -> str:
    """将提取出的图标字节落盘，并返回本地绝对路径。

    规则：
    - 文件后缀统一小写
    - webp 格式转换为 png（与 web 端约定）
    """

    settings.icon_storage_dir.mkdir(parents=True, exist_ok=True)
    suffix = Path(archive_path).suffix.lower() or ".png"
    if suffix not in ICON_IMAGE_SUFFIXES:
        suffix = ".png"

    # webp 转 png
    if suffix == ".webp":
        try:
            from PIL import Image
            img = Image.open(BytesIO(icon_bytes))
            output = BytesIO()
            img.save(output, format="PNG")
            icon_bytes = output.getvalue()
            suffix = ".png"
        except Exception as exc:
            logger.warning("WebP 转 PNG 失败: %s, 使用原格式: %s", archive_path, exc)

    icon_path = settings.icon_storage_dir / f"{apk_md5}{suffix}"
    icon_path.write_bytes(icon_bytes)
    return str(icon_path.resolve())


def read_bounded_archive_member(
    zip_file: ZipFile,
    archive_path: str,
    warnings: list[str],
) -> bytes | None:
    """有界读取不可信 APK 成员，避免图标候选触发 ZIP 解压炸弹。"""

    try:
        member = zip_file.getinfo(archive_path)
    except KeyError:
        return None

    if member.file_size > MAX_ICON_ARCHIVE_BYTES:
        append_warning(warnings, f"图标候选文件过大，已跳过: {archive_path}")
        return None

    if (
        member.file_size > 1024 * 1024
        and (
            member.compress_size <= 0
            or member.file_size / member.compress_size > MAX_ICON_COMPRESSION_RATIO
        )
    ):
        append_warning(warnings, f"图标候选压缩比异常，已跳过: {archive_path}")
        return None

    try:
        return zip_file.read(member)
    except (KeyError, OSError, RuntimeError):
        return None


def _sniff_image_magic(data: bytes) -> bool:
    """按文件头魔数识别常见图标图片（PNG/WebP/JPEG/GIF）。

    混淆 APK 常把资源文件改成无扩展名路径，后缀判断会漏掉真实图片。
    """

    if len(data) < 12:
        return False
    if data[:4] == b"RIFF":
        return data[8:12] == b"WEBP"
    return data.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF8"))


def select_best_icon_image(
    zip_file: ZipFile,
    zip_names: set[str],
    candidates: list[str],
    warnings: list[str],
) -> tuple[str, bytes] | None:
    """从同一资源引用的密度变体中选择像素面积最大的可用图片。"""

    best_image: tuple[str, bytes] | None = None
    best_quality: tuple[int, int, int, int] | None = None

    for index, archive_path in enumerate(candidates[:MAX_ICON_CANDIDATES_PER_GROUP]):
        if archive_path not in zip_names:
            continue

        icon_bytes = read_bounded_archive_member(zip_file, archive_path, warnings)
        if icon_bytes is None:
            continue

        # 有图片扩展名的直接信任；无扩展名（混淆路径）按魔数嗅探内容。
        if (
            Path(archive_path).suffix.lower() not in ICON_IMAGE_SUFFIXES
            and not _sniff_image_magic(icon_bytes)
        ):
            continue

        try:
            with py_warnings.catch_warnings():
                py_warnings.simplefilter("error", Image.DecompressionBombWarning)
                with Image.open(BytesIO(icon_bytes)) as image:
                    width, height = image.size
                    if (
                        width <= 0
                        or height <= 0
                        or width > MAX_ICON_DIMENSION
                        or height > MAX_ICON_DIMENSION
                        or width * height > MAX_ICON_PIXELS
                    ):
                        append_warning(
                            warnings,
                            f"图标候选像素尺寸异常，已跳过: {archive_path}",
                        )
                        continue
                    image.load()
        except Exception:  # noqa: BLE001 - 损坏/不支持的图片交给后续候选兜底
            continue

        # 像素面积优先，文件字节数只作为同尺寸时的质量兜底；最后保留
        # 原候选顺序，避免不同编码方式意外改变来源优先级。
        quality = (width * height, min(width, height), len(icon_bytes), -index)
        if best_quality is None or quality > best_quality:
            best_image = (archive_path, icon_bytes)
            best_quality = quality

    return best_image


def extract_app_icon(
    apk: APK | None,
    apk_file: Path,
    apk_md5: str,
    package_name: str,
    warnings: list[str],
    aapt2_icon_candidates: list[str] | None = None,
) -> dict[str, object]:
    """尽量稳地提取图标。

    提取顺序如下：
    1. 优先使用 aapt2/Androguard 从 Manifest 定位的权威图标资源。
    2. aapt2 单一路径反查同资源 ID 的全部密度变体，优先完整 legacy 图。
    3. 如果只有 adaptive icon XML，则继续解析其 foreground。
    4. 最后只扫描具有明确图标语义的 `res/` 资源，不随机选择业务图片。
    """

    androguard_groups = (
        collect_icon_candidate_groups(apk, package_name, warnings)
        if apk is not None
        else []
    )

    # 正常 APK 先尝试 Androguard，成功时不额外执行 aapt2；只有实际候选
    # 不可读时才延迟调用。身份回退已经给出 aapt2 候选时则直接优先使用。
    aapt2_deferred = aapt2_icon_candidates is None and bool(androguard_groups)
    if aapt2_icon_candidates is None:
        if aapt2_deferred:
            raw_aapt2_candidates: list[str] = []
        else:
            raw_aapt2_candidates = collect_aapt2_icon_candidates(apk_file, warnings)
    else:
        raw_aapt2_candidates = list(aapt2_icon_candidates)

    aapt2_groups, aapt2_resource_files = expand_aapt2_icon_candidate_groups(
        apk_file,
        raw_aapt2_candidates,
        warnings,
    )

    # 某些畸形 APK 的 android:icon 指向 type=id：badging 和 Manifest
    # 属性层都返回空，但 ARSC 底层仍保存真实密度图片。只有常规权威来源
    # 完全为空时才读取 xmltree 原始 ID，避免增加正常 APK 的解析成本。
    manifest_id_groups: list[list[str]] = []
    manifest_id_recovery_attempted = False
    if not aapt2_groups and not androguard_groups:
        manifest_id_recovery_attempted = True
        manifest_id_groups = collect_aapt2_manifest_icon_candidate_groups(
            apk_file,
            apk,
            warnings,
        )

    # 当身份已经回退到 aapt2 时，其 badging 结果比畸形 Androguard Manifest
    # 更可信，因此置于首位；正常 APK 没有 aapt2 候选，仍沿用原有顺序。
    primary_groups: list[list[str]] = list(aapt2_groups)
    primary_groups.extend(androguard_groups)
    primary_groups.extend(manifest_id_groups)
    primary_groups = primary_groups[:MAX_ICON_PRIMARY_GROUPS]
    primary_candidates = [
        candidate for group in primary_groups for candidate in group
    ]
    fallback_candidates = collect_archive_icon_candidates(apk_file)
    fallback_queue = [
        candidate for candidate in fallback_candidates if candidate not in primary_candidates
    ][:MAX_ICON_FALLBACK_CANDIDATES]

    if not primary_candidates and not fallback_queue:
        return {
            "icon_path": "",
            "icon_source": "",
            "icon_candidates": [],
        }

    tried_candidates: list[str] = []
    visited_candidates: set[str] = set()

    try:
        with ZipFile(apk_file, "r") as zip_file:
            zip_names = set(zip_file.namelist())

            def try_candidate_group(group: list[str]) -> tuple[str, bytes] | None:
                """解析单一来源组；legacy 图片优先于 adaptive icon 图层。"""

                group_queue = dedupe_keep_order(group)[:MAX_ICON_CANDIDATES_PER_GROUP]
                while group_queue:
                    unread_candidates = [
                        candidate
                        for candidate in group_queue
                        if candidate not in visited_candidates
                    ]
                    best_image = select_best_icon_image(
                        zip_file,
                        zip_names,
                        unread_candidates,
                        warnings,
                    )
                    image_candidates = [
                        candidate
                        for candidate in unread_candidates
                        if Path(candidate).suffix.lower() in ICON_IMAGE_SUFFIXES
                    ]
                    for candidate in image_candidates:
                        visited_candidates.add(candidate)
                        tried_candidates.append(candidate)
                    if best_image is not None:
                        return best_image

                    xml_path = next(
                        (
                            candidate
                            for candidate in unread_candidates
                            if Path(candidate).suffix.lower() in ICON_XML_SUFFIXES
                        ),
                        None,
                    )
                    if xml_path is None:
                        break

                    visited_candidates.add(xml_path)
                    tried_candidates.append(xml_path)
                    xml_bytes = read_bounded_archive_member(
                        zip_file,
                        xml_path,
                        warnings,
                    )
                    if xml_bytes is None:
                        group_queue.remove(xml_path)
                        continue

                    nested_candidates = parse_icon_xml_candidates(
                        apk,
                        xml_path,
                        xml_bytes,
                        warnings,
                        aapt2_resource_files,
                    )
                    group_queue.extend(
                        candidate
                        for candidate in nested_candidates
                        if candidate not in group_queue
                        and candidate not in visited_candidates
                    )
                    if len(group_queue) > MAX_ICON_CANDIDATES_PER_GROUP:
                        del group_queue[MAX_ICON_CANDIDATES_PER_GROUP:]

                return None

            # 每个资源引用独立选择最高分辨率，保持 activity/application/
            # roundIcon/命名兜底之间的来源优先级。
            for primary_group in primary_groups:
                best_image = try_candidate_group(primary_group)
                if best_image is None:
                    continue
                archive_path, archive_bytes = best_image
                return {
                    "icon_path": save_icon_bytes(apk_md5, archive_path, archive_bytes),
                    "icon_source": archive_path,
                    "icon_candidates": tried_candidates,
                }

            # Androguard 有时能给出非空但不存在/损坏的资源路径；实际尝试
            # 失败后再调用 aapt2，避免半畸形 APK 直接落入启发式扫描。
            if aapt2_deferred:
                lazy_candidates = collect_aapt2_icon_candidates(apk_file, warnings)
                lazy_groups, lazy_resource_files = expand_aapt2_icon_candidate_groups(
                    apk_file,
                    lazy_candidates,
                    warnings,
                )
                aapt2_resource_files.update(lazy_resource_files)
                for lazy_group in lazy_groups[:MAX_ICON_PRIMARY_GROUPS]:
                    for candidate in lazy_group:
                        visited_candidates.discard(candidate)
                    best_image = try_candidate_group(lazy_group)
                    if best_image is None:
                        continue
                    archive_path, archive_bytes = best_image
                    return {
                        "icon_path": save_icon_bytes(
                            apk_md5,
                            archive_path,
                            archive_bytes,
                        ),
                        "icon_source": archive_path,
                        "icon_candidates": tried_candidates,
                    }

            # 常规来源可能给出非空但不存在、损坏或格式不支持的候选；只有
            # 所有权威候选实际读取失败后，才执行一次 xmltree/ARSC 恢复。
            # 放在全包启发式扫描之前，避免被随机业务图片抢占。
            if not manifest_id_recovery_attempted:
                manifest_id_recovery_attempted = True
                late_manifest_groups = collect_aapt2_manifest_icon_candidate_groups(
                    apk_file,
                    apk,
                    warnings,
                )
                for late_group in late_manifest_groups[:MAX_ICON_PRIMARY_GROUPS]:
                    for candidate in late_group:
                        visited_candidates.discard(candidate)
                    best_image = try_candidate_group(late_group)
                    if best_image is None:
                        continue
                    archive_path, archive_bytes = best_image
                    return {
                        "icon_path": save_icon_bytes(
                            apk_md5,
                            archive_path,
                            archive_bytes,
                        ),
                        "icon_source": archive_path,
                        "icon_candidates": tried_candidates,
                    }

            # 全包扫描是最后兜底，继续按 score_icon_candidate 的既有顺序；
            # XML 展开的同源 foreground 仍会在组内选取最高分辨率。
            for fallback_candidate in fallback_queue:
                best_image = try_candidate_group([fallback_candidate])
                if best_image is None:
                    continue
                archive_path, archive_bytes = best_image
                return {
                    "icon_path": save_icon_bytes(apk_md5, archive_path, archive_bytes),
                    "icon_source": archive_path,
                    "icon_candidates": tried_candidates,
                }
    except (BadZipFile, OSError) as exc:
        append_warning(warnings, f"APK 压缩包读取失败: {exc}")

    return {
        "icon_path": "",
        "icon_source": "",
        "icon_candidates": tried_candidates,
    }


def _parse_aapt2_badging(
    apk_file: Path,
    *,
    aapt2_path: str,
    stdout: str,
    parser_used: str,
    warnings: list[str],
    streamed_manifest: ET.Element | None = None,
) -> dict | None:
    """解析一次成功的 aapt2 badging 输出，并补取启动 Activity。"""

    result: dict = {}
    for line in stdout.split("\n"):
        line = line.strip()
        if line.startswith("package:"):
            for part in line.split():
                if "=" in part:
                    key, _, val = part.partition("=")
                    val = val.strip("'\"")
                    if key == "name":
                        result["package_name"] = val
                    elif key == "versionCode":
                        result["version_code"] = val
                    elif key == "versionName":
                        result["version_name"] = val
        elif line.startswith("sdkVersion:") or line.startswith("minSdkVersion:"):
            result["min_sdk_version"] = line.split(":")[1].strip().strip("'\"")
        elif line.startswith("targetSdkVersion:"):
            result["target_sdk_version"] = line.split(":")[1].strip().strip("'\"")
        elif line.startswith("launchable-activity:"):
            match = re.search(r"name='([^']+)'", line)
            if match:
                result["main_activity"] = match.group(1)

    icon_candidates = extract_aapt2_icon_candidates(stdout)
    if icon_candidates:
        result["icon_candidates"] = icon_candidates

    if "main_activity" not in result:
        package = result.get("package_name", "")
        if streamed_manifest is not None and package and package == streamed_manifest.get("package"):
            result["main_activity"] = launcher_activity(streamed_manifest, package)
        else:
            result["main_activity"] = _extract_main_activity_from_xmltree(
                apk_file,
                aapt2_path=aapt2_path,
            )

    if result:
        for key in (
            "package_name",
            "version_name",
            "version_code",
            "min_sdk_version",
            "target_sdk_version",
            "main_activity",
        ):
            if key in result:
                result[key] = strip_zero_width_joiners(result[key]).strip()
        labels, reported = read_badging_labels(stdout, parser_used)
        result.update(name_fields(labels, result.get("package_name", ""), badging=reported))
        result["parser_used"] = parser_used

    return result or None


def parse_apk_with_aapt2(
    apk_file: Path, warnings: list[str], streamed_manifest: ET.Element | None = None,
) -> dict | None:
    """使用 aapt2 解析 APK 基础信息（androguard 失败时的备用方案）。

    aapt2 若因 ZIP 中央目录偏移畸形而拒绝原文件，会再尝试一个只包含
    Manifest/资源表的临时元数据视图。原始文件用于计算摘要及读取签名。
    """

    aapt2_path = shutil.which(settings.aapt2_bin)
    if not aapt2_path:
        append_warning(warnings, f"aapt2 不可用: {settings.aapt2_bin}")
        return None

    code, stdout, stderr = run_command(
        [aapt2_path, "dump", "badging", str(apk_file)],
        timeout=60,
    )
    if code == 0:
        result = _parse_aapt2_badging(
            apk_file,
            aapt2_path=aapt2_path,
            stdout=stdout,
            parser_used="aapt2",
            warnings=warnings,
            streamed_manifest=streamed_manifest,
        )
        if result and streamed_manifest is None:
            append_warning(warnings, "androguard 解析不完整，使用 aapt2 备用解析")
        return result

    append_warning(warnings, f"aapt2 原文件解析失败: {stderr[:200]}")
    with _aapt2_metadata_view(apk_file, warnings) as metadata_apk:
        if metadata_apk is None:
            return None

        recovered_code, recovered_stdout, recovered_stderr = run_command(
            [aapt2_path, "dump", "badging", str(metadata_apk)],
            timeout=60,
        )
        if recovered_code != 0:
            append_warning(
                warnings,
                f"aapt2 元数据视图解析失败: {recovered_stderr[:200]}",
            )
            return None

        result = _parse_aapt2_badging(
            metadata_apk,
            aapt2_path=aapt2_path,
            stdout=recovered_stdout,
            parser_used="aapt2_metadata_view",
            warnings=warnings,
        )

    if result:
        append_warning(
            warnings,
            "APK ZIP 索引畸形，已使用只读元数据视图恢复身份；原始 APK 未修改",
        )
        logger.warning(
            "APK ZIP 索引畸形，已通过只读元数据视图恢复身份: path=%s package=%s",
            apk_file,
            result.get("package_name", ""),
        )
    return result


def _extract_main_activity_from_xmltree(
    apk_file: Path,
    *,
    aapt2_path: str = "",
) -> str:
    root, _ = read_xmltree(apk_file, aapt2_path or settings.aapt2_bin)
    if root is None or not (package := root.get("package", "")):
        return ""
    return launcher_activity(root, package)


def _handle_apkfile_basic_runtime(
    apk_file_path: str,
    *,
    prefer_aapt2: bool = False,
) -> tuple[dict, APK | None, ET.Element | None]:
    """解析 APK 基础信息并返回 JSON 可序列化字典。

    当前字段与 APP_BASIC_INFO 落表场景保持对齐，重点包括：
    - MD5 / 文件路径 / 文件大小
    - 应用名称（优先中文名称）
    - 包名 / 版本 / SDK / 主 Activity
    - 图标落地路径
    - 依赖库信息
    """

    apk_file = validate_apk_path(apk_file_path)
    apk_md5 = calculate_file_md5(apk_file)
    file_size = apk_file.stat().st_size
    warnings: list[str] = []
    streamed_manifest = None
    streamed_package = ""
    if manifest_requires_streaming(apk_file):
        streamed_manifest, problem = read_streamed_manifest(apk_file)
        if streamed_manifest is not None:
            streamed_package = streamed_manifest.get("package", "").strip()
            if not streamed_package or streamed_package.startswith(("@", "?")):
                streamed_manifest = None
                problem = "流式 Manifest 缺少可读取的包名"
        if streamed_manifest is None:
            append_warning(warnings, problem)

    parsed_data: dict = {
        "apk_path": str(apk_file.resolve()),
        "file_path": str(apk_file.resolve()),
        "apk_md5": apk_md5,
        "md5": apk_md5,
        "file_size": file_size,
        "package_name": "",
        "version_name": "",
        "version_code": "",
        "min_sdk_version": "",
        "target_sdk_version": "",
        "main_activity": "",
        "libraries": [],
        "library": "",
        "icon_path": "",
        "icon_source": "",
        "icon_candidates": [],
        "parser_used": "androguard",
        "parse_warnings": warnings,
        "jadx_summary": {},
        "create_datetime": datetime.now().isoformat(timespec="seconds"),
    }

    apk: APK | None = None
    aapt2_icon_candidates: list[str] | None = None
    labels: Labels = {}
    badging_names: dict[str, str] = {}
    has_garbled_name = False
    androguard_valid = False
    if prefer_aapt2:
        parsed_data["parser_used"] = "aapt2_forced"
        append_warning(warnings, "Androguard隔离解析超时，已切换aapt2降级模式")
    elif streamed_manifest is None:
        try:
            apk = APK(str(apk_file))
        except Exception as exc:  # noqa: BLE001
            # 加固样本可能通过畸形 AXML 让 Androguard 在构造阶段失败。这里不能
            # 直接返回，否则已经安装好的 aapt2 兜底永远没有执行机会。
            parsed_data["parser_used"] = "androguard_failed"
            append_warning(warnings, f"androguard 初始化失败: {exc}")

    if apk is not None:
        androguard_valid = bool(
            safe_call(
                "APK有效性",
                warnings,
                getattr(apk, "is_valid_APK", lambda: True),
                False,
            )
        )
        if not androguard_valid:
            append_warning(warnings, "androguard 判定 APK/Manifest 结构无效")

        package_name = normalize_text(safe_call("包名", warnings, apk.get_package, ""))
        parsed_data["package_name"] = package_name

        labels, has_garbled_name = safe_call(
            "应用名称",
            warnings,
            lambda: read_manifest_labels(apk, package_name),
            ({}, False),
        )

        parsed_data["version_name"] = normalize_text(
            safe_call("版本名称", warnings, apk.get_androidversion_name, "")
        )

        version_code = safe_call("版本号", warnings, apk.get_androidversion_code, None)
        parsed_data["version_code"] = normalize_text(version_code)

        parsed_data["min_sdk_version"] = normalize_text(
            safe_call("minSdkVersion", warnings, apk.get_min_sdk_version, "")
        )
        parsed_data["target_sdk_version"] = normalize_text(
            safe_call("targetSdkVersion", warnings, apk.get_target_sdk_version, "")
        )
        parsed_data["main_activity"] = normalize_text(
            safe_call("主 Activity", warnings, apk.get_main_activity, "")
        )

    # 包名或名称缺失、名称乱码、Androguard 初始化失败时，都独立执行 aapt2。
    # 沙箱启动真正依赖 package_name，不能让畸形 Manifest 把任务永久挡在预检。
    need_aapt2_fallback = (
        apk is None
        or not androguard_valid
        or not parsed_data["package_name"]
        or not any(locale in labels for locale in DISPLAY_LOCALES)
        or has_garbled_name
    )
    if need_aapt2_fallback:
        aapt2_result = parse_apk_with_aapt2(apk_file, warnings, streamed_manifest)
        if aapt2_result:
            for key in ("package_name", "version_name", "version_code", "min_sdk_version", "target_sdk_version", "main_activity"):
                if aapt2_result.get(key) and not parsed_data.get(key):
                    parsed_data[key] = aapt2_result[key]
            tool = aapt2_result.get("parser_used") or "aapt2"
            parsed_data["parser_used"] = tool
            names = aapt2_result.get("app_names", {})
            for locale, label in names.get("localized", {}).items():
                labels.setdefault(locale, (label, tool))
            default = names.get("default") if names else aapt2_result.get("app_name")
            if isinstance(default, str) and is_usable_text(default):
                labels.setdefault("default", (default, tool))
            badging_names = names.get("badging_reported_labels", {})
            aapt2_icon_candidates = list(
                aapt2_result.get("icon_candidates") or []
            )
        else:
            # 标记已经尝试过，避免图标流程重复执行同一失败命令。
            aapt2_icon_candidates = []

    if not any(locale in labels for locale in DISPLAY_LOCALES):
        aapt = shutil.which("aapt")
        if aapt:
            code, stdout, _ = run_command([aapt, "dump", "badging", str(apk_file)], timeout=15)
            if code == 0:
                aapt_labels, reported = read_badging_labels(stdout, "aapt")
                for locale, label in aapt_labels.items():
                    labels.setdefault(locale, label)
                badging_names.update(reported)

    # 归一化包名后再选择显示名，包名是最后一级回退。
    for key in (
        "package_name",
        "version_name",
        "version_code",
        "min_sdk_version",
        "target_sdk_version",
        "main_activity",
    ):
        parsed_data[key] = strip_zero_width_joiners(parsed_data.get(key)).strip()

    if streamed_manifest is not None:
        if parsed_data["package_name"] and parsed_data["package_name"] != streamed_package:
            append_warning(warnings, "流式 Manifest 的包名与已读取的包名不一致")
            streamed_manifest = None
        else:
            manifest_data, _ = manifest_fields(streamed_manifest)
            if not parsed_data["package_name"]:
                parsed_data["package_name"] = streamed_package
                parsed_data["parser_used"] = "axml_stream"
            for key in ("version_name", "version_code", "min_sdk_version", "target_sdk_version", "main_activity"):
                if not parsed_data[key]:
                    parsed_data[key] = manifest_data.get(key, "")

    if not parsed_data["package_name"]:
        parsed_data["parser_used"] = "identity_unresolved"
        append_warning(
            warnings,
            "APK 身份解析失败：androguard 与 aapt2 均未得到包名",
        )

    parsed_data.update(name_fields(labels, parsed_data["package_name"], badging=badging_names))
    parsed_data["has_garbled_name"] = has_garbled_name

    parsed_data["manifest_components_status"] = (
        "unavailable" if apk is None else "ok" if androguard_valid else "partial"
    )
    if apk is not None:
        libraries = safe_call("uses-library", warnings, apk.get_libraries, []) or []
        if not isinstance(libraries, list):
            libraries = list(libraries)
        parsed_data["libraries"] = [
            strip_zero_width_joiners(item) for item in libraries
        ]
        parsed_data["library"] = ",".join(parsed_data["libraries"])

    # 即使 Androguard 构造失败，aapt2 仍可能定位到可直接读取的图片资源。
    icon_result = extract_app_icon(
        apk=apk,
        apk_file=apk_file,
        apk_md5=apk_md5,
        package_name=parsed_data["package_name"],
        warnings=warnings,
        aapt2_icon_candidates=aapt2_icon_candidates,
    )
    parsed_data["icon_path"] = normalize_text(icon_result.get("icon_path"))
    parsed_data["icon_source"] = normalize_text(icon_result.get("icon_source"))
    parsed_data["icon_candidates"] = icon_result.get("icon_candidates", [])

    return parsed_data, apk, streamed_manifest


def handle_apkfile_basic(
    apk_file_path: str,
    *,
    prefer_aapt2: bool = False,
) -> dict:
    """公开的基础解析入口；运行时 APK 对象不会泄露给 API 调用方。"""

    parsed, _apk, _manifest = _handle_apkfile_basic_runtime(
        apk_file_path,
        prefer_aapt2=prefer_aapt2,
    )
    return parsed


def extract_manifest_components(apk: APK, warnings: list[str]) -> dict:
    """从 APK manifest 中提取权限、活动、服务、广播接收器、内容提供者。

    Returns:
        {
            "permissions": ["android.permission.INTERNET", ...],
            "activities": ["com.example.MainActivity", ...],
            "services": ["com.example.MyService", ...],
            "receivers": ["com.example.MyReceiver", ...],
            "providers": ["com.example.MyProvider", ...],
        }
    """

    return {
        "permissions": list(safe_call("permissions", warnings, apk.get_permissions, []) or []),
        "activities": list(safe_call("activities", warnings, apk.get_activities, []) or []),
        "services": list(safe_call("services", warnings, apk.get_services, []) or []),
        "receivers": list(safe_call("receivers", warnings, apk.get_receivers, []) or []),
        "providers": list(safe_call("providers", warnings, apk.get_providers, []) or []),
    }


def _set_manifest_declarations(parsed: dict, root) -> None:
    parsed["manifest_declared_permissions"], complete = declarations(root)
    parsed["manifest_declared_permissions_status"] = "ready" if complete else "partial"


def _recover_manifest_components(
    apk_file: Path, parsed: dict, warnings: list[str], streamed_manifest: ET.Element | None,
) -> None:
    expected = parsed["package_name"]
    best = None
    aapt2_reader = ("aapt2", lambda path: read_xmltree(path, settings.aapt2_bin))
    legacy = (("aapt", read_legacy_xmltree),) if shutil.which("aapt") else ()
    for temporary_view in (False, True):
        binary = () if temporary_view else (("apkinspector_axml", read_binary_manifest),)
        streamed = (
            (("axml_stream", lambda _: (streamed_manifest, "")),)
            if not temporary_view and streamed_manifest is not None else ()
        )
        readers = (*streamed, aapt2_reader, *binary, *legacy)
        context = (
            _aapt2_metadata_view(apk_file, warnings, include_resources=False)
            if temporary_view else nullcontext(apk_file)
        )
        with context as path:
            if path is None:
                break
            for tool, read in readers:
                source = f"{tool}_metadata_view" if temporary_view else tool
                root, problem = read(path)
                if root is None:
                    append_warning(warnings, f"{source} Manifest 组件解析失败: {problem}")
                    continue
                fields, incomplete = manifest_fields(root)
                package = fields.pop("package_name")
                if not package or package.startswith(("@", "?")) or (expected and expected != package):
                    append_warning(warnings, f"{source} Manifest 的包名缺失或与已读取的包名不一致")
                    continue
                expected = package
                definition_rows, definitions_complete = declarations(root)
                if fields_missing := sorted(incomplete):
                    append_warning(warnings, f"{source} 未读全 Manifest 字段: {', '.join(fields_missing)}")
                score = (len(incomplete), not definitions_complete)
                if best is None or score < best[0]:
                    best = (score, source, fields, incomplete, definition_rows, definitions_complete)
                if score == (0, False):
                    break
        if best is not None and best[0] == (0, False):
            break
    if best is None:
        return
    _, source, fields, incomplete, definition_rows, definitions_complete = best
    package = expected
    if not parsed["package_name"]:
        parsed["package_name"] = package
        parsed["parser_used"] = source
        parsed["app_names"]["package_name"] = package
        if not parsed["app_name"]:
            parsed.update(name_fields({}, package))

    for field in ("version_name", "version_code", "min_sdk_version", "target_sdk_version", "main_activity"):
        if (value := fields.pop(field, "")) and not parsed.get(field):
            parsed[field] = value
    for field, value in fields.items():
        if field not in incomplete or not parsed.get(field):
            parsed[field] = value
    parsed["library"] = ",".join(parsed["libraries"])
    parsed["manifest_components_source"] = source
    parsed["manifest_components_status"] = "partial" if incomplete else "ok"
    parsed["manifest_permission_requests_status"] = "partial" if "permissions" in incomplete else "ok"
    parsed["manifest_declared_permissions"] = definition_rows
    parsed["manifest_declared_permissions_status"] = "ready" if definitions_complete else "partial"


def extract_apk_file_tree(apk_file: Path, *, include_file_tree: bool = False) -> dict:
    """统计 APK 条目，按需附上按名称排序的完整路径列表。"""
    try:
        with ZipFile(apk_file) as archive:
            entries = archive.infolist()
            summary = {"file_count": len(entries)}
            if include_file_tree:
                summary["file_tree"] = sorted(entry.filename for entry in entries)
            return summary
    except (BadZipFile, OSError):
        return {"file_count": 0, "file_tree": []} if include_file_tree else {"file_count": 0}


def parse_apk_full(
    apk_file_path: str,
    *,
    prefer_aapt2: bool = False,
    include_file_tree: bool = False,
) -> dict:
    """解析 APK 的基础信息、组件和文件条目。

    这是供上层调用的单一入口，扩展 handle_apkfile_basic() 的输出，
    增加权限、活动、服务、广播接收器、内容提供者和文件统计。
    """

    # 基础字段与组件提取复用同一个 Androguard APK 对象。旧实现对同一文件
    # 构造两次 APK，在病理 AXML/资源表上会把最坏耗时和内存放大一倍。
    parsed, apk, streamed_manifest = _handle_apkfile_basic_runtime(
        apk_file_path,
        prefer_aapt2=prefer_aapt2,
    )

    apk_file = validate_apk_path(apk_file_path)
    warnings = parsed.setdefault("parse_warnings", [])

    parsed["manifest_components_source"] = "androguard" if apk is not None else None
    parsed.update(permissions=[], activities=[], services=[], receivers=[], providers=[])
    if apk is not None:
        try:
            warning_count = len(warnings)
            parsed.update(extract_manifest_components(apk, warnings))
            if len(warnings) != warning_count:
                parsed["manifest_components_status"] = "partial"
        except Exception as exc:
            append_warning(warnings, f"组件解析失败: {exc}")
            parsed["manifest_components_status"] = "unavailable"

    parsed["manifest_permission_requests_status"] = "unavailable"
    if apk is not None and parsed["manifest_components_status"] == "ok":
        root = safe_call("AndroidManifest.xml", warnings, apk.get_android_manifest_xml)
        if root is not None and local_tag(root) == "manifest" and root.get("package") == parsed["package_name"]:
            names, requests, complete = requested_permissions(root)
            parsed["permissions"] = names
            parsed["permission_requests"] = requests
            parsed["manifest_permission_requests_status"] = "ok" if complete else "partial"
            _set_manifest_declarations(parsed, root)
    if parsed["manifest_components_status"] != "ok" or parsed["manifest_permission_requests_status"] != "ok":
        _recover_manifest_components(apk_file, parsed, warnings, streamed_manifest)
    if parsed["manifest_permission_requests_status"] != "ok" and parsed["package_name"]:
        permission_dump = read_permission_dump(apk_file, settings.aapt2_bin)
        if permission_dump and permission_dump[0] == parsed["package_name"]:
            _, requested, defined = permission_dump
            if requested:
                parsed["permissions"] = list(dict.fromkeys([*parsed["permissions"], *requested]))
                parsed["manifest_permission_requests_status"] = "partial"
                parsed["manifest_permission_requests_source"] = "aapt2_permissions"
                definitions = parsed.setdefault("manifest_declared_permissions", {})
                for name in defined:
                    definitions.setdefault(name, {"protectionLevel": None})
                parsed["manifest_declared_permissions_status"] = "partial"
                append_warning(warnings, "AAPT2 回填了可读取的权限名，完整声明仍待核验")

    parsed.update(extract_apk_file_tree(apk_file, include_file_tree=include_file_tree))

    return parsed
