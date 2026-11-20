"""Android permission semantics and business-risk classification.

The Android ``protectionLevel`` describes how a permission may be granted.  It
is not a risk score.  This module intentionally keeps those two concepts
separate and never treats a manifest declaration as proof that the permission
was granted at runtime.
"""

from __future__ import annotations

import json
import re
import shutil
import threading
from collections import Counter, OrderedDict
from pathlib import Path
from typing import Any, Iterable, Mapping

from androguard.core import api_specific_resources

from apk_lens_service.config import parse_tools as settings
from apk_lens_service.utils import run_command


PERMISSION_CATALOG_PATH = Path(__file__).with_name("android_permissions.json")

PROTECTION_BASE_MASK = 0xF
PROTECTION_BASES = {
    0x0: "normal",
    0x1: "dangerous",
    0x2: "signature",
    0x3: "signature_or_system",
    0x4: "internal",
}
PROTECTION_LABELS = {
    "normal": "普通级",
    "dangerous": "危险级",
    "signature": "签名级",
    "signature_or_system": "签名或系统级（旧）",
    "internal": "系统内部级",
    "unknown": "未识别",
}

# Values from android.content.pm.PermissionInfo.  Unknown future bits are kept
# in the response as a hexadecimal flag rather than silently discarded.
PROTECTION_FLAG_BITS = (
    (0x00000010, "privileged"),
    (0x00000020, "development"),
    (0x00000040, "appop"),
    (0x00000080, "pre23"),
    (0x00000100, "installer"),
    (0x00000200, "verifier"),
    (0x00000400, "preinstalled"),
    (0x00000800, "setup"),
    (0x00001000, "instant"),
    (0x00002000, "runtime"),
    (0x00004000, "oem"),
    (0x00008000, "vendorPrivileged"),
    (0x00010000, "textClassifier"),
    (0x00020000, "wellbeing"),
    (0x00040000, "documenter"),
    (0x00080000, "configurator"),
    (0x00100000, "incidentReportApprover"),
    (0x00200000, "appPredictor"),
    (0x00400000, "module"),
    (0x00800000, "companion"),
    (0x01000000, "retailDemo"),
    (0x02000000, "recents"),
    (0x04000000, "role"),
    (0x08000000, "knownSigner"),
)
PROTECTION_FLAG_LABELS = {
    "privileged": "特权预装",
    "development": "开发授权",
    "appop": "特殊访问/AppOp",
    "pre23": "兼容旧版应用",
    "installer": "安装器",
    "verifier": "应用验证器",
    "preinstalled": "预装应用",
    "setup": "设备设置程序",
    "instant": "即时应用",
    "runtime": "仅运行时",
    "oem": "OEM",
    "vendorPrivileged": "厂商特权",
    "textClassifier": "文本分类器",
    "wellbeing": "数字健康",
    "documenter": "系统文档组件",
    "configurator": "系统配置器",
    "incidentReportApprover": "事件报告审批器",
    "appPredictor": "应用预测器",
    "companion": "配套设备组件",
    "retailDemo": "零售演示",
    "recents": "最近任务组件",
    "role": "系统角色",
    "knownSigner": "已知签名者",
    "module": "系统模块",
    "system": "系统应用",
}

RISK_LABELS = {
    "high": "高风险",
    "medium": "中风险",
    "low": "低风险",
    "unknown": "待评估",
}

# Business risk is an independent, auditable policy keyed by capability.  Do
# not infer it from protectionLevel: signature describes who may receive a
# permission, while risk describes what the capability could do if available.
HIGH_RISK_PLATFORM_PERMISSIONS = {
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_MOCK_LOCATION",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.BODY_SENSORS",
    "android.permission.CALL_PHONE",
    "android.permission.CAMERA",
    "android.permission.CHANGE_CONFIGURATION",
    "android.permission.CLEAR_APP_CACHE",
    "android.permission.DELETE_PACKAGES",
    "android.permission.DEVICE_POWER",
    "android.permission.FORCE_STOP_PACKAGES",
    "android.permission.GET_ACCOUNTS",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
    "android.permission.PACKAGE_OVERLAYS",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.READ_CALENDAR",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.READ_FRAME_BUFFER",
    "android.permission.READ_LOGS",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PROFILE",
    "android.permission.READ_SMS",
    "android.permission.READ_SOCIAL_STREAM",
    "android.permission.REBOOT",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECORD_AUDIO",
    "android.permission.RECORD_AUDIO_CAPTURE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SEND_SMS",
    "android.permission.SET_ALWAYS_FINISH",
    "android.permission.SET_DEBUG_APP",
    "android.permission.SET_PROCESS_LIMIT",
    "android.permission.SUBSCRIBED_FEEDS_READ",
    "android.permission.SUBSCRIBED_FEEDS_WRITE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.WRITE_APNS_SETTINGS",
    "android.permission.WRITE_CALENDAR",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.WRITE_CONTACTS",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.WRITE_PROFILE",
    "android.permission.WRITE_SETTINGS",
    "android.permission.WRITE_SOCIAL_STREAM",
}
MEDIUM_RISK_PLATFORM_PERMISSIONS = {
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_NOTIFICATION_POLICY",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.BLUETOOTH_ADMIN",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.GET_TASKS",
    "android.permission.INTERNET",
    "android.permission.KILL_BACKGROUND_PROCESSES",
    "android.permission.MODIFY_AUDIO_SETTINGS",
    "android.permission.NFC",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.RESTART_PACKAGES",
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    "android.permission.SCHEDULE_EXACT_ALARM",
    "android.permission.USE_FULL_SCREEN_INTENT",
    "android.permission.WAKE_LOCK",
    "android.permission.WRITE_SYNC_SETTINGS",
}
LOW_RISK_PLATFORM_PERMISSIONS = {
    "android.permission.EXPAND_STATUS_BAR",
    "android.permission.FLASHLIGHT",
    "android.permission.FOREGROUND_SERVICE_DATA_SYNC",
    "android.permission.FOREGROUND_SERVICE_MEDIA_PLAYBACK",
    "android.permission.READ_SYNC_SETTINGS",
    "android.permission.READ_SYNC_STATS",
    "android.permission.SET_WALLPAPER",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.VIBRATE",
}

RISK_REASON_OVERRIDES = {
    "android.permission.CHANGE_CONFIGURATION": "可修改影响设备行为的系统配置",
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS": "可挂载或卸载文件系统，影响数据可用性与完整性",
    "android.permission.READ_LOGS": "可读取可能包含账号、设备或业务信息的系统日志",
    "android.permission.SYSTEM_ALERT_WINDOW": "可在其他应用上方显示内容，存在界面遮挡或诱导操作风险",
    "android.permission.REQUEST_INSTALL_PACKAGES": "可发起安装其他应用，存在软件投递和供应链风险",
    "android.permission.INTERNET": "可与外部网络通信；需结合敏感权限和实际流量判断数据外传风险",
}

# AppOp does not universally mean that an ordinary app can obtain the
# permission through a Settings page.  Only documented special-access
# capabilities are classified that way here.
SPECIAL_ACCESS_MIN_API = {
    "android.permission.PACKAGE_USAGE_STATS": 21,
    "android.permission.ACCESS_NOTIFICATION_POLICY": 23,
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": 23,
    "android.permission.SYSTEM_ALERT_WINDOW": 23,
    "android.permission.WRITE_SETTINGS": 23,
    "android.permission.REQUEST_INSTALL_PACKAGES": 26,
    "android.permission.MANAGE_EXTERNAL_STORAGE": 30,
    "android.permission.SCHEDULE_EXACT_ALARM": 31,
}

_PLATFORM_CATALOG_CACHE: dict[int, dict[str, dict[str, str]]] = {}
_AVAILABLE_API_LEVELS_CACHE: tuple[int, ...] | None = None
_DESCRIPTION_CATALOG_CACHE: dict[str, dict[str, Any]] | None = None
_DECLARED_PERMISSION_CACHE: OrderedDict[
    tuple[str, int, int, str], dict[str, dict[str, str]]
] = OrderedDict()
_CACHE_LOCK = threading.RLock()
_DECLARED_PERMISSION_CACHE_SIZE = 128

_ELEMENT_RE = re.compile(r"^(\s*)E:\s+([\w.-]+)(?:\s|$)")
_NAME_RE = re.compile(r":name\([^)]*\)=\"([^\"]+)\"")
_PROTECTION_RE = re.compile(
    r":protectionLevel\([^)]*\)=(0x[0-9a-fA-F]+|\d+|\"[^\"]+\")"
)


def _load_description_catalog() -> dict[str, dict[str, Any]]:
    global _DESCRIPTION_CATALOG_CACHE
    with _CACHE_LOCK:
        if _DESCRIPTION_CATALOG_CACHE is not None:
            return _DESCRIPTION_CATALOG_CACHE
    try:
        loaded = json.loads(PERMISSION_CATALOG_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    if not isinstance(loaded, dict) or not loaded:
        return {}
    with _CACHE_LOCK:
        _DESCRIPTION_CATALOG_CACHE = loaded
    return loaded


def _available_api_levels() -> tuple[int, ...]:
    global _AVAILABLE_API_LEVELS_CACHE
    with _CACHE_LOCK:
        if _AVAILABLE_API_LEVELS_CACHE is not None:
            return _AVAILABLE_API_LEVELS_CACHE
    resource_dir = Path(api_specific_resources.__file__).resolve().parent / "aosp_permissions"
    levels: list[int] = []
    try:
        candidates = resource_dir.glob("permissions_*.json")
        for path in candidates:
            match = re.fullmatch(r"permissions_(\d+)\.json", path.name)
            if match:
                levels.append(int(match.group(1)))
    except OSError:
        return ()
    resolved = tuple(sorted(set(levels)))
    if resolved:
        with _CACHE_LOCK:
            _AVAILABLE_API_LEVELS_CACHE = resolved
    return resolved


def _parse_target_sdk(value: Any) -> int | None:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _resolve_api_level(
    target_sdk_version: Any,
    min_sdk_version: Any = None,
) -> tuple[int | None, int | None, int, int | None]:
    requested = _parse_target_sdk(target_sdk_version)
    minimum = _parse_target_sdk(min_sdk_version)
    # Android defaults an omitted targetSdkVersion to minSdkVersion, and an
    # omitted minSdkVersion to API 1.
    effective = requested or minimum or 1
    levels = _available_api_levels()
    if not levels:
        return requested, minimum, effective, None
    eligible = [level for level in levels if level <= effective]
    resolved = eligible[-1] if eligible else levels[0]
    return requested, minimum, effective, resolved


def _load_platform_catalog(api_level: int | None) -> dict[str, dict[str, str]]:
    if api_level is None:
        return {}
    with _CACHE_LOCK:
        cached = _PLATFORM_CATALOG_CACHE.get(api_level)
    if cached is not None:
        return cached
    try:
        loaded = api_specific_resources.load_permissions(api_level)
    except (OSError, TypeError, ValueError):
        return {}
    # Do not cache failures: a repaired package/resource mount must recover
    # without restarting the API process.
    if loaded:
        with _CACHE_LOCK:
            _PLATFORM_CATALOG_CACHE[api_level] = loaded
    return loaded


def _normalise_protection_token(token: str) -> str:
    compact = re.sub(r"[-_\s]", "", token).lower()
    aliases = {
        "normal": "normal",
        "dangerous": "dangerous",
        "signature": "signature",
        "signatureorsystem": "signature_or_system",
        "internal": "internal",
        # Older AOSP metadata used ``system|signature`` for what is now
        # represented by signature + privileged.
        "system": "system",
        "vendorprivileged": "vendorPrivileged",
        "textclassifier": "textClassifier",
        "incidentreportapprover": "incidentReportApprover",
        "apppredictor": "appPredictor",
        "retaildemo": "retailDemo",
        "knownsigner": "knownSigner",
    }
    return aliases.get(compact, token.strip())


def decode_protection_level(raw_value: Any) -> tuple[str, list[str], str]:
    """Decode either Android's numeric value or an AOSP textual value."""

    raw = "" if raw_value is None else str(raw_value).strip().strip('"')
    if not raw:
        return "normal", [], "normal"

    try:
        numeric = int(raw, 0)
    except ValueError:
        numeric = None

    if numeric is not None:
        base = PROTECTION_BASES.get(numeric & PROTECTION_BASE_MASK, "unknown")
        flags: list[str] = []
        known_bits = PROTECTION_BASE_MASK
        for bit, name in PROTECTION_FLAG_BITS:
            known_bits |= bit
            if numeric & bit:
                flags.append(name)
        unknown_bits = numeric & ~known_bits
        if unknown_bits:
            flags.append(f"0x{unknown_bits:x}")
        return base, flags, f"0x{numeric:08x}"

    tokens = [_normalise_protection_token(part) for part in raw.split("|") if part.strip()]
    if "signature_or_system" in tokens:
        base = "signature_or_system"
    elif "internal" in tokens:
        base = "internal"
    elif "signature" in tokens:
        base = "signature"
    elif "dangerous" in tokens:
        base = "dangerous"
    elif "normal" in tokens:
        base = "normal"
    else:
        base = "unknown"

    base_tokens = {"normal", "dangerous", "signature", "signature_or_system", "internal"}
    flags: list[str] = []
    for token in tokens:
        if token in base_tokens:
            continue
        # ``system|signature`` is the old alias for signature + privileged.
        flag = "privileged" if token == "system" else token
        if flag and flag not in flags:
            flags.append(flag)
    return base, flags, raw


def _parse_declared_permissions_output(output: str) -> dict[str, dict[str, str]]:
    """Extract top-level ``<permission>`` declarations from aapt2 xmltree."""

    lines = output.splitlines()
    declared: dict[str, dict[str, str]] = {}
    index = 0
    while index < len(lines):
        element = _ELEMENT_RE.match(lines[index])
        if not element or element.group(2) != "permission":
            index += 1
            continue

        element_indent = len(element.group(1))
        name = ""
        raw_protection = ""
        cursor = index + 1
        while cursor < len(lines):
            next_element = _ELEMENT_RE.match(lines[cursor])
            if next_element and len(next_element.group(1)) <= element_indent:
                break
            if not name:
                name_match = _NAME_RE.search(lines[cursor])
                if name_match:
                    name = name_match.group(1).strip()
            protection_match = _PROTECTION_RE.search(lines[cursor])
            if protection_match:
                raw_protection = protection_match.group(1).strip('"')
            cursor += 1

        if name:
            # Android defaults a declared permission with no protectionLevel to
            # normal.  Keep that fact explicit for later analysis.
            declared[name] = {"protectionLevel": raw_protection or "0x00000000"}
        index = cursor
    return declared


def _read_declared_permissions_cached(
    apk_path: str,
    file_mtime_ns: int,
    file_size: int,
    aapt2_bin: str,
) -> tuple[dict[str, dict[str, str]], str, str]:
    cache_key = (apk_path, file_mtime_ns, file_size, aapt2_bin)
    with _CACHE_LOCK:
        cached = _DECLARED_PERMISSION_CACHE.get(cache_key)
        if cached is not None:
            _DECLARED_PERMISSION_CACHE.move_to_end(cache_key)
            return cached, "ready", ""
    executable = shutil.which(aapt2_bin)
    if not executable:
        return {}, "unavailable", f"aapt2 不可用: {aapt2_bin}"
    returncode, stdout, stderr = run_command(
        [executable, "dump", "xmltree", "--file", "AndroidManifest.xml", apk_path],
        timeout=20,
    )
    if returncode != 0 or not stdout:
        detail = stderr[:200] if stderr else f"退出码 {returncode}"
        return {}, "failed", f"APK 自定义权限解析失败: {detail}"
    parsed = _parse_declared_permissions_output(stdout)
    with _CACHE_LOCK:
        _DECLARED_PERMISSION_CACHE[cache_key] = parsed
        _DECLARED_PERMISSION_CACHE.move_to_end(cache_key)
        while len(_DECLARED_PERMISSION_CACHE) > _DECLARED_PERMISSION_CACHE_SIZE:
            _DECLARED_PERMISSION_CACHE.popitem(last=False)
    return parsed, "ready", ""


def _read_declared_permissions_with_status(
    apk_path: str | Path | None,
) -> tuple[dict[str, dict[str, str]], str, str]:
    if not apk_path:
        return {}, "unavailable", "未提供 APK 文件路径，无法核验应用自定义权限"
    path = Path(apk_path)
    try:
        stat = path.stat()
    except OSError:
        return {}, "unavailable", f"APK 文件不可用，无法核验应用自定义权限: {path}"
    if not path.is_file():
        return {}, "unavailable", f"APK 路径不是文件，无法核验应用自定义权限: {path}"
    return _read_declared_permissions_cached(
        str(path), stat.st_mtime_ns, stat.st_size, str(settings.aapt2_bin)
    )


def read_declared_permissions(apk_path: str | Path | None) -> dict[str, dict[str, str]]:
    """Read permissions defined by the APK itself; failure is non-fatal."""

    declared, _status, _warning = _read_declared_permissions_with_status(apk_path)
    return declared


def _coerce_declared_permissions(
    declared_permissions: Mapping[str, Any] | None,
    apk_path: str | Path | None,
) -> tuple[dict[str, dict[str, Any]], str, list[str]]:
    if declared_permissions is not None:
        source = declared_permissions
        status = "provided"
        warnings: list[str] = []
    else:
        source, status, warning = _read_declared_permissions_with_status(apk_path)
        warnings = [warning] if warning else []
    result: dict[str, dict[str, Any]] = {}
    for name, value in (source or {}).items():
        if isinstance(value, Mapping):
            result[str(name)] = dict(value)
        else:
            result[str(name)] = {"protectionLevel": value}
    return result, status, warnings


def _risk_for_permission(
    name: str,
    permission_source: str,
) -> tuple[str, str]:
    if permission_source == "app_declared":
        return "unknown", "应用自定义权限，需结合受保护组件和调用关系评估"
    if permission_source != "android":
        return "unknown", "权限定义或能力规则未收录，无法仅凭权限名称评估"
    if name in RISK_REASON_OVERRIDES:
        if name in HIGH_RISK_PLATFORM_PERMISSIONS:
            return "high", RISK_REASON_OVERRIDES[name]
        if name in MEDIUM_RISK_PLATFORM_PERMISSIONS:
            return "medium", RISK_REASON_OVERRIDES[name]
        if name in LOW_RISK_PLATFORM_PERMISSIONS:
            return "low", RISK_REASON_OVERRIDES[name]
    if name in HIGH_RISK_PLATFORM_PERMISSIONS:
        return "high", "该权限对应的能力可访问敏感数据或影响关键系统行为"
    if name in MEDIUM_RISK_PLATFORM_PERMISSIONS:
        return "medium", "可影响应用持久运行、包可见性或系统交互，建议结合动态行为审查"
    if name in LOW_RISK_PLATFORM_PERMISSIONS:
        return "low", "当前能力通常影响较小，仍需结合权限组合和实际行为判断"
    return "unknown", "尚无独立的业务能力风险规则，不能从保护级别推断风险"


def _grantability_for_permission(
    name: str,
    protection_level: str,
    protection_flags: list[str],
    permission_source: str,
    effective_target_sdk_version: int,
) -> tuple[str, str]:
    if permission_source not in {"android", "app_declared"}:
        return "unknown", "需由权限定义方确认"
    special_access_min_api = SPECIAL_ACCESS_MIN_API.get(name)
    if (
        permission_source == "android"
        and special_access_min_api is not None
        and effective_target_sdk_version >= special_access_min_api
    ):
        if protection_level in {"signature", "signature_or_system", "internal"}:
            return "special_access", "需平台签名或用户在系统特殊访问页面授权"
        return "special_access", "需用户在系统设置或确认页面授予特殊访问权限"
    if permission_source == "app_declared":
        if protection_level == "normal":
            return "automatic", "应用自定义普通权限，通常安装时授予"
        if protection_level == "dangerous":
            if effective_target_sdk_version >= 23:
                return "runtime", "应用自定义危险权限，通常需用户运行时授权"
            return "install_consent", "旧目标版本应用，通常在安装时由用户确认"
        if protection_level == "signature":
            return "restricted", "仅同签名应用可获得"
        if protection_level == "signature_or_system":
            return "restricted", "仅同签名应用或系统应用可获得"
        return "restricted", "由应用自定义保护规则决定"
    if protection_level == "normal":
        suffix = "，并受系统 AppOp 控制" if "appop" in protection_flags else ""
        return "automatic", "安装时通常自动授予" + suffix
    if protection_level == "dangerous":
        if effective_target_sdk_version >= 23:
            return "runtime", "通常需用户运行时授权"
        return "install_consent", "目标 API 22 及以下，通常在安装时由用户确认"
    if protection_level == "internal":
        return "restricted", "仅 Android 系统内部组件可获得"
    if protection_level in {"signature", "signature_or_system"}:
        conditions = ["平台签名" if protection_level == "signature" else "同签名或系统应用身份"]
        if "privileged" in protection_flags:
            conditions.append("特权预装")
        if "development" in protection_flags:
            conditions.append("调试授权")
        label = "需" + "、".join(conditions[:-1]) + ("或" + conditions[-1] if len(conditions) > 1 else "")
        if "appop" in protection_flags:
            label += "，并受系统 AppOp 控制"
        return "restricted", label
    return "unknown", "授权条件未识别"


def analyze_permissions(
    permission_names: Iterable[str],
    target_sdk_version: Any,
    apk_path: str | Path | None = None,
    catalog: Mapping[str, Any] | None = None,
    declared_permissions: Mapping[str, Any] | None = None,
    min_sdk_version: Any = None,
) -> dict[str, Any]:
    """Classify requested permissions without claiming they were granted."""

    requested_api, minimum_api, effective_api, resolved_api = _resolve_api_level(
        target_sdk_version, min_sdk_version
    )
    platform_catalog = _load_platform_catalog(resolved_api)
    platform_status = "ready" if platform_catalog else "unavailable"
    description_catalog = dict(catalog) if catalog is not None else _load_description_catalog()
    local_declarations, declaration_status, warnings = _coerce_declared_permissions(
        declared_permissions, apk_path
    )
    if platform_status != "ready":
        warnings.append("Android 平台权限元数据不可用，系统权限保护级别无法核验")
    unique_names: list[str] = []
    seen_names: set[str] = set()
    for raw_name in permission_names:
        if raw_name is None:
            continue
        name = str(raw_name).strip()
        if name and name not in seen_names:
            seen_names.add(name)
            unique_names.append(name)
    unique_names.sort()

    items: list[dict[str, Any]] = []
    for name in unique_names:
        platform_info = platform_catalog.get(name)
        custom_info = local_declarations.get(name)
        if platform_info is not None:
            permission_source = "android"
            raw_protection = platform_info.get("protectionLevel", "")
        elif custom_info is not None:
            permission_source = "app_declared"
            raw_protection = custom_info.get(
                "protectionLevel", custom_info.get("protection_level", "0x00000000")
            )
        elif name.startswith("android.permission."):
            permission_source = "android_unresolved"
            raw_protection = ""
        elif declaration_status not in {"ready", "provided"}:
            permission_source = "unresolved"
            raw_protection = ""
        else:
            permission_source = "third_party"
            raw_protection = ""

        if permission_source not in {"android", "app_declared"}:
            protection_level, protection_flags, protection_raw = "unknown", [], ""
        else:
            protection_level, protection_flags, protection_raw = decode_protection_level(raw_protection)

        risk_level, risk_reason = _risk_for_permission(name, permission_source)
        grantability, grantability_label = _grantability_for_permission(
            name,
            protection_level,
            protection_flags,
            permission_source,
            effective_api,
        )
        catalog_info = description_catalog.get(name, {})
        description = str(catalog_info.get("desc", "") or "").strip()
        if not description and platform_info:
            description = str(platform_info.get("description", "") or "").strip()
        if not description and permission_source == "app_declared":
            description = "应用自定义权限"

        items.append(
            {
                "name": name,
                "desc": description,
                # Deprecated alias retained for old clients.  In schema v2 it
                # explicitly means protection_level, never business risk.
                "level": protection_level,
                "level_semantics": "protection_level",
                "protection_level": protection_level,
                "protection_flags": protection_flags,
                "protection_flags_label": [
                    PROTECTION_FLAG_LABELS.get(flag, flag) for flag in protection_flags
                ],
                "protection_raw": protection_raw,
                "protection_label": PROTECTION_LABELS.get(protection_level, "未识别"),
                "permission_source": permission_source,
                "risk_level": risk_level,
                "risk_label": RISK_LABELS[risk_level],
                "risk_reason": risk_reason,
                "declared": True,
                "grant_state": "not_checked",
                "grant_state_label": "实际授权未核验",
                "grantability": grantability,
                "grantability_label": grantability_label,
            }
        )

    risk_order = {"high": 0, "medium": 1, "low": 2, "unknown": 3}
    protection_order = {
        "dangerous": 0,
        "signature": 1,
        "signature_or_system": 2,
        "internal": 3,
        "normal": 4,
        "unknown": 5,
    }
    items.sort(
        key=lambda item: (
            risk_order.get(item["risk_level"], 3),
            protection_order.get(item["protection_level"], 5),
            item["name"],
        )
    )

    protection_counts = Counter(item["protection_level"] for item in items)
    risk_counts = Counter(item["risk_level"] for item in items)
    source_counts = Counter(item["permission_source"] for item in items)
    unresolved_count = source_counts.get("android_unresolved", 0) + source_counts.get(
        "unresolved", 0
    )
    if unresolved_count:
        warnings.append(f"{unresolved_count} 项权限因元数据不完整而未能解析")
    metadata_complete = platform_status == "ready" and declaration_status in {
        "ready",
        "provided",
    } and not unresolved_count
    return {
        "schema_version": 2,
        "target_sdk_version": requested_api,
        "min_sdk_version": minimum_api,
        "effective_target_sdk_version": effective_api,
        "resolved_api_level": resolved_api,
        "grant_state": "not_checked",
        "analysis_status": "complete" if metadata_complete else "partial",
        "metadata_status": {
            "platform_permissions": platform_status,
            "app_declarations": declaration_status,
        },
        "warnings": warnings,
        "deprecated_fields": {
            "level": "schema v2 中仅作为 protection_level 的兼容别名；请勿用于风险判断"
        },
        "note": (
            "风险等级表示权限能力可能造成的业务影响；保护级别表示 Android 的授权机制。"
            "当前结果来自 APK Manifest，不能证明权限已在设备上实际授予。"
        ),
        "summary": {
            "protection_levels": dict(protection_counts),
            "risk_levels": dict(risk_counts),
            "permission_sources": dict(source_counts),
        },
        "permissions": items,
    }
