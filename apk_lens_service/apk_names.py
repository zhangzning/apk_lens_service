"""Read and select the APK's application labels without mixing locales."""

import re
from collections.abc import Iterator, Mapping

from androguard.core.apk import APK
from androguard.core.axml import (
    TYPE_REFERENCE,
    TYPE_STRING,
    ARSCParser,
    ARSCResTableConfig,
    ARSCResTableEntry,
    ARSCResType,
)

from apk_lens_service.utils import is_garbled_text, is_usable_text, normalize_app_name

type Labels = dict[str, tuple[str, str]]
type ResourceLabels = dict[tuple[str, str], str]

CN_LOCALES = ("zh-CN", "zh-Hans-CN")
DISPLAY_LOCALES = (*CN_LOCALES, "zh-Hans", "zh", "default")
BADGING_LABEL = re.compile(r"application-label(?:-([\w+-]+))?:(.*)")
STRING_REFERENCE = re.compile(r"@(?:(?P<package>[\w.]+):)?string/(?P<key>[\w.]+)")


def normalize_locale(locale: str) -> str:
    """Convert Android qualifiers and aapt2's language tags to a common format."""

    if not locale or not locale.strip("\x00"):
        return "default"
    parts = locale.removeprefix("b+").replace("_", "-").replace("+", "-").split("-")
    normalized = [parts[0].lower()]
    for part in parts[1:]:
        if re.fullmatch(r"r(?:[A-Z]{2}|\d{3})", part):
            part = part[1:]
        if len(part) == 4 and part.isalpha():
            part = part.title()
        elif len(part) == 2 and part.isalpha():
            part = part.upper()
        normalized.append(part)
    return "-".join(normalized)


def resource_locale(config: ARSCResTableConfig) -> str:
    locale = normalize_locale(config.get_language_and_region())
    script = getattr(config, "localeScript", b"").rstrip(b"\x00").decode("ascii", errors="ignore")
    if locale == "default" or not script:
        return locale
    language, separator, region = locale.partition("-")
    return f"{language}-{script.title()}{separator}{region}"


def resource_entries(
    resources: ARSCParser, package: str, res_id: int
) -> Iterator[tuple[ARSCResTableConfig, str | int]]:
    # Androguard's resolved config map can merge zh-rCN with b+zh+Hans+CN.
    # Its original resource entries retain the script and the corresponding value.
    config = None
    for item in resources.get_items(package):
        if isinstance(item, ARSCResType):
            config = item.config
        elif isinstance(item, ARSCResTableEntry) and config is not None and item.mResId == res_id:
            if item.is_complex():
                continue
            if item.is_compact():
                if item.datatype == TYPE_STRING:
                    yield config, item.parent.stringpool_main.getString(item.data)
                elif item.datatype == TYPE_REFERENCE:
                    yield config, item.data
            elif item.key.get_data_type() == TYPE_STRING:
                yield config, item.key.get_data_value()
            elif item.key.is_reference():
                yield config, item.key.get_data()


def label_for_locale(labels: ResourceLabels, locale: str) -> str | None:
    parts = locale.split("-")
    preferred = ["-".join(parts[:end]) for end in range(len(parts), 0, -1)]
    for language in (*preferred, "default"):
        candidates = sorted(
            (len(qualifier), qualifier, name)
            for (candidate, qualifier), name in labels.items()
            if candidate == language
        )
        if candidates:
            return candidates[0][2]
    return None


def resolve_label_resource(
    resources: ARSCParser, package: str, res_id: int, visiting: frozenset[int] = frozenset()
) -> ResourceLabels:
    if not res_id or res_id in visiting or len(visiting) >= 32:
        return {}
    entries = list(resource_entries(resources, package, res_id)) if package else []
    if not entries:
        return {
            (resource_locale(config), config.get_qualifier()): value
            for config, value in resources.get_resolved_res_configs(res_id)
            if isinstance(value, str)
        }

    inherited: ResourceLabels = {}
    declared: ResourceLabels = {}
    for config, value in entries:
        locale = resource_locale(config)
        if isinstance(value, int):
            target = resolve_label_resource(resources, package, value, visiting | {res_id})
            if locale == "default":
                # A language-neutral alias also inherits the target's localized entries.
                inherited.update(target)
            value = label_for_locale(target, locale)
        if value is not None:
            declared[locale, config.get_qualifier()] = value
    inherited.update(declared)
    return inherited


def read_manifest_labels(apk: APK, package_name: str) -> tuple[Labels, bool]:
    label = apk.get_attribute_value("application", "label")
    source = "manifest"
    if label is None:
        activity = apk.get_main_activity()
        if activity:
            label = apk.get_attribute_value("activity", "label", name=activity)
            source = "launcher_activity"
    if not label:
        return {}, False
    if not label.startswith("@"):
        value = normalize_app_name(label)
        return ({"default": (value, source)} if is_usable_text(value) else {}), is_garbled_text(value)

    resources = apk.get_android_resources()
    if not resources:
        return {}, False
    symbolic = STRING_REFERENCE.fullmatch(label)
    if symbolic:
        package = symbolic["package"] or package_name
        if package not in resources.get_packages_names():
            return {}, False
        # Resolve symbolic references after the table has indexed its keys.
        resources.get_items(package)
        res_id = resources.get_res_id_by_key(package, "string", symbolic["key"])
    else:
        res_id, package = resources.parse_id(label.replace("@0x", "@", 1))
        package = package or package_name
    if not res_id or package == "android":
        return {}, False

    packages = resources.get_packages_names()
    if package not in packages:
        package = packages[0] if len(packages) == 1 else ""
    resolved = resolve_label_resource(resources, package, res_id)

    labels: Labels = {}
    garbled = False
    for (locale, _), raw in sorted(resolved.items(), key=lambda item: (len(item[0][1]), item[0])):
        value = normalize_app_name(raw)
        garbled |= locale in DISPLAY_LOCALES and is_garbled_text(value)
        if is_usable_text(value):
            labels.setdefault(locale, (value, "resources.arsc"))
    return labels, garbled


def read_badging_labels(stdout: str, source: str) -> tuple[Labels, dict[str, str]]:
    reported: dict[str, str] = {}
    inline_default = ""
    for line in stdout.splitlines():
        line = line.strip()
        match = BADGING_LABEL.fullmatch(line)
        if match:
            raw = match[2].strip()
            if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
                raw = raw[1:-1]
            value = normalize_app_name(raw)
            if is_usable_text(value):
                reported[normalize_locale(match[1] or "")] = value
        elif line.startswith("application:"):
            match = re.search(r"\blabel='(.*?)'(?:\s+icon=|$)", line)
            if match:
                inline_default = normalize_app_name(match[1])
    if is_usable_text(inline_default):
        reported.setdefault("default", inline_default)

    labels: Labels = {}
    for locale, value in reported.items():
        # badging may repeat the effective fallback string for an untranslated locale.
        # Keep those observations visible without presenting them as dedicated names.
        parent = locale.rpartition("-")[0]
        if locale == "default" or value not in {reported.get("default"), reported.get(parent)}:
            labels[locale] = (value, source)
    return labels, reported


def name_fields(
    labels: Labels, package_name: str, *, badging: Mapping[str, str] | None = None
) -> dict:
    chosen = next((locale for locale in DISPLAY_LOCALES if locale in labels), None)
    cn = next((labels[locale][0] for locale in CN_LOCALES if locale in labels), None)
    display, source = labels[chosen] if chosen else (package_name, "package_name")
    default_name = labels["default"][0] if "default" in labels else None
    zh_name = labels["zh"][0] if "zh" in labels else None
    names = {
        "display_name": display,
        "display_locale": chosen or ("package_name" if display else None),
        "display_source": source if display else None,
        "zh_cn": cn,
        "zh": zh_name,
        "default": default_name,
        "package_name": package_name,
        "localized": {locale: value for locale, (value, _) in sorted(labels.items()) if locale != "default"},
        "label_sources": {locale: origin for locale, (_, origin) in sorted(labels.items())},
    }
    if badging:
        names["badging_reported_labels"] = dict(badging)
    return {
        "app_name": display,
        "app_name_zh_cn": cn or "",
        "app_name_zh": zh_name or "",
        "app_name_default": default_name or "",
        "app_name_source": names["display_locale"] or "",
        "app_names": names,
    }
