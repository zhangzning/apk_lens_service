"""Read and project Android manifests."""

import re
import shutil
from collections.abc import Sequence
from io import BytesIO
from pathlib import Path
from struct import Struct
from struct import error as StructError
from sys import getsizeof
from time import monotonic
from xml.etree.ElementTree import Element
from zipfile import ZIP_DEFLATED, ZIP_STORED, BadZipFile, ZipExtFile, ZipFile
from zlib import error as ZlibError

from apk_lens_service.config import MAX_REPORT_BYTES
from apk_lens_service.utils import run_command

ANDROID = "http://schemas.android.com/apk/res/android"
ANDROID_ATTR = f"{{{ANDROID}}}"
REQUEST_TAGS = {"uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"}
COMPONENT_TAGS = {
    "activity": "activities",
    "service": "services",
    "receiver": "receivers",
    "provider": "providers",
    "activity-alias": "activity_aliases",
    "uses-library": "libraries",
}
_ELEMENT = re.compile(r"([^\s]*)(?:\s*\(line=\d+\))?")
_NAMESPACE = re.compile(r"([^=]*)=(\S+?)(?:\s+\(line=\d+\))?")
_ATTRIBUTE = re.compile(r"([^\s(=]*)(?:\(0x([0-9a-fA-F]+)\))?=(.*)")
_DUMP_PERMISSION_NAME = re.compile(r"name='([^'\r\n]+)'")
# Package parsing identifies these framework attributes by resource ID.
_FRAMEWORK_ATTRIBUTES = {
    "01010003": "name",
    "01010009": "protectionLevel",
    "01010202": "targetActivity",
    "0101020c": "minSdkVersion",
    "0101021b": "versionCode",
    "0101021c": "versionName",
    "01010270": "targetSdkVersion",
    "01010271": "maxSdkVersion",
}
_FRAMEWORK_ATTRIBUTES_BY_ID = {
    int(resource_id, 16): name for resource_id, name in _FRAMEWORK_ATTRIBUTES.items()
}
_PROJECTED_ANDROID_ATTRIBUTES = frozenset(ANDROID_ATTR + name for name in _FRAMEWORK_ATTRIBUTES.values())
_RAW_SUFFIX = re.compile(r'\s+\(Raw: ".*"\)$')
_TYPED_VALUE = re.compile(r"^\(type 0x[0-9a-fA-F]+\)\s*")
_OUTPUT_LIMIT = 16 * 1024**2
MAX_MANIFEST_BYTES = 32 * 1024**2

# Chunk and node types from Android's androidfw/ResourceTypes.h.
_XML = 0x0003
_STRING_POOL = 0x0001
_RESOURCE_MAP = 0x0180
_START_ELEMENT = 0x0102
_END_ELEMENT = 0x0103
_NODE_EXT_SIZES = {0x0100: 8, 0x0101: 8, _START_ELEMENT: 20, _END_ELEMENT: 8, 0x0104: 12}
_NO_INDEX = 0xFFFFFFFF
_CHUNK = Struct("<HHI")
_POOL_HEADER = Struct("<IIIII")
_INDEX = Struct("<I")
_UTF16_UNIT = Struct("<H")
_ELEMENT_NAME = Struct("<II")
_START = Struct("<IIHHH6x")
_AXML_ATTRIBUTE = Struct("<II4xHBBI")
_BLOCK_BYTES = 64 * 1024
_STRING_BYTES = 4096
_STREAM_ITEMS = 65_536
_STREAM_DEPTH = 256
_STREAM_TIMEOUT = 20


def parse_xmltree(output: str) -> Element | None:
    """Recover the element hierarchy and Android attributes from aapt2 dump xmltree."""
    root = None
    elements: list[tuple[int, Element]] = []
    namespaces: list[tuple[int, str, str]] = []
    anonymous_attribute = False
    for line in output.split("\n"):
        content = line.lstrip(" \t").rstrip("\r")
        if not content:
            continue
        indent = len(line) - len(line.lstrip(" \t"))
        kind, separator, value = content.partition(": ")
        if not separator or kind not in {"N", "E", "A", "T"}:
            if anonymous_attribute and "=" in content:
                anonymous_attribute = False
                continue
            return None
        anonymous_attribute = False
        while namespaces and namespaces[-1][0] >= indent:
            namespaces.pop()
        while elements and elements[-1][0] >= indent:
            elements.pop()
        if kind == "N":
            ns = _NAMESPACE.fullmatch(value)
            if not ns:
                return None
            namespaces.append((indent, ns[1], ns[2]))
        elif kind == "E":
            tag = _ELEMENT.fullmatch(value)
            if not tag:
                return None
            # Keep unnamed nested records as structural placeholders. They
            # cannot match any Android manifest tag used by the projection.
            node = Element(tag[1].rsplit(":", 1)[-1])
            if elements:
                elements[-1][1].append(node)
            elif root is not None:
                return None
            else:
                root = node
            elements.append((indent, node))
        elif kind == "A":
            attr = _ATTRIBUTE.fullmatch(value)
            if not elements:
                return None
            if not attr:
                if not value.strip() or (value[:1].isspace() and "=" not in value):
                    # Unnamed attributes can leave a continuation outside the
                    # usual indentation. Neither line defines a projected field.
                    anonymous_attribute = True
                    continue
                return None
            key, resource_id, raw_value = attr.groups()
            framework_field = _FRAMEWORK_ATTRIBUTES.get((resource_id or "").lower())
            if framework_field:
                key = ANDROID_ATTR + framework_field
            elif not key:
                if not resource_id:
                    return None
                # AAPT2 can print an unnamed resource attribute. Its ID confirms
                # that it is outside the fields used for this projection.
                continue
            elif ":" in key:
                prefix, field = key.rsplit(":", 1)
                uri = next((uri for _, alias, uri in reversed(namespaces) if alias == prefix), prefix)
                key = f"{{{uri}}}{field}" if uri != "android" else ANDROID_ATTR + field
            node = elements[-1][1]
            if key not in _PROJECTED_ANDROID_ATTRIBUTES and (key != "package" or node is not root):
                continue
            raw_value = _TYPED_VALUE.sub("", _RAW_SUFFIX.sub("", raw_value))
            if raw_value.startswith('"'):
                if not raw_value.endswith('"') or len(raw_value) < 2:
                    return None
                raw_value = raw_value[1:-1]
            previous = node.get(key)
            node.set(key, raw_value if previous is None or previous == raw_value else "@?")
    if root is None or root.tag != "manifest":
        return None
    return root


def read_xmltree(apk_path: Path, aapt2_bin: str) -> tuple[Element | None, str]:
    return _read_xmltree(
        aapt2_bin, "aapt2", ["dump", "xmltree", "--file", "AndroidManifest.xml", str(apk_path)],
    )


def read_legacy_xmltree(apk_path: Path) -> tuple[Element | None, str]:
    return _read_xmltree(
        "aapt", "aapt", ["dump", "xmltree", str(apk_path), "AndroidManifest.xml"],
    )


def _read_xmltree(binary: str, source: str, arguments: list[str]) -> tuple[Element | None, str]:
    executable = shutil.which(binary)
    if not executable:
        return None, f"{source} 不可用"
    code, output, stderr = run_command(
        [executable, *arguments],
        timeout=20, capture_limit=_OUTPUT_LIMIT,
    )
    if code != 0:
        return None, stderr[:200] or f"{source} 退出码 {code}"
    root = parse_xmltree(output)
    return (root, "") if root is not None else (None, f"{source} 未返回可读取的 Manifest 树")


def read_permission_dump(apk_path: Path, aapt2_bin: str) -> tuple[str, list[str], list[str]] | None:
    """Read only the names AAPT2 can confirm without returning the XML tree."""
    executable = shutil.which(aapt2_bin)
    if not executable:
        return None
    code, output, _ = run_command(
        [executable, "dump", "permissions", str(apk_path)],
        timeout=20, capture_limit=2 * 1024**2,
    )
    if code != 0:
        return None
    package = ""
    requested: list[str] = []
    defined: list[str] = []
    for line in output.splitlines():
        label, separator, value = line.partition(": ")
        if not separator:
            continue
        if label == "package":
            if package and package != value:
                return None
            package = value
        elif label in REQUEST_TAGS or label == "permission":
            match = _DUMP_PERMISSION_NAME.fullmatch(value)
            if not match:
                continue
            name = match[1]
            if (name.isprintable() and not name.startswith(("@", "?"))
                    and not any(char.isspace() or char == "\ufffd" for char in name)):
                target = defined if label == "permission" else requested
                target.append(name)
    return (package, requested, defined) if package else None


def manifest_requires_streaming(apk_path: Path) -> bool:
    try:
        with ZipFile(apk_path) as apk:
            return apk.getinfo("AndroidManifest.xml").file_size > MAX_MANIFEST_BYTES
    except (BadZipFile, OSError, KeyError):
        return False


class _ManifestStream:
    def __init__(self, stream: ZipExtFile):
        self.stream = stream
        self.deadline = monotonic() + _STREAM_TIMEOUT

    def tell(self) -> int:
        return self.stream.tell()

    def read(self, size: int) -> bytes:
        if monotonic() >= self.deadline:
            raise ValueError("读取超时")
        data = self.stream.read(size)
        if len(data) != size:
            raise ValueError("数据提前结束")
        return data

    def advance(self, offset: int) -> None:
        remaining = offset - self.tell()
        if remaining < 0:
            raise ValueError("数据块位置无效")
        while remaining:
            remaining -= len(self.read(min(remaining, _BLOCK_BYTES)))

    def chunk(self, limit: int) -> tuple[int, int, int]:
        start = self.tell()
        if limit - start < _CHUNK.size:
            raise ValueError("数据块头不完整")
        kind, header, size = _CHUNK.unpack(self.read(_CHUNK.size))
        if not _CHUNK.size <= header <= size <= limit - start or (header | size) & 3:
            raise ValueError("数据块大小无效")
        return kind, start + header, start + size

    def indices(self, count: int) -> list[int]:
        if count > _STREAM_ITEMS:
            raise ValueError("索引过多")
        indices = []
        while count:
            entries = min(count, _BLOCK_BYTES // _INDEX.size)
            indices.extend(value for (value,) in _INDEX.iter_unpack(self.read(entries * _INDEX.size)))
            count -= entries
        return indices


def _pool_string(data: bytes, start: int, utf8: bool) -> str | None:
    if utf8:
        # UTF-8 entries carry the UTF-16 character count followed by the byte count.
        start += 2 if data[start] & 0x80 else 1
        if start >= len(data):
            return None
        length = data[start]
        start += 1
        if length & 0x80:
            if start >= len(data):
                return None
            length = ((length & 0x7f) << 8) | data[start]
            start += 1
        terminator = b"\0"
    else:
        length, = _UTF16_UNIT.unpack_from(data, start)
        start += _UTF16_UNIT.size
        if length & 0x8000:
            if start + _UTF16_UNIT.size > len(data):
                return None
            low, = _UTF16_UNIT.unpack_from(data, start)
            length = ((length & 0x7fff) << 16) | low
            start += _UTF16_UNIT.size
        length *= _UTF16_UNIT.size
        terminator = b"\0\0"
    end = start + length
    if length > _STRING_BYTES or data[end:end + len(terminator)] != terminator:
        return None
    try:
        value = data[start:end].decode("utf-8" if utf8 else "utf-16-le")
    except UnicodeDecodeError:
        return None
    return None if "\0" in value else value


def _read_streamed_strings(stream: _ManifestStream, header: int, end: int) -> list[str | None]:
    start = stream.tell() - _CHUNK.size
    if header - stream.tell() < _POOL_HEADER.size:
        raise ValueError("字符串池头不完整")
    count, styles, flags, strings_start, styles_start = _POOL_HEADER.unpack(stream.read(_POOL_HEADER.size))
    string_data = start + strings_start
    strings_end = start + styles_start if styles_start else end
    if not header + (count + styles) * _INDEX.size <= string_data <= strings_end <= end:
        raise ValueError("字符串池边界无效")
    stream.advance(header)
    offsets = stream.indices(count)
    stream.advance(string_data)
    utf8 = bool(flags & 0x100)
    min_length = 1 if utf8 else _UTF16_UNIT.size
    window = b""
    window_start = string_data
    decoded: dict[int, str] = {}
    retained_bytes = 0
    # Offsets may be duplicated or unordered. Reading them in file order lets
    # ZIP inflation move forward once while keeping at most one small window.
    for offset in sorted(set(offsets)):
        position = string_data + offset
        if position + min_length > strings_end or (not utf8 and offset % _UTF16_UNIT.size):
            continue
        if position >= stream.tell():
            stream.advance(position)
            window = b""
            window_start = position
        if stream.tell() < min(strings_end, position + _STRING_BYTES + 6):
            window = window[position - window_start:] + stream.read(min(_BLOCK_BYTES, strings_end - stream.tell()))
            window_start = position
        value = _pool_string(window, position - window_start, utf8)
        if value is not None:
            retained_bytes += getsizeof(value)
            if retained_bytes > MAX_REPORT_BYTES:
                raise ValueError("可保留字符串超出限制")
            decoded[offset] = value
    return [decoded.get(offset) for offset in offsets]


def _read_streamed_tree(stream: _ManifestStream, end: int) -> Element:
    strings: list[str | None] | None = None
    resource_ids: list[int] | None = None
    root = None
    stack: list[tuple[tuple[int, int], Element]] = []
    attributes_seen = retained_bytes = 0
    for _ in range(_STREAM_ITEMS):
        if stream.tell() == end:
            break
        kind, header, chunk_end = stream.chunk(end)
        if kind == _STRING_POOL:
            if strings is not None or root is not None:
                raise ValueError("字符串池重复或顺序无效")
            strings = _read_streamed_strings(stream, header, chunk_end)
        elif kind == _RESOURCE_MAP:
            if strings is None or resource_ids is not None or root is not None:
                raise ValueError("资源映射重复或顺序无效")
            stream.advance(header)
            resource_ids = stream.indices((chunk_end - header) // _INDEX.size)
        elif kind in _NODE_EXT_SIZES:
            if strings is None or header - stream.tell() < 8 or chunk_end - header < _NODE_EXT_SIZES[kind]:
                raise ValueError("XML 节点头不完整")
            stream.advance(header)
            if kind == _START_ELEMENT:
                namespace, index, attr_start, attr_size, count = _START.unpack(stream.read(_START.size))
                if (attr_start < _START.size or attr_size < _AXML_ATTRIBUTE.size
                        or header + attr_start + attr_size * count > chunk_end):
                    raise ValueError("属性边界无效")
                attributes_seen += count
                if attributes_seen > _STREAM_ITEMS or len(stack) >= _STREAM_DEPTH:
                    raise ValueError("XML 节点或属性超出限制")
                tag = strings[index] if index < len(strings) else None
                if tag is None:
                    raise ValueError("XML 元素名无法读取")
                node = Element(tag)
                stream.advance(header + attr_start)
                for _ in range(count):
                    attr_end = stream.tell() + attr_size
                    ns, key, value_size, _, value_type, value = _AXML_ATTRIBUTE.unpack(stream.read(_AXML_ATTRIBUTE.size))
                    if not 8 <= value_size <= attr_size - 12:
                        raise ValueError("属性值边界无效")
                    _project_binary_attribute(node, ns, key, value_type, value, strings, resource_ids or ())
                    stream.advance(attr_end)
                retained_bytes += getsizeof(node.tag) + sum(getsizeof(value) for value in node.attrib.values())
                if retained_bytes > MAX_REPORT_BYTES:
                    raise ValueError("组件投影超出限制")
                if stack:
                    stack[-1][1].append(node)
                elif root is not None:
                    raise ValueError("XML 存在多个根元素")
                else:
                    root = node
                stack.append(((namespace, index), node))
            elif kind == _END_ELEMENT:
                element = _ELEMENT_NAME.unpack(stream.read(_ELEMENT_NAME.size))
                if not stack or stack.pop()[0] != element:
                    raise ValueError("XML 元素起止记录不匹配")
        # Android ignores unknown chunk types. Their lengths were checked
        # against the container above, so no data from them enters the projection.
        stream.advance(chunk_end)
    if stream.tell() != end or stack or root is None or root.tag != "manifest":
        raise ValueError("XML 树未完整闭合")
    return root


def read_streamed_manifest(apk_path: Path) -> tuple[Element | None, str]:
    """Project a large ZIP member without loading the XML or writing a copy."""
    try:
        with ZipFile(apk_path) as apk:
            member = apk.getinfo("AndroidManifest.xml")
            if member.file_size <= MAX_MANIFEST_BYTES:
                return None, "Manifest 未超过常规读取上限"
            if member.compress_type not in {ZIP_STORED, ZIP_DEFLATED}:
                return None, "流式读取不支持该 Manifest 压缩方式"
            with apk.open(member) as raw:
                stream = _ManifestStream(raw)
                kind, header, end = stream.chunk(member.file_size)
                if kind != _XML:
                    raise ValueError("Manifest 不是二进制 XML")
                stream.advance(header)
                root = _read_streamed_tree(stream, end)
                # Read through the ZIP member boundary so ZipFile verifies its CRC.
                stream.advance(member.file_size)
        return root, ""
    except ValueError as exc:
        return None, f"二进制 Manifest 流式读取失败（{exc}）"
    except (BadZipFile, EOFError, OSError, KeyError, RuntimeError, StructError, ZlibError) as exc:
        return None, f"二进制 Manifest 流式读取失败（{type(exc).__name__}）"


def read_binary_manifest(apk_path: Path) -> tuple[Element | None, str]:
    """Project compiled XML events without serializing namespace or attribute names."""
    from apkInspector.axml import ManifestStruct, XmlEndElement, XmlStartElement

    try:
        with ZipFile(apk_path) as apk:
            member = apk.getinfo("AndroidManifest.xml")
            if not 0 < member.file_size <= MAX_MANIFEST_BYTES:
                return None, "Manifest 大小超出读取限制"
            with apk.open(member) as stream:
                data = stream.read(MAX_MANIFEST_BYTES + 1)
        if len(data) != member.file_size or data[:2] != b"\x03\x00":
            return None, "Manifest 不是可读取的二进制 XML"
        binary = ManifestStruct.parse(BytesIO(data))
        strings = binary.string_pool.string_list
        resource_ids = binary.resource_map.resids
        root: Element | None = None
        stack: list[tuple[tuple[int, int], Element]] = []
        for event in binary.elements:
            if isinstance(event, XmlStartElement):
                namespace, index, *_ = event.attrext
                name = strings[index]
                if not name or not isinstance(name, str):
                    return None, "Manifest 元素名无法读取"
                node = Element(name)
                for attribute in event.attributes:
                    _project_binary_attribute(
                        node, attribute.full_namespace_index, attribute.name_index,
                        attribute.typed_value_datatype, attribute.typed_value_data, strings, resource_ids,
                    )
                if stack:
                    stack[-1][1].append(node)
                elif root is not None:
                    return None, "Manifest 存在多个根元素"
                else:
                    root = node
                stack.append(((namespace, index), node))
            elif isinstance(event, XmlEndElement):
                if not stack or stack.pop()[0] != tuple(event.attrext):
                    return None, "Manifest 元素起止记录不匹配"
        if stack or root is None or root.tag != "manifest":
            return None, "Manifest 根元素未完整闭合"
        return root, ""
    except (BadZipFile, OSError, ValueError, KeyError, IndexError, RuntimeError, TypeError, StructError) as exc:
        return None, f"二进制 Manifest 读取失败（{type(exc).__name__}）"


def _project_binary_attribute(
    node: Element, namespace: int, index: int, kind: int, encoded: int,
    strings: Sequence[str | None], resource_ids: Sequence[int],
) -> None:
    resource_id = resource_ids[index] if index < len(resource_ids) else 0
    field = _FRAMEWORK_ATTRIBUTES_BY_ID.get(resource_id)
    if field:
        key = ANDROID_ATTR + field
    elif index < len(strings):
        name = strings[index]
        if namespace < len(strings) and strings[namespace] == ANDROID and name in _FRAMEWORK_ATTRIBUTES_BY_ID.values():
            key = ANDROID_ATTR + name
        elif namespace == 0xFFFFFFFF and node.tag == "manifest" and name == "package":
            key = "package"
        else:
            return
    else:
        return

    if kind == 3 and encoded < len(strings) and isinstance(strings[encoded], str):
        value = strings[encoded]
    elif kind == 16 and key != "package":
        value = str(encoded)
    elif kind == 17 and key != "package":
        value = f"0x{encoded:x}"
    else:
        value = "@?"
    previous = node.get(key)
    node.set(key, value if previous is None or value == previous else "@?")


def android_name(node: Element) -> str:
    value = node.get(ANDROID_ATTR + "name", "").strip()
    return value if value and not value.startswith(("@", "?")) and not any(c.isspace() or c == "\ufffd" for c in value) else ""


def local_tag(node: Element) -> str:
    return node.tag.rsplit("}", 1)[-1] if isinstance(node.tag, str) else ""


def _children(node: Element, tag: str):
    return (child for child in node if local_tag(child) == tag)


def declarations(root: Element) -> tuple[dict[str, dict[str, str]], bool]:
    permissions: dict[str, dict[str, str]] = {}
    complete = True
    for node in _children(root, "permission"):
        name = android_name(node)
        level = node.get(ANDROID_ATTR + "protectionLevel", "0x00000000")
        if not name or name in permissions or not level or level.startswith(("@", "?")):
            complete = False
            continue
        permissions[name] = {"protectionLevel": level}
    return permissions, complete


def qualify_class(package: str, name: str) -> str:
    if name.startswith("."):
        return package + name
    return name if "." in name else f"{package}.{name}"


def _android_integer(value: str) -> int | None:
    if re.fullmatch(r"0x[0-9a-fA-F]{1,8}", value):
        return int(value, 16)
    return int(value) if re.fullmatch(r"\d{1,10}", value) else None


def launcher_activity(root: Element, package: str) -> str:
    for application in _children(root, "application"):
        for component in application:
            if local_tag(component) not in {"activity", "activity-alias"} or not (name := android_name(component)):
                continue
            for intent in _children(component, "intent-filter"):
                actions = {android_name(node) for node in _children(intent, "action")}
                categories = {android_name(node) for node in _children(intent, "category")}
                if "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in categories:
                    return qualify_class(package, name)
    return ""


def requested_permissions(root: Element) -> tuple[list[str], list[dict], bool]:
    requests = []
    complete = True
    for node in root:
        tag = local_tag(node)
        if tag not in REQUEST_TAGS:
            continue
        if not (name := android_name(node)):
            complete = False
            continue
        request = {"name": name, "tag": tag}
        maximum = node.get(ANDROID_ATTR + "maxSdkVersion")
        if maximum is not None:
            if (number := _android_integer(maximum)) is None:
                complete = False
            else:
                request["max_sdk_version"] = number
        requests.append(request)
    return list(dict.fromkeys(request["name"] for request in requests)), requests, complete


def manifest_fields(root: Element) -> tuple[dict, set[str]]:
    """Return fields read from a complete tree and identify any unreadable groups."""
    package = root.get("package", "").strip()
    incomplete: set[str] = set()
    fields: dict = {field: [] for field in COMPONENT_TAGS.values()}
    permissions, requests, requests_complete = requested_permissions(root)
    fields.update(package_name=package, permissions=permissions, permission_requests=requests)
    if not requests_complete:
        incomplete.add("permissions")
    applications = list(_children(root, "application"))
    if len(applications) > 1:
        incomplete.update(COMPONENT_TAGS.values())
    for application in applications:
        for node in application:
            tag = local_tag(node)
            if (field := COMPONENT_TAGS.get(tag)) is None:
                continue
            if not (name := android_name(node)):
                incomplete.add(field)
                continue
            if tag == "activity-alias":
                target = node.get(ANDROID_ATTR + "targetActivity", "")
                if not target or target.startswith(("@", "?")):
                    incomplete.add(field)
                    continue
                fields[field].append({"name": qualify_class(package, name), "target_activity": qualify_class(package, target)})
            elif tag == "uses-library":
                fields[field].append(name)
            else:
                fields[field].append(qualify_class(package, name))
    for field in ("activities", "services", "receivers", "providers", "libraries"):
        fields[field] = list(dict.fromkeys(fields[field]))
    fields["library"] = ",".join(fields["libraries"])
    fields["main_activity"] = launcher_activity(root, package)
    sdk = next(_children(root, "uses-sdk"), None)
    for node, attribute, field in (
        (root, "versionName", "version_name"),
        (root, "versionCode", "version_code"),
        (sdk, "minSdkVersion", "min_sdk_version"),
        (sdk, "targetSdkVersion", "target_sdk_version"),
    ):
        if node is not None and (value := node.get(ANDROID_ATTR + attribute, "")) and not value.startswith(("@", "?")):
            number = _android_integer(value) if attribute != "versionName" else None
            fields[field] = str(number) if number is not None else value
    return fields, incomplete
