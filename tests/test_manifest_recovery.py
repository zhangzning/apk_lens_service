from io import BytesIO
from pathlib import Path
from struct import pack
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from apk_lens_service import apk_parser
from apk_lens_service import manifest
from apk_lens_service import permission_analysis
from apk_lens_service.config import Profile
from apk_lens_service.manifest import manifest_fields, parse_xmltree, requested_permissions
from apk_lens_service.permission_analysis import analyze_permissions
from apk_lens_service.worker import analyze_base


MANIFEST_TREE = """\
N: a=http://schemas.android.com/apk/res/android (line=1)
  E: manifest (line=2)
    A: package="test.static.fixture" (Raw: "test.static.fixture")
    A: a:versionCode(0x0101021b)=(type 0x10)0x2
      E: uses-sdk (line=3)
        A: a:minSdkVersion(0x0101020c)=0x18
        A: a:targetSdkVersion(0x01010270)=0x1e
      E: uses-permission (line=4)
        A: a:name(0x01010003)="android.permission.POST_NOTIFICATIONS"
      E: uses-permission-sdk-23 (line=5)
        A: http://schemas.android.com/apk/res/android:name(0x01010003)="android.permission.CAMERA"
        A: a:maxSdkVersion(0x01010271)=0x1d
      E: permission (line=6)
        A: a:name(0x01010003)="test.static.fixture.BRIDGE"
        A: a:protectionLevel(0x01010009)=0x2
      E: uses-permission (line=7)
        A: a:name(0x01010003)="test.static.fixture.BRIDGE"
      E: queries (line=8)
          E: provider (line=9)
            A: a:authorities="other.package"
      E: application (line=10)
          E: packed:activity (line=11)
            A: packed:renamed(0x01010003)=".Main"
          E: activity-alias (line=12)
            A: a:name(0x01010003)="Launcher"
            A: a:targetActivity(0x01010202)=".Main"
              E: intent-filter (line=13)
                  E: action (line=14)
                    A: a:name(0x01010003)="android.intent.action.MAIN"
                  E: category (line=15)
                    A: a:name(0x01010003)="android.intent.category.LAUNCHER"
          E: service (line=16)
            A: a:name(0x01010003)=".Worker"
          E: receiver (line=17)
            A: a:name(0x01010003)="com.example.Receiver"
          E: provider (line=18)
            A: a:name(0x01010003)=".Store"
"""


@pytest.fixture
def invalid_manifest_apk(tmp_path, monkeypatch):
    apk = tmp_path / "original.apk"
    with ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"fixture compiled manifest")
        archive.writestr("assets/data", b"untouched")
    monkeypatch.setattr(apk_parser.settings, "icon_storage_dir", tmp_path / "icon")
    monkeypatch.setattr(apk_parser, "extract_app_icon", lambda **_: {})
    monkeypatch.setattr(
        apk_parser, "parse_apk_with_aapt2",
        lambda *_: {"package_name": "test.static.fixture", "parser_used": "aapt2"},
    )
    return apk


@pytest.mark.parametrize("metadata_view", [False, True])
def test_aapt2_recovers_complete_components_and_permissions(invalid_manifest_apk, monkeypatch, metadata_view):
    read_paths = []

    def read(path, _):
        read_paths.append(path)
        if metadata_view and path == invalid_manifest_apk:
            return None, "original archive could not be opened"
        if metadata_view:
            with ZipFile(path) as archive:
                assert archive.namelist() == ["AndroidManifest.xml"]
        return parse_xmltree(MANIFEST_TREE), ""

    monkeypatch.setattr(apk_parser, "read_xmltree", read)
    modules = analyze_base(
        invalid_manifest_apk, Profile.STANDARD, prefer_aapt2=False, include_file_tree=False,
    )
    basic = modules["basic"]["data"]
    assert modules["basic"]["status"] == "ok"
    assert basic["manifest_components_source"] == ("aapt2_metadata_view" if metadata_view else "aapt2")
    assert basic["main_activity"] == "test.static.fixture.Launcher"
    assert basic["version_code"] == "2"
    assert basic["min_sdk_version"] == "24"
    assert basic["target_sdk_version"] == "30"
    assert basic["activities"] == ["test.static.fixture.Main"]
    assert basic["activity_aliases"] == [
        {"name": "test.static.fixture.Launcher", "target_activity": "test.static.fixture.Main"}
    ]
    assert basic["services"] == ["test.static.fixture.Worker"]
    assert basic["providers"] == ["test.static.fixture.Store"]
    assert basic["receivers"] == ["com.example.Receiver"]
    assert basic["permission_requests"][1] == {
        "name": "android.permission.CAMERA", "tag": "uses-permission-sdk-23", "max_sdk_version": 29,
    }
    assert "file_tree" not in basic
    assert modules["permission_analysis"]["status"] == "ok"
    permissions = {row["name"]: row for row in modules["permission_analysis"]["data"]["permissions"]}
    assert permissions["test.static.fixture.BRIDGE"]["protection_level"] == "signature"
    assert permissions["test.static.fixture.BRIDGE"]["desc"] == "未知"
    assert permissions["android.permission.POST_NOTIFICATIONS"]["definition_api_level"] == 33
    assert len(read_paths) == (2 if metadata_view else 1)
    if metadata_view:
        assert not read_paths[-1].exists()


def test_aapt2_does_not_merge_manifest_for_a_different_package(invalid_manifest_apk, monkeypatch):
    other_tree = MANIFEST_TREE.replace('package="test.static.fixture"', 'package="other.package"')
    monkeypatch.setattr(apk_parser, "read_xmltree", lambda *_: (parse_xmltree(other_tree), ""))
    report = apk_parser.parse_apk_full(str(invalid_manifest_apk), prefer_aapt2=True)
    assert report["manifest_components_status"] == "unavailable"
    assert report["activities"] == []
    assert report["package_name"] == "test.static.fixture"


def test_unreadable_component_does_not_claim_complete_manifest(invalid_manifest_apk, monkeypatch):
    incomplete = MANIFEST_TREE.replace('a:name(0x01010003)=".Worker"', 'a:name(0x01010003)=@0x7f020001')
    monkeypatch.setattr(apk_parser, "read_xmltree", lambda *_: (parse_xmltree(incomplete), ""))
    modules = analyze_base(
        invalid_manifest_apk, Profile.STANDARD, prefer_aapt2=True, include_file_tree=False,
    )
    assert modules["basic"]["status"] == "partial"
    assert modules["basic"]["data"]["activities"] == ["test.static.fixture.Main"]
    assert modules["permission_analysis"]["status"] == "ok"


def test_legacy_aapt_is_used_when_aapt2_cannot_build_tree(invalid_manifest_apk, monkeypatch):
    monkeypatch.setattr(apk_parser.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(apk_parser, "read_xmltree", lambda *_: (None, "could not open"))
    monkeypatch.setattr(apk_parser, "read_legacy_xmltree", lambda _: (parse_xmltree(MANIFEST_TREE), ""))
    report = apk_parser.parse_apk_full(str(invalid_manifest_apk), prefer_aapt2=True)
    assert report["manifest_components_source"] == "aapt"
    assert report["manifest_components_status"] == "ok"
    assert report["activities"] == ["test.static.fixture.Main"]
    assert report["permission_requests"][1]["max_sdk_version"] == 29


def test_aapt2_projects_names_by_resource_id_when_attribute_labels_are_absent():
    rendered = MANIFEST_TREE.replace(
        '    A: a:versionCode(0x0101021b)',
        '    A: (0x7f010001)="opaque"\n    A: (0x0101021b)',
    ).replace('A: packed:renamed(0x01010003)', 'A: (0x01010003)')
    tree = parse_xmltree(rendered)
    assert tree is not None
    fields, missing = manifest_fields(tree)
    assert not missing
    assert fields["package_name"] == "test.static.fixture"
    assert fields["activities"] == ["test.static.fixture.Main"]
    assert fields["version_code"] == "2"


def test_aapt2_retains_component_siblings_after_an_unnamed_element():
    rendered = MANIFEST_TREE.replace(
        "          E: service (line=16)",
        "          E:  (line=16)\n"
        '            A: a:name(0x01010003)=".Opaque"\n'
        "          E: service (line=16)",
    )
    tree = parse_xmltree(rendered)
    assert tree is not None
    fields, missing = manifest_fields(tree)
    assert not missing
    assert fields["services"] == ["test.static.fixture.Worker"]


def test_aapt2_ignores_unrelated_duplicate_attributes_but_marks_conflicting_names():
    application = "      E: application (line=10)"
    rendered = MANIFEST_TREE.replace(application, application + '\n'
        '        A: opaque(0x7f010001)="first"\n'
        '        A: opaque(0x7f010001)="second"\n'
        '        A:  ?\n'
        'tail="ignored"')
    root = parse_xmltree(rendered)
    assert root is not None
    fields, missing = manifest_fields(root)
    assert fields["services"] == ["test.static.fixture.Worker"]
    assert not missing

    conflict = rendered.replace(
        '            A: a:name(0x01010003)=".Worker"',
        '            A: a:name(0x01010003)=".Worker"\n'
        '            A: a:name(0x01010003)=".Other"',
    )
    root = parse_xmltree(conflict)
    assert root is not None
    fields, missing = manifest_fields(root)
    assert missing == {"services"}
    assert fields["activities"] == ["test.static.fixture.Main"]


def test_binary_manifest_is_used_when_aapt2_cannot_project_its_dump(invalid_manifest_apk, monkeypatch):
    monkeypatch.setattr(apk_parser, "read_xmltree", lambda *_: (None, "unreadable text output"))
    monkeypatch.setattr(apk_parser, "read_binary_manifest", lambda _: (parse_xmltree(MANIFEST_TREE), ""))
    report = apk_parser.parse_apk_full(str(invalid_manifest_apk), prefer_aapt2=True)
    assert report["manifest_components_source"] == "apkinspector_axml"
    assert report["manifest_components_status"] == "ok"
    assert report["providers"] == ["test.static.fixture.Store"]
    assert report["manifest_permission_requests_status"] == "ok"


def _make_streamed_axml(utf8: bool) -> bytes:
    def chunk(kind, header=b"", data=b""):
        data += b"\0" * (-len(data) % 4)
        return pack("<HHI", kind, 8 + len(header), 8 + len(header) + len(data)) + header + data

    def string(value):
        def length8(size):
            return bytes([size]) if size < 0x80 else bytes([0x80 | (size >> 8), size & 0xff])

        if utf8:
            encoded = value.encode("utf-8")
            return length8(len(value)) + length8(len(encoded)) + encoded + b"\0"
        length = len(value)
        prefix = pack("<H", length) if length < 0x8000 else pack("<HH", 0x8000 | (length >> 16), length & 0xffff)
        return prefix + value.encode("utf-16-le") + b"\0\0"

    text = [
        "manifest", "package", "test.static.fixture", manifest.ANDROID, "uses-permission-sdk-23",
        "name", "test.permission.UNKNOWN", "maxSdkVersion", "application", "service", ".Worker",
        "value", "x" * (20_000 if utf8 else 66_000),
    ]
    ids = {value: index for index, value in enumerate(text)}
    offsets = [0] * len(text)
    encoded = bytearray()
    for value in reversed(text):
        offsets[ids[value]] = len(encoded)
        encoded.extend(string(value))
    pool_header = pack("<IIIII", len(text), 0, 0x100 if utf8 else 0, 28 + 4 * len(text), 0)
    pool = chunk(0x0001, pool_header, pack(f"<{len(text)}I", *offsets) + encoded)

    no_index = 0xffffffff
    node_header = pack("<II", 1, no_index)

    def attribute(ns, name, kind, value):
        return pack("<IIIHBBI", ns, ids[name], no_index, 8, 0, kind, value) + b"\0" * 4

    def element(tag, attributes=(), children=b""):
        index = ids[tag]
        start = pack("<IIHHHHHH", no_index, index, 20, 24, len(attributes), 0, 0, 0)
        finish = pack("<II", no_index, index)
        return chunk(0x0102, node_header, start + b"".join(attributes)) + children + chunk(0x0103, node_header, finish)

    android = ids[manifest.ANDROID]
    request = element("uses-permission-sdk-23", [
        attribute(android, "name", 3, ids["test.permission.UNKNOWN"]),
        attribute(android, "maxSdkVersion", 16, 33),
    ])
    service = element("service", [attribute(android, "name", 3, ids[".Worker"])])
    application = element("application", [attribute(android, "value", 3, len(text) - 1)], service)
    root = element("manifest", [attribute(no_index, "package", 3, ids["test.static.fixture"])], request + application)
    return chunk(0x0003, data=pool + chunk(0x17e, data=b"\0" * 70_000) + root)


@pytest.mark.parametrize("utf8", [False, True])
def test_streamed_manifest_projects_fields_and_checks_the_end(utf8, monkeypatch):
    monkeypatch.setattr(manifest, "MAX_MANIFEST_BYTES", 1024)
    original = _make_streamed_axml(utf8)

    def read(payload):
        target = BytesIO()
        with ZipFile(target, "w", compression=ZIP_DEFLATED) as archive:
            archive.writestr("AndroidManifest.xml", payload)
        return manifest.read_streamed_manifest(target)

    root, problem = read(original + b"ZIP member trailer")
    assert not problem
    assert root is not None
    fields, incomplete = manifest_fields(root)
    assert not incomplete
    assert fields["package_name"] == "test.static.fixture"
    assert fields["services"] == ["test.static.fixture.Worker"]
    assert fields["permission_requests"] == [
        {"tag": "uses-permission-sdk-23", "name": "test.permission.UNKNOWN", "max_sdk_version": 33}
    ]
    root, problem = read(original[:-1])
    assert root is None
    assert problem


def test_permission_analysis_keeps_an_unverified_protection_level():
    names = ["android.permission.READ_APP_BADGE", "android.permission.EXAMPLE_NOT_IN_ANY_CATALOG"]
    report = analyze_permissions(
        names, 28, declared_permissions={},
        catalog={names[1]: {"desc": "没有可核实来源的解释"}},
    )
    by_name = {row["name"]: row for row in report["permissions"]}
    badge = by_name[names[0]]
    assert badge["permission_source"] == "third_party"
    assert badge["permission_vendor"] == "ZUK"
    assert badge["protection_level"] == "unknown"
    unknown = by_name[names[1]]
    assert unknown["permission_source"] == "android_unresolved"
    assert unknown["desc"] == "未知"
    assert unknown["protection_level"] == "unknown"
    assert unknown["grant_state"] == "not_checked"
    assert report["summary"]["unknown_description_count"] == 2
    assert report["warnings"]
    assert report["analysis_status"] == "complete"


def test_complete_manifest_with_unknown_permission_description_is_ok(invalid_manifest_apk, monkeypatch):
    name = "android.permission.EXAMPLE_NOT_IN_ANY_CATALOG"
    tree = MANIFEST_TREE.replace("android.permission.POST_NOTIFICATIONS", name)
    monkeypatch.setattr(apk_parser, "read_xmltree", lambda *_: (parse_xmltree(tree), ""))
    modules = analyze_base(invalid_manifest_apk, Profile.STANDARD, prefer_aapt2=True, include_file_tree=False)
    assert modules["basic"]["data"]["manifest_permission_requests_status"] == "ok"
    assert modules["permission_analysis"]["status"] == "ok"
    row = next(row for row in modules["permission_analysis"]["data"]["permissions"] if row["name"] == name)
    assert row["desc"] == "未知"


def test_permission_dump_fills_known_names_without_claiming_a_complete_manifest(invalid_manifest_apk, monkeypatch):
    monkeypatch.setattr(apk_parser, "read_xmltree", lambda *_: (None, "command output exceeded limit"))
    monkeypatch.setattr(apk_parser, "read_permission_dump", lambda *_: (
        "test.static.fixture", ["android.permission.CAMERA", "test.static.fixture.BRIDGE"],
        ["test.static.fixture.BRIDGE"],
    ))
    modules = analyze_base(invalid_manifest_apk, Profile.STANDARD, prefer_aapt2=True, include_file_tree=False)
    basic = modules["basic"]["data"]
    assert basic["manifest_permission_requests_source"] == "aapt2_permissions"
    assert basic["manifest_permission_requests_status"] == "partial"
    assert basic["permissions"] == ["android.permission.CAMERA", "test.static.fixture.BRIDGE"]
    analysis = modules["permission_analysis"]["data"]
    definitions = {row["name"]: row for row in analysis["permissions"]}
    assert definitions["test.static.fixture.BRIDGE"]["permission_source"] == "app_declared"
    assert definitions["test.static.fixture.BRIDGE"]["protection_level"] == "unknown"
    assert definitions["test.static.fixture.BRIDGE"]["grantability"] == "unknown"
    assert modules["permission_analysis"]["status"] == "partial"


def test_verified_empty_permission_list_needs_no_definition_sources(monkeypatch):
    def unexpected(*_):
        pytest.fail("An empty permission list does not require a definition lookup")

    monkeypatch.setattr(permission_analysis, "_load_platform_catalog", unexpected)
    monkeypatch.setattr(permission_analysis, "_coerce_declared_permissions", unexpected)
    report = analyze_permissions([], 34, manifest_requests_status="ok")
    assert report["analysis_status"] == "complete"
    assert report["permissions"] == []
    assert report["grant_state"] == "not_checked"
    assert set(report["metadata_status"].values()) == {"not_applicable"}
    unreadable = analyze_permissions([], 34, manifest_requests_status="unavailable")
    assert unreadable["analysis_status"] == "partial"
    assert unreadable["warnings"]


def test_androguard_xml_includes_sdk_conditioned_permission_requests():
    from lxml import etree

    root = etree.fromstring(b"""<manifest xmlns:android="http://schemas.android.com/apk/res/android">
        <uses-permission-sdk-m android:name="android.permission.CAMERA" />
        <uses-permission-sdk-23 android:name="android.permission.CAMERA" android:maxSdkVersion="33" />
        <application><uses-permission android:name="test.nested.invalid" /></application>
    </manifest>""")
    names, requests, complete = requested_permissions(root)
    assert complete
    assert names == ["android.permission.CAMERA"]
    assert requests == [
        {"name": "android.permission.CAMERA", "tag": "uses-permission-sdk-m"},
        {"name": "android.permission.CAMERA", "tag": "uses-permission-sdk-23", "max_sdk_version": 33},
    ]


def test_aosp_definition_uses_exact_name_and_versioned_reference():
    names = [
        "android.permission.ACCESS_DOWNLOAD_MANAGER",
        "android.permission.DOWNLOAD_WITHOUT_NOTIFICATION",
        "android.permission.INSTALL_SHORTCUT",
        "android.permission.ACCESS_ADSERVICES_AD_ID",
    ]
    report = analyze_permissions(names, 28, declared_permissions={})
    rows = {row["name"]: row for row in report["permissions"]}
    assert rows[names[0]]["protection_level"] == "signature_or_system"
    assert rows[names[0]]["definition_api_level"] == 34
    assert "/DownloadProvider/" in rows[names[0]]["definition_reference"]
    assert rows[names[1]]["protection_level"] == "normal"
    assert rows[names[2]]["permission_source"] == "android_unresolved"
    assert rows[names[2]]["desc"] == "未知"
    assert rows[names[3]]["protection_level"] == "normal"
    assert "/AdServices/" in rows[names[3]]["definition_reference"]
    assert report["analysis_status"] == "complete"
