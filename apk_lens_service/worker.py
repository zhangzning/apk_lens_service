"""单阶段进程入口。每次从一个临时目录读取 sample.apk 并写出阶段报告。"""

import argparse
import errno
import logging
import stat
from collections.abc import Iterable
from pathlib import Path, PureWindowsPath
from zipfile import BadZipFile, ZipFile

from apk_lens_service.artifacts import AnalysisError, checked_files, encode_report
from apk_lens_service.config import Profile, parse_tools
from apk_lens_service.worker_limits import apply_process_limits

logger = logging.getLogger(__name__)


def validate_archive(apk: Path, *, byte_limit: int, file_limit: int) -> None:
    try:
        with ZipFile(apk) as archive:
            entries = archive.infolist()
            if sum(entry.filename == "AndroidManifest.xml" for entry in entries) != 1:
                raise AnalysisError("INVALID_APK", "APK 必须包含唯一的 AndroidManifest.xml")
            if len(entries) > file_limit or sum(entry.file_size for entry in entries) > byte_limit:
                raise AnalysisError("APK_EXPANSION_LIMIT", "APK 解压体积或条目数超过上限")
            for entry in entries:
                path = entry.filename.replace("\\", "/")
                if (
                    path.startswith("/")
                    or ".." in path.split("/")
                    or PureWindowsPath(path).drive
                    or stat.S_ISLNK(entry.external_attr >> 16)
                ):
                    raise AnalysisError("INVALID_APK", "APK 包含不安全的条目路径")
    except (BadZipFile, OSError) as exc:
        raise AnalysisError("INVALID_APK", "无法读取 APK 容器") from exc


def analyze_base(
    apk: Path, profile: Profile, *, prefer_aapt2: bool, include_file_tree: bool
) -> dict:
    from apk_lens_service.apk_parser import parse_apk_full
    from apk_lens_service.packer_detector import quick_packing_check

    base = parse_apk_full(
        str(apk), prefer_aapt2=prefer_aapt2, include_file_tree=include_file_tree
    )
    if not base["package_name"]:
        raise AnalysisError("APK_IDENTITY_UNRESOLVED", "无法从 APK 读取包名")

    # API 返回产物相对于 ZIP 的路径。请求临时目录仅供内部使用。
    base.pop("apk_path", None)
    base.pop("file_path", None)
    icon_path = base.get("icon_path")
    if icon_path:
        base["icon_path"] = f"icon/{Path(icon_path).name}"

    components_ok = base["manifest_components_status"] == "ok"
    modules = {
        "basic": {"status": "ok" if components_ok else "partial", "data": base},
        "packing": {"status": "ok", "data": quick_packing_check(apk)},
    }
    if profile != Profile.BASIC:
        from apk_lens_service.permission_analysis import analyze_permissions

        try:
            permissions = analyze_permissions(
                base["permissions"],
                base["target_sdk_version"],
                apk_path=apk,
                min_sdk_version=base["min_sdk_version"],
            )
            complete = components_ok and permissions["analysis_status"] == "complete"
            modules["permission_analysis"] = {"status": "ok" if complete else "partial", "data": permissions}
        except Exception:
            logger.exception("权限详情分析失败")
            modules["permission_analysis"] = {
                "status": "failed",
                "error": {"code": "PERMISSION_ANALYSIS_FAILED", "message": "权限详情分析失败"},
            }
    return modules


def analyze_certificate(apk: Path) -> dict:
    from apk_lens_service.cert_analyzer import parse_apk_certificate

    certificate = parse_apk_certificate(str(apk))
    status = "ok" if certificate["signature_version"] else "unavailable"
    return {"certificate": {"status": status, "data": certificate}}


def write_records(path: Path, records: Iterable[dict], *, byte_limit: int) -> int:
    count = 0
    written = 0
    with path.open("wb") as output:
        for record in records:
            line = encode_report(record) + b"\n"
            written += len(line)
            if written > byte_limit:
                raise AnalysisError("RESULT_LIMIT", "结构化代码或资源记录超过大小上限")
            output.write(line)
            count += 1
    return count


def analyze_deep(apk: Path, artifacts: Path, *, byte_limit: int, file_limit: int) -> dict:
    from apk_lens_service.java_extractor import extract_java_file
    from apk_lens_service.packer_detector import detect_packing, list_dex_files
    from apk_lens_service.reverse_artifacts import collect_native_libraries, iter_resource_records
    from apk_lens_service.source_service import decompile_apk, inspect_decompile_output

    decompiled = artifacts / "jadx"
    try:
        jadx_summary = decompile_apk(apk, decompiled, temp_dir=artifacts.parent / "tmp")
    except FileNotFoundError as exc:
        raise AnalysisError("JADX_UNAVAILABLE", "JADX 或 Java 不可用") from exc
    except RuntimeError as exc:
        raise AnalysisError("JADX_FAILED", "JADX 未生成可用结果") from exc

    for _ in checked_files([decompiled], byte_limit=byte_limit, file_limit=file_limit):
        pass
    jadx = inspect_decompile_output(decompiled, jadx_summary)
    sources = Path(jadx["sources_dir"])
    resources = Path(jadx["resources_dir"])
    reverse_dir = artifacts / "reverse"
    reverse_dir.mkdir()
    counts = {"classes": 0, "methods": 0, "fields": 0, "fallback_files": 0}

    def java_records():
        for relative_path in jadx["java_files"]:
            record = extract_java_file(
                sources / relative_path, source_file=relative_path, sources_root=sources
            )
            if record["parse_status"] != "ok":
                counts["fallback_files"] += 1
            for declaration in record["classes"]:
                counts["classes"] += 1
                counts["methods"] += len(declaration["methods"])
                counts["fields"] += len(declaration["fields"])
            yield record

    write_records(reverse_dir / "java.jsonl", java_records(), byte_limit=byte_limit)
    counts["resources"] = write_records(
        reverse_dir / "resources.jsonl",
        iter_resource_records(resources, jadx["resource_files"]),
        byte_limit=byte_limit,
    )
    native = collect_native_libraries(str(apk))
    counts["native_libraries"] = write_records(
        reverse_dir / "native.jsonl", native, byte_limit=byte_limit
    )
    statuses = {library["exports_status"] for library in native}
    if not native:
        native_exports = "not_applicable"
    elif "tool_unavailable" in statuses:
        native_exports = "tool_unavailable"
    else:
        native_exports = "partial" if "failed" in statuses else "available"

    jadx["source_root"] = "jadx/"
    jadx["sources_dir"] = "jadx/sources/"
    jadx["resources_dir"] = "jadx/resources/"
    jadx["jadx_summary"] = {"code": jadx_summary["code"]}
    jadx["dex_files"] = list_dex_files(apk)
    jadx["packing"] = detect_packing(apk, jadx["java_file_count"])
    return {
        "decompile": {"status": "partial" if jadx_summary["code"] else "ok", "data": jadx},
        "reverse": {
            "status": "partial" if counts["fallback_files"] or native_exports in {"partial", "tool_unavailable"} else "ok",
            "data": {
                **counts,
                "native_exports": native_exports,
                "java": "reverse/java.jsonl",
                "resources_file": "reverse/resources.jsonl",
                "native": "reverse/native.jsonl",
            },
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("full", "aapt2", "certificate", "deep"))
    parser.add_argument("profile", type=Profile)
    parser.add_argument("job_dir", type=Path)
    parser.add_argument("max_expanded_bytes", type=int)
    parser.add_argument("max_result_bytes", type=int)
    parser.add_argument("max_files", type=int)
    parser.add_argument("--include-file-tree", action="store_true")
    args = parser.parse_args()
    apk = args.job_dir / "sample.apk"
    try:
        apply_process_limits(parse_tools)
        from loguru import logger as androguard_logger

        androguard_logger.remove()
        if args.stage == "certificate":
            result = analyze_certificate(apk)
        elif args.stage == "deep":
            result = analyze_deep(
                apk, args.job_dir / "artifacts",
                byte_limit=args.max_result_bytes, file_limit=args.max_files,
            )
        else:
            validate_archive(apk, byte_limit=args.max_expanded_bytes, file_limit=args.max_files)
            result = analyze_base(
                apk, args.profile, prefer_aapt2=args.stage == "aapt2",
                include_file_tree=args.include_file_tree,
            )
        payload = encode_report({"modules": result})
    except AnalysisError as exc:
        payload = encode_report({"error": {"code": exc.code, "message": str(exc)}})
    except OSError as exc:
        errors = {
            errno.EFBIG: ("RESULT_LIMIT", "解析阶段超过单文件大小上限"),
            errno.ENOSPC: ("WORKSPACE_LIMIT", "解析临时空间不足"),
            errno.EDQUOT: ("WORKSPACE_LIMIT", "解析临时空间达到配额"),
        }
        if exc.errno not in errors:
            logger.exception("静态解析阶段异常: %s", args.stage)
            return 1
        code, message = errors[exc.errno]
        payload = encode_report({"error": {"code": code, "message": message}})
    except MemoryError:
        payload = encode_report({"error": {"code": "STAGE_MEMORY_LIMIT", "message": "解析阶段内存分配失败"}})
    except Exception:
        logger.exception("静态解析阶段异常: %s", args.stage)
        return 1
    (args.job_dir / f"{args.stage}.json").write_bytes(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
