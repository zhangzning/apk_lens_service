import json
import os
import stat
from collections.abc import Iterable, Iterator
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from apk_lens_service.config import MAX_REPORT_BYTES


class AnalysisError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def encode_report(report: dict) -> bytes:
    data = json.dumps(report, ensure_ascii=True, separators=(",", ":")).encode()
    if len(data) > MAX_REPORT_BYTES:
        raise AnalysisError("RESULT_LIMIT", "解析报告超过大小上限")
    return data


def checked_files(roots: Iterable[Path], *, byte_limit: int, file_limit: int) -> Iterator[Path]:
    """遍历本次生成的常规文件，拒绝符号链接和超出结果配额的输出。"""

    file_count = 0
    byte_count = 0
    for root in roots:
        if not root.exists() and not root.is_symlink():
            continue
        if root.is_symlink() or not root.is_dir():
            raise AnalysisError("INVALID_ARTIFACT", "解析产物目录格式无效")
        for directory, dir_names, file_names in os.walk(root):
            parent = Path(directory)
            for child in dir_names:
                if (parent / child).is_symlink():
                    raise AnalysisError("INVALID_ARTIFACT", "解析产物包含符号链接")
            for name in sorted(file_names):
                path = parent / name
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode):
                    raise AnalysisError("INVALID_ARTIFACT", "解析产物包含非常规文件")
                file_count += 1
                byte_count += info.st_size
                if file_count > file_limit or byte_count > byte_limit:
                    raise AnalysisError("RESULT_LIMIT", "解析产物超过文件数或大小上限")
                yield path
            dir_names.sort()


def write_bundle(
    job_dir: Path,
    report: bytes,
    roots: list[Path],
    *,
    byte_limit: int,
    file_limit: int,
) -> Path:
    result = job_dir / "result.zip"
    with ZipFile(result, "w", compression=ZIP_DEFLATED, compresslevel=1) as archive:
        archive.writestr("result.json", report)
        remaining = byte_limit - len(report)
        for member in checked_files(roots, byte_limit=remaining, file_limit=file_limit):
            archive.write(member, member.relative_to(job_dir / "artifacts").as_posix())
    return result
