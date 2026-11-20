"""提取反编译资源、原生库及其导出符号。"""

import hashlib
import logging
from pathlib import Path
from zipfile import ZipFile

from apk_lens_service.utils import find_readelf

logger = logging.getLogger(__name__)

CONTENT_MAX_BYTES = 256 * 1024  # resource content 截断上限

# 文本类资源扩展名（存 content）；其余按二进制（只存 metadata）
TEXT_EXTS = {
    ".xml", ".properties", ".json", ".txt", ".html", ".htm", ".js", ".css",
    ".md", ".kts", ".kt", ".gradle", ".mf", ".csv", ".svg", ".proto",
    ".version", ".lst", ".bin",  # .bin 多为文本 metadata（kotlin/proguard 等）
}


def calculate_file_sha256(file_path: Path | str, chunk_size: int = 65536) -> str:
    """分块计算文件 SHA256（仿 utils.calculate_file_md5）。"""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def _infer_res_type(rel_path: str) -> str:
    """从资源相对路径推断 res_type。"""
    first = rel_path.split("/", 1)[0]
    mapping = {
        "AndroidManifest.xml": "manifest",
        "res": "res",
        "assets": "assets",
        "META-INF": "meta_inf",
        "kotlin": "kotlin_meta",
        "lib": "lib",
    }
    return mapping.get(first, first or "other")


def iter_resource_records(resources_dir: Path, rel_paths: list[str]):
    """逐条生成资源记录，文本最多读取 CONTENT_MAX_BYTES。"""
    for rel in rel_paths:
        abs_path = resources_dir / rel
        try:
            if not abs_path.is_file():
                continue
            ext = abs_path.suffix.lower()
            size = abs_path.stat().st_size
            content = None
            metadata: dict = {"size": size}

            if ext in TEXT_EXTS:
                try:
                    with abs_path.open("rb") as source:
                        raw = source.read(CONTENT_MAX_BYTES + 1)
                    if len(raw) > CONTENT_MAX_BYTES:
                        metadata["truncated"] = True
                    content = raw[:CONTENT_MAX_BYTES].decode("utf-8", errors="replace")
                except Exception as exc:
                    logger.debug("资源读取失败（按二进制处理）: %s, %s", rel, exc)
                    content = None

            yield {
                "res_path": rel,
                "res_type": _infer_res_type(rel),
                "content": content,
                "metadata": metadata,
            }
        except Exception as exc:
            logger.debug("资源记录构建失败: %s, %s", rel, exc)
def collect_native_libraries(apk_path: str) -> list[dict]:
    """从源 APK 的 lib/{arch}/*.so 提取 native 库信息（arch/sha256/exports）。

    exports 用 readelf 解析导出函数符号（GLOBAL FUNC）。
    """

    import tempfile
    from shutil import copyfileobj

    libs = []
    readelf = find_readelf()
    try:
        with ZipFile(apk_path) as zf:
            for name in zf.namelist():
                if not (name.startswith("lib/") and name.endswith(".so")):
                    continue
                parts = name.split("/")
                arch = parts[1] if len(parts) >= 3 else "unknown"
                try:
                    with tempfile.NamedTemporaryFile(suffix=".so") as tmp:
                        with zf.open(name) as source:
                            copyfileobj(source, tmp, length=65536)
                        tmp.flush()
                        lib_sha256 = calculate_file_sha256(tmp.name)
                        exports = _read_native_exports(readelf, tmp.name) if readelf else None

                    libs.append({
                        "lib_name": parts[-1],
                        "arch": arch,
                        "sha256": lib_sha256,
                        "obj_path": name,
                        "exports": exports if exports else None,
                        "exports_status": (
                            "tool_unavailable" if not readelf else "failed" if exports is None else "ok"
                        ),
                    })
                except Exception as exc:
                    logger.debug("so 读取失败: %s, %s", name, exc)
    except Exception as exc:
        logger.warning("提取 native libs 失败: %s, error=%s", apk_path, exc)
    return libs


def _read_native_exports(readelf: str, path: str) -> list[str] | None:
    import subprocess

    try:
        result = subprocess.run(
            [readelf, "--wide", "--dyn-syms", path], capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("readelf 解析失败: %s", exc)
        return None
    if result.returncode != 0:
        return None
    exports = []
    for line in result.stdout.splitlines():
        tokens = line.split()
        if len(tokens) >= 8 and tokens[3:5] == ["FUNC", "GLOBAL"] and tokens[6] != "UND":
            symbol = tokens[7]
            if not symbol.startswith("_DYNAMIC"):
                exports.append(symbol)
    return exports
