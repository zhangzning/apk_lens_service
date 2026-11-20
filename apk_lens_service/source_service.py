"""APK 反编译服务。

提供 jadx 反编译、Java 源码结构收集、资源结构收集等可复用的服务函数。
"""

import logging
import shutil
from pathlib import Path

from apk_lens_service.config import parse_tools as settings
from apk_lens_service.utils import (
    collect_java_source_structure,
    java_tool_environment,
    run_command,
)

logger = logging.getLogger("apk_lens_service.source_service")


def ensure_jadx_available() -> None:
    """确认 jadx 可执行文件存在。"""

    if not shutil.which(settings.jadx_bin):
        raise FileNotFoundError(f"jadx 可执行文件不存在: {settings.jadx_bin}")


def decompile_apk(
    apk_file: Path,
    output_dir: Path,
    timeout: int | None = None,
    *,
    temp_dir: Path | None = None,
) -> dict:
    """调用 jadx 反编译 APK 源码到指定目录。

    jadx 退出码：
    - 0：完全成功
    - 1：命令行参数错误
    - 2：初始化失败
    - 3：反编译有错误但大部分完成（仍有输出）
    """

    ensure_jadx_available()
    output_dir.mkdir(parents=True, exist_ok=True)
    effective_timeout = (
        int(settings.jadx_timeout_seconds)
        if timeout is None
        else max(1, int(timeout))
    )

    jadx_code, jadx_stdout, jadx_stderr = run_command(
        [
            settings.jadx_bin,
            "-d",
            str(output_dir),
            str(apk_file),
        ],
        timeout=effective_timeout,
        env=java_tool_environment(
            settings.java_home,
            max_heap_mb=settings.jadx_max_heap_mb,
            temp_dir=temp_dir,
        ),
    )

    # 仅 0/3 可用；127（命令不存在）和 124（超时）同样不能伪装成成功。
    if jadx_code not in (0, 3):
        raise RuntimeError(f"jadx 反编译失败 (exit={jadx_code}): {jadx_stderr or jadx_stdout}")

    return {
        "code": jadx_code,
        "stdout": jadx_stdout[-2000:],
        "stderr": jadx_stderr[-2000:],
    }


def collect_resources_structure(output_dir: Path) -> dict:
    """整理 jadx 反编译后的 resources 目录结构。"""

    resources_dir = output_dir / "resources"
    if not resources_dir.exists():
        return {
            "resources_dir": str(resources_dir.resolve()),
            "resource_file_count": 0,
            "resource_types": [],
            "resource_files": [],
        }

    resource_paths = sorted(
        [path for path in resources_dir.rglob("*") if path.is_file()],
        key=lambda item: str(item),
    )

    resource_files = [
        str(path.relative_to(resources_dir).as_posix())
        for path in resource_paths
    ]
    resource_types = sorted(
        {
            path.relative_to(resources_dir).parts[0]
            for path in resource_paths
            if path.relative_to(resources_dir).parts
        }
    )

    return {
        "resources_dir": str(resources_dir.resolve()),
        "resource_file_count": len(resource_files),
        "resource_types": resource_types,
        "resource_files": resource_files,
    }


def inspect_decompile_output(output_dir: Path, jadx_summary: dict) -> dict:
    """收集已生成的反编译目录，供不同入口使用同一结果结构。"""

    structure = collect_java_source_structure(output_dir / "sources")
    resources = collect_resources_structure(output_dir)

    return {
        "jadx_summary": jadx_summary,
        "source_root": str(output_dir.resolve()),
        "sources_dir": structure["sources_dir"],
        "java_file_count": structure["java_file_count"],
        "package_count": structure["package_count"],
        "package_names": structure["package_names"],
        "java_files": structure["java_files"],
        "java_dotted_files": structure["java_dotted_files"],
        "resources_dir": resources["resources_dir"],
        "resource_file_count": resources["resource_file_count"],
        "resource_types": resources["resource_types"],
        "resource_files": resources["resource_files"],
    }
