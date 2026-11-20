"""管理一次请求的独立进程及降级行为。"""

import asyncio
import json
import os
import shutil
import signal
import sys
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from apk_lens_service.artifacts import AnalysisError
from apk_lens_service.config import MAX_REPORT_BYTES, MIB, Profile, StaticAnalysisSettings

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class StageResult:
    state: str
    modules: dict
    error: dict | None
    pid: int

    def attempt(self, stage: str) -> dict:
        result = {"stage": stage, "state": self.state, "pid": self.pid}
        if self.error:
            result["error_code"] = self.error["code"]
        return result


def child_environment(job_dir: Path, settings: StaticAnalysisSettings) -> dict[str, str]:
    allowed = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ")
    environment = {key: os.environ[key] for key in allowed if key in os.environ}
    temporary = job_dir / "tmp"
    environment.update(
        {
            "TMPDIR": str(temporary),
            "HOME": str(temporary),
            "JADX_TMP_DIR": str(temporary / "jadx-temp"),
            "JADX_CACHE_DIR": str(temporary / "jadx-cache"),
            "JADX_CONFIG_DIR": str(temporary / "jadx-config"),
            "APK_LENS_SERVICE_TOOL_ICON_STORAGE_DIR": str(job_dir / "artifacts" / "icon"),
            "APK_LENS_SERVICE_TOOL_AAPT2_BIN": settings.aapt2_bin,
            "APK_LENS_SERVICE_TOOL_JADX_BIN": settings.jadx_bin,
            "APK_LENS_SERVICE_TOOL_JAVA_HOME": settings.java_home,
            "APK_LENS_SERVICE_TOOL_JADX_MAX_HEAP_MB": str(settings.jadx_max_heap_mb),
            "APK_LENS_SERVICE_TOOL_JADX_TIMEOUT_SECONDS": str(
                max(300, min(3600, int(settings.deep_timeout)))
            ),
            "APK_LENS_SERVICE_TOOL_CPU_SECONDS": str(settings.worker_cpu_seconds),
            "APK_LENS_SERVICE_TOOL_ADDRESS_SPACE_MIB": str(settings.worker_address_space_mib),
            "APK_LENS_SERVICE_TOOL_MAX_FILE_MIB": str(settings.worker_max_file_mib),
        }
    )
    return environment


async def stop_group(process: asyncio.subprocess.Process, grace: float) -> None:
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    with suppress(TimeoutError):
        await asyncio.wait_for(process.wait(), grace)
    # 子进程可能已退出，工具进程仍留在同一进程组。
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    await process.wait()


async def run_stage(
    job_dir: Path,
    stage: str,
    profile: Profile,
    timeout: float,
    settings: StaticAnalysisSettings,
    *,
    include_file_tree: bool = False,
) -> StageResult:
    command = [
        sys.executable, "-B", "-m", "apk_lens_service.worker",
        stage, profile.value, str(job_dir), str(settings.max_expanded_mib * MIB),
        str(settings.max_result_mib * MIB), str(settings.max_files),
    ]
    if include_file_tree:
        command.append("--include-file-tree")
    launch = asyncio.create_task(
        asyncio.create_subprocess_exec(
            *command,
            cwd=PROJECT_ROOT,
            env=child_environment(job_dir, settings),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            start_new_session=True,
        )
    )
    try:
        process = await asyncio.shield(launch)
    except asyncio.CancelledError:
        process = await launch
        await stop_group(process, settings.terminate_grace)
        raise

    try:
        await asyncio.wait_for(process.wait(), timeout)
    except TimeoutError:
        await stop_group(process, settings.terminate_grace)
        return StageResult(
            "timed_out", {}, {"code": "STAGE_TIMEOUT", "message": "解析阶段超时"}, process.pid
        )
    except asyncio.CancelledError:
        await stop_group(process, settings.terminate_grace)
        raise

    # A stage may exit while tools are still in its process group.
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    if process.returncode in {-signal.SIGXCPU, -signal.SIGXFSZ}:
        code, message = (
            ("STAGE_CPU_LIMIT", "解析阶段超过 CPU 时间上限")
            if process.returncode == -signal.SIGXCPU
            else ("RESULT_LIMIT", "解析阶段超过单文件大小上限")
        )
        return StageResult("failed", {}, {"code": code, "message": message}, process.pid)

    report = job_dir / f"{stage}.json"
    if process.returncode == 0 and report.is_file() and report.stat().st_size <= MAX_REPORT_BYTES:
        try:
            payload = json.loads(report.read_bytes())
        except (OSError, ValueError):
            payload = {}
        if "error" in payload:
            return StageResult("failed", {}, payload["error"], process.pid)
        if "modules" in payload:
            return StageResult("ok", payload["modules"], None, process.pid)
    return StageResult(
        "failed", {}, {"code": "STAGE_PROCESS_FAILED", "message": "解析进程未返回有效报告"}, process.pid
    )


async def analyze_job(
    job_dir: Path,
    profile: Profile,
    settings: StaticAnalysisSettings,
    *,
    include_file_tree: bool,
) -> dict:
    attempts = []
    base = await run_stage(
        job_dir, "full", profile, settings.full_timeout, settings, include_file_tree=include_file_tree
    )
    attempts.append(base.attempt("full"))
    if base.error and base.error["code"] in {"STAGE_TIMEOUT", "STAGE_PROCESS_FAILED"}:
        icon_dir = job_dir / "artifacts" / "icon"
        if icon_dir.is_dir():
            shutil.rmtree(icon_dir)
        base = await run_stage(
            job_dir, "aapt2", profile, settings.fallback_timeout, settings,
            include_file_tree=include_file_tree,
        )
        attempts.append(base.attempt("aapt2"))
    if base.error:
        raise AnalysisError(base.error["code"], base.error["message"])

    modules = base.modules
    if profile != Profile.BASIC:
        certificate = await run_stage(
            job_dir, "certificate", profile, settings.certificate_timeout, settings
        )
        attempts.append(certificate.attempt("certificate"))
        if certificate.error:
            modules["certificate"] = {"status": certificate.state, "error": certificate.error}
        else:
            modules.update(certificate.modules)
    if profile == Profile.DEEP:
        deep = await run_stage(job_dir, "deep", profile, settings.deep_timeout, settings)
        attempts.append(deep.attempt("deep"))
        if deep.error:
            modules["decompile"] = {"status": deep.state, "error": deep.error}
            modules["reverse"] = {"status": "unavailable"}
        else:
            modules.update(deep.modules)
    return {"modules": modules, "attempts": attempts}
