"""独立的 HTTP 入口，接收 APK 字节并返回解析结果。"""

import asyncio
import base64
import errno
import hashlib
import hmac
import mimetypes
import os
import shutil
import tempfile
from collections.abc import Awaitable, Callable
from enum import StrEnum
from pathlib import Path

import anyio
from fastapi import FastAPI, Query, Request
from starlette.requests import ClientDisconnect
from starlette.responses import FileResponse, JSONResponse

from apk_lens_service.utils import find_readelf
from apk_lens_service.artifacts import AnalysisError, checked_files, encode_report, write_bundle
from apk_lens_service.config import MAX_INLINE_ICON_BYTES, MIB, Profile, StaticAnalysisSettings
from apk_lens_service.http_requests import apk_chunks, error, while_connected
from apk_lens_service.supervisor import analyze_job
from apk_lens_service.worker_proxy import SocketWorkers, WorkerJobResponse


class OutputFormat(StrEnum):
    JSON = "json"
    ZIP = "zip"


class Capacity:
    """在同一个 HTTP 事件循环中保留总槽位和深度分析槽位。"""

    def __init__(self, settings: StaticAnalysisSettings):
        self.settings = settings
        self.active = 0
        self.deep = 0

    def acquire(self, profile: Profile) -> bool:
        if self.active >= self.settings.max_jobs:
            return False
        if profile == Profile.DEEP and self.deep >= self.settings.max_deep_jobs:
            return False
        self.active += 1
        if profile == Profile.DEEP:
            self.deep += 1
        return True

    def release(self, profile: Profile) -> None:
        self.active -= 1
        if profile == Profile.DEEP:
            self.deep -= 1


class JobFileResponse(FileResponse):
    def __init__(self, *args, cleanup: Callable[[], Awaitable[None]], **kwargs):
        super().__init__(*args, **kwargs)
        self.cleanup = cleanup

    async def __call__(self, scope, receive, send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            await self.cleanup()


def authorize(request: Request, settings: StaticAnalysisSettings) -> None:
    token = settings.token.get_secret_value()
    if not token:
        return
    scheme, _, provided = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(provided.encode(), token.encode()):
        raise error(401, "UNAUTHORIZED", "需要服务凭据", headers={"WWW-Authenticate": "Bearer"})


async def upload(request: Request, path: Path, filename: str, settings: StaticAnalysisSettings) -> dict:
    sha256 = hashlib.sha256()
    received = 0
    try:
        async with asyncio.timeout(settings.upload_timeout), await anyio.open_file(path, "wb") as target:
            async for chunk in apk_chunks(
                request, byte_limit=settings.max_apk_mib * MIB, timeout=settings.upload_timeout
            ):
                received += len(chunk)
                await target.write(chunk)
                sha256.update(chunk)
    except TimeoutError as exc:
        raise error(408, "UPLOAD_TIMEOUT", "接收 APK 超时") from exc
    return {"filename": filename, "file_size": received, "sha256": sha256.hexdigest()}


def materialize(
    job_dir: Path, report: dict, output: OutputFormat, settings: StaticAnalysisSettings
) -> Path:
    artifacts = job_dir / "artifacts"
    roots = [artifacts / "icon"]
    basic = report["modules"]["basic"]["data"]
    icon_path = basic["icon_path"]
    if icon_path:
        icon = artifacts / icon_path
        files = checked_files([icon.parent], byte_limit=settings.max_result_mib * MIB, file_limit=4)
        if icon not in list(files):
            raise AnalysisError("INVALID_ARTIFACT", "图标产物不完整")
        icon_info = {
            "path": icon_path,
            "content_type": mimetypes.guess_type(icon.name)[0] or "application/octet-stream",
            "size": icon.stat().st_size,
        }
        if output == OutputFormat.JSON:
            if icon_info["size"] <= MAX_INLINE_ICON_BYTES:
                icon_info["base64"] = base64.b64encode(icon.read_bytes()).decode("ascii")
            else:
                icon_info["delivery"] = "zip"
        report["icon"] = icon_info

    decompile = report["modules"].get("decompile", {})
    if "data" in decompile:
        roots.extend([artifacts / "jadx", artifacts / "reverse"])
        report["artifact_delivery"] = "zip" if output == OutputFormat.ZIP else "summary"
    data = encode_report(report)
    if len(data) > settings.max_result_mib * MIB:
        raise AnalysisError("RESULT_LIMIT", "解析报告超过大小上限")
    if output == OutputFormat.ZIP:
        bundle = write_bundle(
            job_dir, data, roots,
            byte_limit=settings.max_result_mib * MIB, file_limit=settings.max_files,
        )
        if bundle.stat().st_size > settings.max_result_mib * MIB:
            raise AnalysisError("RESULT_LIMIT", "解析压缩包超过大小上限")
        return bundle
    report_path = job_dir / "result.json"
    report_path.write_bytes(data)
    return report_path


def create_app(settings: StaticAnalysisSettings | None = None) -> FastAPI:
    settings = settings or StaticAnalysisSettings()
    capacity = Capacity(settings)
    workers = SocketWorkers(settings.worker_sockets) if settings.worker_sockets else None
    app = FastAPI(title="APK Lens Service", version="1.0")

    @app.get("/healthz")
    async def health():
        return {"status": "ok"}

    @app.get("/readyz")
    async def ready():
        details = {
            "jobs": {"active": capacity.active, "limit": settings.max_jobs},
            "deep_jobs": {"active": capacity.deep, "limit": settings.max_deep_jobs},
        }
        if workers is not None:
            live, tools = await workers.status()
            details["workers"] = {"ready": live, "configured": len(settings.worker_sockets)}
            ok = live > 0
        else:
            ok = settings.work_dir.is_dir() and os.access(settings.work_dir, os.W_OK | os.X_OK)
            tools = {
                "aapt2": bool(shutil.which(settings.aapt2_bin)),
                "jadx": bool(shutil.which(settings.jadx_bin)),
                "java": (
                    os.access(Path(settings.java_home) / "bin/java", os.X_OK)
                    if settings.java_home else bool(shutil.which("java"))
                ),
                "readelf": bool(find_readelf()),
            }
        details.update(ready=ok, tools=tools)
        return JSONResponse(details, status_code=200 if ok else 503)

    @app.post(
        "/v1/analyze",
        response_class=FileResponse,
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {
                    "application/vnd.android.package-archive": {
                        "schema": {"type": "string", "format": "binary"}
                    }
                },
            }
        },
        responses={200: {"content": {"application/json": {}, "application/zip": {}}}},
    )
    async def analyze(
        request: Request,
        profile: Profile = Profile.STANDARD,
        output: OutputFormat | None = None,
        filename: str = Query("sample.apk", min_length=1, max_length=240),
        include_file_tree: bool = Query(False, description="在基础信息中返回 APK 内的完整条目路径"),
    ):
        authorize(request, settings)
        name = Path(filename.replace("\\", "/")).name
        if not name.lower().endswith(".apk"):
            raise error(422, "INVALID_APK_FILENAME", "文件名须以 .apk 结尾")
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type not in {"application/vnd.android.package-archive", "application/octet-stream"}:
            raise error(415, "UNSUPPORTED_CONTENT_TYPE", "请求正文须为 APK 文件字节")
        if length := request.headers.get("content-length"):
            if not length.isascii() or not length.isdigit() or len(length) > 16:
                raise error(400, "INVALID_CONTENT_LENGTH", "Content-Length 无效")
            if int(length) > settings.max_apk_mib * MIB:
                raise error(413, "APK_SIZE_LIMIT", "上传的 APK 超过大小上限")
        if profile == Profile.DEEP and settings.max_deep_jobs == 0:
            raise error(503, "DEEP_DISABLED", "当前实例关闭深度分析")
        if not capacity.acquire(profile):
            raise error(503, "CAPACITY_EXHAUSTED", "解析服务繁忙", headers={"Retry-After": "5"})

        temporary = None
        response_owns_job = False

        async def cleanup():
            with anyio.CancelScope(shield=True):
                try:
                    if temporary is not None:
                        await anyio.to_thread.run_sync(temporary.cleanup)
                finally:
                    capacity.release(profile)

        try:
            if workers is not None:
                params = {
                    "profile": profile.value, "filename": name,
                    "include_file_tree": str(include_file_tree).lower(),
                }
                if output is not None:
                    params["output"] = output.value
                response = WorkerJobResponse(
                    workers, request, settings, profile, params, content_type, cleanup=cleanup
                )
                response_owns_job = True
                return response

            temporary = tempfile.TemporaryDirectory(prefix="apk-lens-", dir=settings.work_dir)
            job_dir = Path(temporary.name).resolve()
            (job_dir / "tmp").mkdir()
            (job_dir / "artifacts").mkdir()
            metadata = await upload(request, job_dir / "sample.apk", name, settings)
            report = await while_connected(
                request, analyze_job(job_dir, profile, settings, include_file_tree=include_file_tree)
            )
            modules = report["modules"]
            metadata["md5"] = modules["basic"]["data"]["md5"]
            report.update(
                schema_version=1,
                input=metadata,
                profile=profile.value,
                status="ok" if all(module["status"] == "ok" for module in modules.values()) else "partial",
            )
            output = output or (OutputFormat.ZIP if profile == Profile.DEEP else OutputFormat.JSON)
            result_path = await anyio.to_thread.run_sync(materialize, job_dir, report, output, settings)
            response = JobFileResponse(
                result_path,
                media_type="application/zip" if output == OutputFormat.ZIP else "application/json",
                filename="apk-lens-analysis.zip" if output == OutputFormat.ZIP else None,
                headers={"Cache-Control": "no-store"},
                cleanup=cleanup,
            )
            response_owns_job = True
            return response
        except ClientDisconnect as exc:
            raise error(499, "CLIENT_DISCONNECTED", "调用方已断开") from exc
        except AnalysisError as exc:
            status = {
                "APK_EXPANSION_LIMIT": 413,
                "RESULT_LIMIT": 413,
                "INVALID_APK": 422,
                "APK_IDENTITY_UNRESOLVED": 422,
                "STAGE_TIMEOUT": 504,
                "STAGE_CPU_LIMIT": 503,
                "STAGE_MEMORY_LIMIT": 503,
                "WORKSPACE_LIMIT": 507,
            }.get(exc.code, 502)
            raise error(status, exc.code, str(exc)) from exc
        except OSError as exc:
            if exc.errno not in {errno.ENOSPC, errno.EDQUOT}:
                raise
            raise error(507, "WORKSPACE_LIMIT", "解析临时空间不足") from exc
        finally:
            if not response_owns_job:
                await cleanup()

    return app
