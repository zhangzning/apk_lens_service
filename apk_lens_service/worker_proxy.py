"""Relay requests and replay spooled jobs over private Unix sockets."""

import asyncio
import json
from collections.abc import AsyncIterable, AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager, suppress
from pathlib import Path

import anyio
import httpx
from fastapi import Request
from starlette.requests import ClientDisconnect
from starlette.responses import Response, StreamingResponse

from apk_lens_service.artifacts import AnalysisError
from apk_lens_service.config import MIB, Profile, StaticAnalysisSettings
from apk_lens_service.http_requests import apk_chunks, error, while_connected
from apk_lens_service.jobs import Job, RetryableJobError
from apk_lens_service.telemetry import (
    REQUEST_ID_HEADER, WORKER_ERROR_HEADER, WORKER_OUTCOME_HEADER, known_error,
)


def worker_client(path: Path) -> httpx.AsyncClient:
    transport = httpx.AsyncHTTPTransport(
        uds=str(path), limits=httpx.Limits(max_connections=1, max_keepalive_connections=0)
    )
    return httpx.AsyncClient(
        base_url="http://apk-lens-worker", transport=transport, trust_env=False,
        headers={"Accept-Encoding": "identity"},
    )


async def read_worker(client: httpx.AsyncClient, path: str, limit: int) -> bytes | None:
    try:
        async with asyncio.timeout(1), client.stream("GET", path) as response:
            if response.status_code != 200:
                return None
            data = bytearray()
            async for chunk in response.aiter_raw(chunk_size=4096):
                if len(data) + len(chunk) > limit:
                    return None
                data.extend(chunk)
        return bytes(data)
    except (TimeoutError, httpx.HTTPError):
        return None


async def probe(client: httpx.AsyncClient) -> dict | None:
    data = await read_worker(client, "/readyz", 4096)
    if data is None:
        return None
    try:
        report = json.loads(data)
    except (ValueError, RecursionError):
        return None
    if (
        isinstance(report, dict)
        and report.get("ready") is True
        and isinstance(report.get("jobs"), dict)
        and isinstance(report.get("tools"), dict)
    ):
        return report
    return None


class SocketWorkers:
    def __init__(self, paths: tuple[Path, ...]):
        self.paths = paths
        self.reserved: set[Path] = set()

    async def status(self) -> tuple[int, dict[str, bool]]:
        async def check(path: Path) -> dict | None:
            async with worker_client(path) as client:
                return await probe(client)

        reports = [report for report in await asyncio.gather(*(check(path) for path in self.paths)) if report]
        tools = {
            tool: bool(reports) and all(report["tools"].get(tool) is True for report in reports)
            for tool in ("aapt2", "jadx", "java", "readelf")
        }
        return len(reports), tools

    async def scrape_metrics(self) -> dict[str, bytes | None]:
        async def scrape(path: Path) -> bytes | None:
            async with worker_client(path) as client:
                return await read_worker(client, "/metrics", 256 * 1024)

        results = await asyncio.gather(*(scrape(path) for path in self.paths))
        return {f"worker-{i}": contents for i, contents in enumerate(results, start=1)}

    @asynccontextmanager
    async def acquire(self, previous: Path | None = None):
        for path in sorted(self.paths, key=lambda path: path == previous):
            if path in self.reserved:
                continue
            self.reserved.add(path)
            try:
                async with worker_client(path) as client:
                    report = await probe(client)
                    if report and report["jobs"].get("active") == 0:
                        yield path, client
                        return
            finally:
                self.reserved.remove(path)
        yield None


def worker_request(
    client: httpx.AsyncClient, params: dict[str, str], body: AsyncIterable[bytes],
    content_type: str, request_id: str, profile: Profile, settings: StaticAnalysisSettings,
) -> httpx.Request:
    read_timeout = settings.full_timeout + settings.fallback_timeout + 30
    if profile != Profile.BASIC:
        read_timeout += settings.certificate_timeout
    if profile == Profile.DEEP:
        read_timeout += settings.deep_timeout
    return client.build_request(
        "POST", "/v1/analyze", params=params,
        headers={"Content-Type": content_type, REQUEST_ID_HEADER: request_id}, content=body,
        timeout=httpx.Timeout(read_timeout, connect=1, write=settings.upload_timeout),
    )


def worker_response_size(upstream: httpx.Response, settings: StaticAnalysisSettings) -> tuple[str, int]:
    content_type = upstream.headers.get("content-type", "").partition(";")[0].strip()
    length = upstream.headers.get("content-length", "")
    if (
        not (upstream.status_code == 200 or 400 <= upstream.status_code <= 599)
        or content_type not in {"application/json", "application/zip"}
        or upstream.headers.get("content-encoding", "identity") != "identity"
        or not length.isascii() or not length.isdecimal() or len(length) > 16
    ):
        raise error(502, "INVALID_WORKER_RESPONSE", "解析实例返回了无效响应")
    size = int(length)
    if size > settings.max_result_mib * MIB:
        raise error(413, "RESULT_LIMIT", "解析产物超过大小上限")
    return content_type, size


async def worker_body(upstream: httpx.Response, size: int) -> AsyncIterator[bytes]:
    sent = 0
    async for chunk in upstream.aiter_raw():
        sent += len(chunk)
        if sent > size:
            raise httpx.RemoteProtocolError("解析实例响应超过声明长度")
        yield chunk
    if sent != size:
        raise httpx.RemoteProtocolError("解析实例响应长度不完整")


async def fetch_job_result(workers: SocketWorkers, job: Job, settings: StaticAnalysisSettings) -> Path:
    async with workers.acquire(job.previous_worker) as lease:
        if lease is None:
            raise RetryableJobError("WORKER_UNAVAILABLE", "暂无可用解析实例")
        job.previous_worker, client = lease

        async def body():
            async with await anyio.open_file(job.sample, "rb") as sample:
                while chunk := await sample.read(128 * 1024):
                    yield chunk

        request = worker_request(
            client, job.options.worker_params(), body(), "application/vnd.android.package-archive",
            job.request_id, job.options.profile, settings,
        )
        result = job.directory / f"result.{job.options.output.value}"
        partial = job.directory / "result.part"
        try:
            upstream = await client.send(request, stream=True)
            try:
                if upstream.status_code >= 400:
                    code = known_error(upstream.headers.get(WORKER_ERROR_HEADER)) or "INVALID_WORKER_RESPONSE"
                    if code in {"CAPACITY_EXHAUSTED", "WORKER_UNAVAILABLE"}:
                        raise RetryableJobError(code, "解析实例暂不可用")
                    raise AnalysisError(code, "解析实例未生成结果")
                content_type, size = worker_response_size(upstream, settings)
                if not size or content_type != f"application/{job.options.output.value}":
                    raise AnalysisError("INVALID_WORKER_RESPONSE", "解析结果格式与请求不符")
                async with await anyio.open_file(partial, "wb") as target:
                    async for chunk in worker_body(upstream, size):
                        await target.write(chunk)
                partial.replace(result)
                return result
            finally:
                with anyio.CancelScope(shield=True):
                    await upstream.aclose()
        except httpx.ConnectTimeout as exc:
            raise RetryableJobError("WORKER_CONNECTION_FAILED", "连接解析实例超时") from exc
        except httpx.TimeoutException as exc:
            raise AnalysisError("WORKER_TIMEOUT", "解析实例响应超时") from exc
        except httpx.RequestError as exc:
            raise RetryableJobError("WORKER_CONNECTION_FAILED", "解析实例连接中断") from exc
        finally:
            partial.unlink(missing_ok=True)


class WorkerJobResponse(Response):
    def __init__(
        self, workers: SocketWorkers, request: Request, settings: StaticAnalysisSettings,
        profile: Profile, params: dict[str, str], content_type: str,
        *, cleanup: Callable[[], Awaitable[None]],
    ):
        super().__init__()
        self.workers = workers
        self.request = request
        self.settings = settings
        self.profile = profile
        self.params = params
        self.content_type = content_type
        self.cleanup = cleanup

    async def __call__(self, scope, receive, send) -> None:
        try:
            async with self.workers.acquire() as lease:
                if lease is None:
                    raise error(503, "WORKER_UNAVAILABLE", "暂无可用解析实例", headers={"Retry-After": "5"})
                _, client = lease
                upstream = await self.analyze(client)
                try:
                    await self.deliver(upstream, scope, receive, send)
                finally:
                    with anyio.CancelScope(shield=True):
                        await upstream.aclose()
        finally:
            await self.cleanup()

    async def analyze(self, client: httpx.AsyncClient) -> httpx.Response:
        settings = self.settings
        uploaded = asyncio.Event()

        async def body():
            async for chunk in apk_chunks(
                self.request, byte_limit=settings.max_apk_mib * MIB, timeout=settings.upload_timeout
            ):
                yield chunk
            uploaded.set()

        request = worker_request(
            client, self.params, body(), self.content_type, self.request.state.request_id,
            self.profile, settings,
        )
        try:
            return await while_connected(self.request, client.send(request, stream=True), uploaded=uploaded)
        except ClientDisconnect as exc:
            raise error(499, "CLIENT_DISCONNECTED", "调用方已断开") from exc
        except httpx.TimeoutException as exc:
            raise error(504, "WORKER_TIMEOUT", "解析实例响应超时") from exc
        except httpx.RequestError as exc:
            raise error(502, "WORKER_CONNECTION_FAILED", "解析实例连接中断") from exc

    async def deliver(self, upstream: httpx.Response, scope, receive, send) -> None:
        content_type, size = worker_response_size(upstream, self.settings)
        if upstream.status_code >= 400:
            self.request.state.analysis_error = known_error(upstream.headers.get(WORKER_ERROR_HEADER))
        elif upstream.headers.get(WORKER_OUTCOME_HEADER) == "partial":
            self.request.state.analysis_outcome = "partial"

        headers = {
            "Cache-Control": "no-store", "Content-Length": str(size), "X-Content-Type-Options": "nosniff"
        }
        if content_type == "application/zip":
            headers["Content-Disposition"] = 'attachment; filename="apk-lens-analysis.zip"'
        if upstream.status_code == 503:
            headers["Retry-After"] = "5"
        response = StreamingResponse(
            worker_body(upstream, size), status_code=upstream.status_code, media_type=content_type, headers=headers
        )
        with suppress(ClientDisconnect):
            await response(scope, receive, send)
