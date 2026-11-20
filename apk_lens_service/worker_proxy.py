"""Relay a job over a private Unix socket while keeping payloads off the API filesystem."""

import asyncio
import json
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager, suppress
from pathlib import Path

import anyio
import httpx
from fastapi import Request
from starlette.requests import ClientDisconnect
from starlette.responses import Response, StreamingResponse

from apk_lens_service.config import MIB, Profile, StaticAnalysisSettings
from apk_lens_service.http_requests import apk_chunks, error, while_connected


def worker_client(path: Path) -> httpx.AsyncClient:
    transport = httpx.AsyncHTTPTransport(
        uds=str(path), limits=httpx.Limits(max_connections=1, max_keepalive_connections=0)
    )
    return httpx.AsyncClient(
        base_url="http://apk-lens-worker", transport=transport, trust_env=False,
        headers={"Accept-Encoding": "identity"},
    )


async def probe(client: httpx.AsyncClient) -> dict | None:
    try:
        async with asyncio.timeout(1), client.stream("GET", "/readyz") as response:
            if response.status_code != 200:
                return None
            data = bytearray()
            async for chunk in response.aiter_raw(chunk_size=4096):
                if len(data) + len(chunk) > 4096:
                    return None
                data.extend(chunk)
        report = json.loads(data)
    except (ValueError, RecursionError, TimeoutError, httpx.HTTPError):
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

    @asynccontextmanager
    async def acquire(self):
        for path in self.paths:
            if path in self.reserved:
                continue
            self.reserved.add(path)
            try:
                async with worker_client(path) as client:
                    report = await probe(client)
                    if report and report["jobs"].get("active") == 0:
                        yield client
                        return
            finally:
                self.reserved.remove(path)
        yield None


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
            async with self.workers.acquire() as client:
                if client is None:
                    raise error(503, "WORKER_UNAVAILABLE", "暂无可用解析实例", headers={"Retry-After": "5"})
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

        read_timeout = settings.full_timeout + settings.fallback_timeout + 30
        if self.profile != Profile.BASIC:
            read_timeout += settings.certificate_timeout
        if self.profile == Profile.DEEP:
            read_timeout += settings.deep_timeout
        request = client.build_request(
            "POST", "/v1/analyze", params=self.params,
            headers={"Content-Type": self.content_type}, content=body(),
            timeout=httpx.Timeout(read_timeout, connect=1, write=settings.upload_timeout),
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
        if size > self.settings.max_result_mib * MIB:
            raise error(413, "RESULT_LIMIT", "解析产物超过大小上限")

        async def bounded_body():
            sent = 0
            async for chunk in upstream.aiter_raw():
                sent += len(chunk)
                if sent > size:
                    raise ValueError("解析实例响应超过声明长度")
                yield chunk
            if sent != size:
                raise ValueError("解析实例响应长度不完整")

        headers = {
            "Cache-Control": "no-store", "Content-Length": str(size), "X-Content-Type-Options": "nosniff"
        }
        if content_type == "application/zip":
            headers["Content-Disposition"] = 'attachment; filename="apk-lens-analysis.zip"'
        if upstream.status_code == 503:
            headers["Retry-After"] = "5"
        response = StreamingResponse(
            bounded_body(), status_code=upstream.status_code, media_type=content_type, headers=headers
        )
        with suppress(ClientDisconnect):
            await response(scope, receive, send)
