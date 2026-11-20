import asyncio
from collections.abc import AsyncIterator, Coroutine
from typing import Any

from fastapi import HTTPException, Request
from starlette.requests import ClientDisconnect


def error(status: int, code: str, message: str, *, headers=None) -> HTTPException:
    return HTTPException(status, detail={"code": code, "message": message}, headers=headers)


async def apk_chunks(request: Request, *, byte_limit: int, timeout: float) -> AsyncIterator[bytes]:
    deadline = asyncio.get_running_loop().time() + timeout
    stream = request.stream()
    received = 0
    while True:
        try:
            async with asyncio.timeout_at(deadline):
                chunk = await anext(stream)
        except StopAsyncIteration:
            break
        except TimeoutError as exc:
            raise error(408, "UPLOAD_TIMEOUT", "接收 APK 超时") from exc
        if chunk:
            received += len(chunk)
            if received > byte_limit:
                raise error(413, "APK_SIZE_LIMIT", "上传的 APK 超过大小上限")
            yield chunk
    if not received:
        raise error(422, "INVALID_APK", "APK 内容为空")


async def while_connected[T](
    request: Request, operation: Coroutine[Any, Any, T], *, uploaded: asyncio.Event | None = None
) -> T:
    async def wait_for_disconnect():
        if uploaded is not None:
            await uploaded.wait()
        while (await request.receive())["type"] != "http.disconnect":
            pass

    work = asyncio.create_task(operation)
    disconnected = asyncio.create_task(wait_for_disconnect())
    try:
        done, _ = await asyncio.wait({work, disconnected}, return_when=asyncio.FIRST_COMPLETED)
        if work in done:
            return work.result()
        raise ClientDisconnect()
    finally:
        for task in (work, disconnected):
            if not task.done():
                task.cancel()
        await asyncio.gather(work, disconnected, return_exceptions=True)
