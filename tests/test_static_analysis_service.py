import asyncio
import io
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from zipfile import ZipFile

import httpx
import pytest

from apk_lens_service.api import create_app
from apk_lens_service.config import StaticAnalysisSettings


APK_HEADERS = {"Content-Type": "application/vnd.android.package-archive"}


def write_fallback_tool(tmp_path: Path, pause: str) -> Path:
    tool = tmp_path / "aapt2"
    tool.write_text(
        f"#!{sys.executable}\n"
        "import os, sys, time\n"
        "from pathlib import Path\n"
        "if sys.argv[1:3] != ['dump', 'badging']:\n"
        "    raise SystemExit(1)\n"
        f"{pause}\n"
        "print(\"package: name='test.static.fixture' versionCode='1' versionName='1.0'\")\n"
        "print(\"application-label:'Fixture'\")\n"
        "print(\"launchable-activity: name='test.static.fixture.Main'\")\n",
        encoding="utf-8",
    )
    tool.chmod(0o755)
    return tool


def archive_with_unreadable_manifest() -> bytes:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"invalid binary XML")
        archive.writestr("assets/fixture.txt", b"fixture")
    return buffer.getvalue()


def test_concurrent_apks_run_in_different_processes_with_capacity_limit(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    tool = write_fallback_tool(tmp_path, "time.sleep(0.4)")
    app = create_app(StaticAnalysisSettings(work_dir=scratch, aapt2_bin=str(tool)))
    payload = archive_with_unreadable_manifest()

    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://static.test"
        ) as client:
            endpoint = "/v1/analyze?profile=basic"
            first = asyncio.create_task(client.post(endpoint, content=payload, headers=APK_HEADERS))
            second = asyncio.create_task(client.post(endpoint, content=payload, headers=APK_HEADERS))
            async with asyncio.timeout(4):
                while (await client.get("/readyz")).json()["jobs"]["active"] < 2:
                    await asyncio.sleep(0.015)

            excess = await client.post(endpoint, content=payload, headers=APK_HEADERS)
            assert excess.status_code == 503
            assert excess.json()["detail"]["code"] == "CAPACITY_EXHAUSTED"

            replies = await asyncio.gather(first, second)
            for reply in replies:
                assert reply.status_code == 200, reply.text
                modules = reply.json()["modules"]
                assert modules["basic"]["data"]["package_name"] == "test.static.fixture"
                assert modules["basic"]["status"] == "partial"
                assert modules["basic"]["data"]["permissions"] == []
            assert len({reply.json()["attempts"][0]["pid"] for reply in replies}) == 2
            assert (await client.get("/readyz")).json()["jobs"]["active"] == 0
            assert list(scratch.iterdir()) == []

    asyncio.run(exercise())


def test_unix_gateway_relays_and_cleans_worker_jobs(tmp_path):
    scratch = tmp_path / "worker"
    scratch.mkdir()
    tool = write_fallback_tool(
        tmp_path, "(Path(os.environ['TMPDIR']) / 'parsing').touch()\ntime.sleep(0.7)"
    )
    env = {name: value for name, value in os.environ.items() if not name.startswith("APK_LENS_SERVICE_")}
    with tempfile.TemporaryDirectory(prefix="lens-uds-", dir="/tmp") as sockets:
        path = Path(sockets) / "worker.sock"
        env.update(
            APK_LENS_SERVICE_LISTEN_SOCKET=str(path),
            APK_LENS_SERVICE_WORK_DIR=str(scratch),
            APK_LENS_SERVICE_MAX_JOBS="1",
            APK_LENS_SERVICE_AAPT2_BIN=str(tool),
        )
        gateway_scratch = tmp_path / "gateway"
        app = create_app(
            StaticAnalysisSettings(
                worker_sockets=(Path(sockets) / "missing.sock", path),
                work_dir=gateway_scratch, max_apk_mib=1, token="test-gateway-token",
            )
        )
        headers = {**APK_HEADERS, "Authorization": "Bearer test-gateway-token"}
        payload = archive_with_unreadable_manifest()

        async def exercise():
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://static.test"
            ) as client:
                async with asyncio.timeout(5):
                    while (await client.get("/readyz")).status_code != 200:
                        await asyncio.sleep(0.05)
                assert (await client.get("/readyz")).json()["workers"] == {"ready": 1, "configured": 2}
                endpoint = (
                    "/v1/analyze?profile=basic&output=zip&include_file_tree=true&filename=fixture.apk"
                )
                assert (await client.post(endpoint, headers=APK_HEADERS, content=payload)).status_code == 401
                result = await client.post(endpoint, headers=headers, content=payload)
                assert result.status_code == 200, result.text
                with ZipFile(io.BytesIO(result.content)) as bundle:
                    report = json.loads(bundle.read("result.json"))
                assert report["input"]["filename"] == "fixture.apk"
                assert report["modules"]["basic"]["data"]["file_tree"] == [
                    "AndroidManifest.xml", "assets/fixture.txt",
                ]
                assert not gateway_scratch.exists()

                async def large_upload():
                    for _ in range(3):
                        yield b"x" * (512 * 1024)

                result = await client.post(endpoint, headers=headers, content=large_upload())
                assert result.status_code == 413
                assert result.json()["detail"]["code"] == "APK_SIZE_LIMIT"
                async with asyncio.timeout(4):
                    while list(scratch.iterdir()):
                        await asyncio.sleep(0.02)

                pending = asyncio.create_task(client.post(endpoint, headers=headers, content=payload))
                async with asyncio.timeout(5):
                    while not any(scratch.glob("*/tmp/parsing")):
                        await asyncio.sleep(0.02)
                    pending.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await pending
                    while list(scratch.iterdir()):
                        await asyncio.sleep(0.02)
                assert (await client.get("/readyz")).json()["jobs"]["active"] == 0

        with (tmp_path / "worker.log").open("w+") as log:
            worker = subprocess.Popen(
                [sys.executable, "-m", "apk_lens_service"], env=env, stdout=log, stderr=log
            )
            try:
                asyncio.run(exercise())
            except Exception:
                log.seek(0)
                print(log.read())
                raise
            finally:
                worker.terminate()
                worker.wait(timeout=12)


@pytest.mark.parametrize("output", ["json", "zip"])
def test_file_tree_is_only_reported_on_request(tmp_path, output):
    tool = write_fallback_tool(tmp_path, "pass")
    app = create_app(StaticAnalysisSettings(work_dir=tmp_path, aapt2_bin=str(tool)))
    payload = archive_with_unreadable_manifest()

    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://static.test"
        ) as client:
            endpoint = f"/v1/analyze?profile=basic&output={output}"
            for flag in ("", "&include_file_tree=false", "&include_file_tree=true"):
                response = await client.post(endpoint + flag, headers=APK_HEADERS, content=payload)
                assert response.status_code == 200, response.text
                if output == "zip":
                    with ZipFile(io.BytesIO(response.content)) as archive:
                        report = json.loads(archive.read("result.json"))
                else:
                    report = response.json()

                basic = report["modules"]["basic"]["data"]
                assert basic["file_count"] == 2
                if flag.endswith("=true"):
                    assert basic["file_tree"] == ["AndroidManifest.xml", "assets/fixture.txt"]
                else:
                    assert "file_tree" not in basic

    asyncio.run(exercise())


def test_timeout_restarts_with_aapt2_in_a_new_process(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    tool = write_fallback_tool(
        tmp_path,
        "marker = Path(os.environ['TMPDIR']) / 'started'\n"
        "if not marker.exists():\n"
        "    marker.touch()\n"
        "    time.sleep(25)",
    )
    app = create_app(
        StaticAnalysisSettings(
            work_dir=scratch, aapt2_bin=str(tool),
            full_timeout=2.5, fallback_timeout=5, terminate_grace=0.2,
        )
    )

    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://static.test"
        ) as client:
            before = time.monotonic()
            response = await client.post(
                "/v1/analyze?profile=basic&include_file_tree=true",
                headers=APK_HEADERS, content=archive_with_unreadable_manifest(),
            )
            assert time.monotonic() - before < 12
            assert response.status_code == 200, response.text
            report = response.json()
            assert report["status"] == "partial"
            basic = report["modules"]["basic"]["data"]
            assert basic["package_name"] == "test.static.fixture"
            assert basic["manifest_components_status"] == "unavailable"
            assert basic["file_tree"] == ["AndroidManifest.xml", "assets/fixture.txt"]
            attempts = report["attempts"]
            assert [(item["stage"], item["state"]) for item in attempts] == [
                ("full", "timed_out"), ("aapt2", "ok"),
            ]
            assert attempts[0]["pid"] != attempts[1]["pid"]
            assert list(scratch.iterdir()) == []

    asyncio.run(exercise())


def test_rejects_unauthorized_over_limit_and_invalid_bodies(tmp_path):
    app = create_app(StaticAnalysisSettings(work_dir=tmp_path, max_apk_mib=1, token="fixture-token"))

    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://static.test"
        ) as client:
            endpoint = "/v1/analyze"
            assert (await client.post(endpoint, content=b"x", headers=APK_HEADERS)).status_code == 401
            headers = {**APK_HEADERS, "Authorization": "Bearer fixture-token"}
            assert (
                await client.post(endpoint, content=b"x" * (1024 * 1024 + 1), headers=headers)
            ).status_code == 413

            async def chunked_body():
                for _ in range(3):
                    yield b"x" * (512 * 1024)

            streamed = await client.post(endpoint, content=chunked_body(), headers=headers)
            assert streamed.status_code == 413
            bad = await client.post(endpoint, content=b"not an APK", headers=headers)
            assert bad.status_code == 422
            assert bad.json()["detail"]["code"] == "INVALID_APK"
            assert list(tmp_path.iterdir()) == []

    asyncio.run(exercise())


def test_disconnect_during_parse_cleans_request_and_releases_capacity(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    tool = write_fallback_tool(tmp_path, "(Path(os.environ['TMPDIR']) / 'parsing').touch()\ntime.sleep(25)")
    app = create_app(StaticAnalysisSettings(work_dir=scratch, aapt2_bin=str(tool)))

    async def exercise():
        payload = archive_with_unreadable_manifest()
        incoming = asyncio.Queue()
        outgoing = []
        incoming.put_nowait({"type": "http.request", "body": payload, "more_body": False})

        async def send(message):
            outgoing.append(message)

        request_task = asyncio.create_task(
            app(
                {
                    "type": "http", "http_version": "1.1", "method": "POST",
                    "path": "/v1/analyze", "query_string": b"profile=basic",
                    "headers": [(b"content-type", b"application/octet-stream")],
                    "scheme": "http",
                },
                incoming.get,
                send,
            )
        )
        async with asyncio.timeout(6):
            while not any(scratch.glob("*/tmp/parsing")):
                await asyncio.sleep(0.015)
            incoming.put_nowait({"type": "http.disconnect"})
            await request_task
        assert outgoing[0]["status"] == 499
        assert list(scratch.iterdir()) == []

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://static.test"
        ) as client:
            assert (await client.get("/readyz")).json()["jobs"]["active"] == 0

    asyncio.run(exercise())
