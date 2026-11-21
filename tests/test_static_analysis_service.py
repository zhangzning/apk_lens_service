import asyncio
import io
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from zipfile import ZipFile

import httpx
import pytest
from prometheus_client.parser import text_string_to_metric_families
from pydantic import ValidationError

from apk_lens_service.api import create_app
from apk_lens_service.config import StaticAnalysisSettings
from apk_lens_service.telemetry import EVENT_LOGGER


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


def test_apk_entry_limit_keeps_output_limit_and_explicit_legacy_limit(monkeypatch):
    monkeypatch.delenv("APK_LENS_SERVICE_MAX_FILES", raising=False)
    monkeypatch.delenv("APK_LENS_SERVICE_MAX_APK_ENTRIES", raising=False)
    defaults = StaticAnalysisSettings()
    assert (defaults.max_apk_entries, defaults.max_files) == (200_000, 50_000)
    with pytest.raises(ValidationError, match="max_apk_entries"):
        StaticAnalysisSettings(max_apk_entries=200_001)

    monkeypatch.setenv("APK_LENS_SERVICE_MAX_FILES", "1000")
    assert StaticAnalysisSettings().max_apk_entries == 1000
    monkeypatch.setenv("APK_LENS_SERVICE_MAX_APK_ENTRIES", "2000")
    separate = StaticAnalysisSettings()
    assert (separate.max_apk_entries, separate.max_files) == (2000, 1000)


def test_apk_entry_limit_reaches_worker_process(tmp_path):
    tool = write_fallback_tool(tmp_path, "")
    app = create_app(StaticAnalysisSettings(
        work_dir=tmp_path, aapt2_bin=str(tool), max_apk_entries=2, max_files=1,
    ))
    at_limit = archive_with_unreadable_manifest()
    over_limit = io.BytesIO(at_limit)
    with ZipFile(over_limit, "a") as archive:
        archive.writestr("assets/extra.txt", b"")

    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://static.test"
        ) as client:
            endpoint = "/v1/analyze?profile=basic"
            admitted = await client.post(endpoint, content=at_limit, headers=APK_HEADERS)
            assert admitted.status_code == 200
            assert admitted.json()["modules"]["basic"]["data"]["file_count"] == 2
            rejected = await client.post(endpoint, content=over_limit.getvalue(), headers=APK_HEADERS)
            assert rejected.status_code == 413
            assert rejected.json()["detail"]["code"] == "APK_EXPANSION_LIMIT"

    asyncio.run(exercise())


def metric_values(text, name, **labels):
    return [
        sample.value
        for family in text_string_to_metric_families(text)
        for sample in family.samples
        if sample.name == name and all(sample.labels.get(key) == value for key, value in labels.items())
    ]


def test_request_ids_and_error_metrics_do_not_include_client_data(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger=EVENT_LOGGER)
    app = create_app(StaticAnalysisSettings(work_dir=tmp_path))

    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://static.test"
        ) as client:
            forged_id = "a" * 32
            result = await client.post(
                "/v1/analyze?filename=external-input.apk",
                headers={**APK_HEADERS, "X-Request-ID": forged_id}, content=b"",
            )
            assert result.status_code == 422
            request_id = result.headers["x-request-id"]
            assert re.fullmatch("[0-9a-f]{32}", request_id) and request_id != forged_id
            invalid = await client.post("/v1/analyze?profile=wrong", headers=APK_HEADERS)
            assert invalid.status_code == 422 and invalid.headers["x-request-id"] != request_id
            metrics = (await client.get("/metrics")).text
            assert metric_values(
                metrics, "apk_lens_requests_total",
                profile="standard", source="standalone", outcome="error", error_code="INVALID_APK",
            ) == [1]
            assert metric_values(metrics, "apk_lens_requests_total", error_code="REQUEST_VALIDATION_FAILED") == [1]
            assert request_id not in metrics and forged_id not in metrics
            return request_id

    request_id = asyncio.run(exercise())
    events = [json.loads(record.getMessage()) for record in caplog.records if record.name == EVENT_LOGGER]
    assert len(events) == 2
    first = events[0]
    assert first["event"] == "request_finished" and first["request_id"] == request_id
    assert first["error_code"] == "INVALID_APK" and first["duration_ms"] >= 0
    assert "external-input.apk" not in caplog.text


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


def test_async_jobs_reuse_options_and_expire(tmp_path, monkeypatch):
    import apk_lens_service.api as api_module

    scratch = tmp_path / "scratch"
    scratch.mkdir()
    jobs_dir = tmp_path / "jobs"
    tool = write_fallback_tool(tmp_path, "pass")
    settings = StaticAnalysisSettings(
        work_dir=scratch, jobs_dir=jobs_dir, aapt2_bin=str(tool), token="job-token",
        max_jobs=1, job_ttl_seconds=1.0, max_apk_mib=2, max_result_mib=2, jobs_storage_mib=8,
    )
    original = api_module.analyze_job
    headers = {**APK_HEADERS, "Authorization": "Bearer job-token"}
    payload = archive_with_unreadable_manifest()

    async def exercise():
        entered = asyncio.Event()
        unblock = asyncio.Event()

        async def analyze(*args, **kwargs):
            entered.set()
            await unblock.wait()
            return await original(*args, **kwargs)

        monkeypatch.setattr(api_module, "analyze_job", analyze)
        app = create_app(settings)
        async with app.router.lifespan_context(app), httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://static.test", headers=headers,
        ) as client:
            async def submit(suffix):
                response = await client.post("/v1/jobs?profile=basic" + suffix, content=payload)
                assert response.status_code == 202, response.text
                return response.json()

            async def completed(job):
                async with asyncio.timeout(8):
                    while True:
                        status = (await client.get(job["status_url"])).json()
                        if status["state"] not in {"running", "queued"}:
                            assert status["state"] == "succeeded", status
                            return await client.get(job["result_url"])
                        await asyncio.sleep(0.02)

            first = await submit("&filename=first.apk")
            await asyncio.wait_for(entered.wait(), 2)
            assert (await client.get(first["result_url"])).status_code == 409
            duplicate = await submit("&filename=second.apk&output=json")
            assert duplicate["job_id"] == first["job_id"] and duplicate["reused"]
            second = await submit("&include_file_tree=true")
            assert second["job_id"] != first["job_id"]
            assert (await client.get(second["status_url"])).json()["state"] == "queued"
            assert (await client.get("/readyz")).json()["jobs"]["active"] == 1
            unblock.set()

            report = (await completed(first)).json()
            assert report["input"]["filename"] == "sample.apk"
            assert "file_tree" not in report["modules"]["basic"]["data"]
            cached = await submit("")
            assert cached["job_id"] == first["job_id"] and cached["state"] == "succeeded"
            assert cached["attempts"] == 1
            expanded = (await completed(second)).json()
            assert expanded["modules"]["basic"]["data"]["file_tree"] == ["AndroidManifest.xml", "assets/fixture.txt"]
            assert all(not (directory / "sample.apk").exists() for directory in jobs_dir.glob("job-*"))

            first_directory = jobs_dir / f"job-{first['job_id']}"
            async with asyncio.timeout(4):
                while first_directory.exists():
                    await asyncio.sleep(0.03)
            assert (await client.get(first["status_url"])).status_code == 404
            return second["status_url"]

    second_url = asyncio.run(exercise())
    assert not list(jobs_dir.glob("job-*"))
    stale = jobs_dir / ("job-" + "a" * 32)
    stale.mkdir()
    (stale / "sample.apk").write_bytes(payload)

    async def restart():
        app = create_app(settings)
        async with app.router.lifespan_context(app), httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://static.test", headers=headers,
        ) as client:
            assert (await client.get(second_url)).status_code == 404
            assert not stale.exists()

    asyncio.run(restart())


def test_async_spool_quota_rejects_without_leaking_upload(tmp_path):
    settings = StaticAnalysisSettings(
        work_dir=tmp_path, jobs_dir=tmp_path / "jobs",
        max_apk_mib=2, jobs_storage_mib=1, max_result_mib=1,
    )
    app = create_app(settings)

    async def exercise():
        async with app.router.lifespan_context(app), httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://static.test",
        ) as client:
            result = await client.post("/v1/jobs", headers=APK_HEADERS, content=archive_with_unreadable_manifest())
            assert result.status_code == 503, result.text
            assert result.json()["detail"]["code"] == "JOB_STORAGE_FULL"
            assert not list(settings.jobs_dir.glob("job-*"))

    asyncio.run(exercise())


def test_unix_gateway_relays_and_cleans_worker_jobs(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger=EVENT_LOGGER)
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
                request_id = result.headers["x-request-id"]
                with ZipFile(io.BytesIO(result.content)) as bundle:
                    report = json.loads(bundle.read("result.json"))
                assert report["input"]["filename"] == "fixture.apk"
                assert report["attempts"][0]["duration_ms"] > 0
                assert report["modules"]["basic"]["data"]["file_tree"] == [
                    "AndroidManifest.xml", "assets/fixture.txt",
                ]
                assert not gateway_scratch.exists()

                bad = await client.post(endpoint, headers=headers, content=b"invalid")
                assert bad.status_code == 422 and bad.json()["detail"]["code"] == "INVALID_APK"
                assert (await client.get("/metrics")).status_code == 401
                scrape = (await client.get("/metrics", headers=headers)).text
                assert metric_values(scrape, "apk_lens_worker_up", source="worker-1") == [0]
                assert metric_values(scrape, "apk_lens_worker_up", source="worker-2") == [1]
                assert metric_values(scrape, "apk_lens_requests_total", source="api", outcome="partial") == [1]
                assert metric_values(scrape, "apk_lens_requests_total", source="api", error_code="INVALID_APK") == [1]
                assert metric_values(scrape, "apk_lens_stage_duration_seconds_count", source="worker-2", stage="full") == [2]
                assert metric_values(
                    scrape, "apk_lens_stage_duration_seconds_bucket", source="worker-2", stage="full", le="+Inf"
                ) == [2]
                assert request_id not in scrape and "test-gateway-token" not in scrape

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
                return request_id

        with (tmp_path / "worker.log").open("w+") as log:
            worker = subprocess.Popen(
                [sys.executable, "-m", "apk_lens_service"], env=env, stdout=log, stderr=log
            )
            try:
                request_id = asyncio.run(exercise())
            except Exception:
                log.seek(0)
                print(log.read())
                raise
            finally:
                worker.terminate()
                worker.wait(timeout=12)
            log.seek(0)
            worker_events = [json.loads(line) for line in log if line.startswith("{")]
            assert any(
                event["event"] == "stage_finished" and event["request_id"] == request_id
                for event in worker_events
            )
            assert any(
                event["event"] == "request_finished" and event["request_id"] == request_id
                for event in worker_events
            )
            assert any(
                record.name == EVENT_LOGGER and json.loads(record.getMessage())["request_id"] == request_id
                for record in caplog.records
            )


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
