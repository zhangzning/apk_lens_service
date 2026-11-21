"""Run the full Docker Compose regression against an isolated project."""

import datetime
import json
import os
import re
import secrets
import subprocess
import sys
import textwrap
import time
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPException
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener
from uuid import uuid4

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "test.apk.lens.compose"
MANIFEST = f'<manifest package="{PACKAGE}"><application/></manifest>'.encode()


class ComposeStack:
    def __init__(self):
        project = f"apk-lens-ci-{uuid4().hex[:10]}"
        self.token = secrets.token_hex(16)
        self.images = (f"{project}:api", f"{project}:worker")
        self.env = {key: value for key, value in os.environ.items() if not key.startswith(("APK_LENS_", "COMPOSE_"))}
        self.env.update(
            APK_LENS_SERVICE_TOKEN=self.token,
            APK_LENS_PORT="0",
            APK_LENS_WORKER_TMPFS="8m",
            APK_LENS_API_IMAGE=self.images[0],
            APK_LENS_WORKER_IMAGE=self.images[1],
        )
        self.command = ["docker", "compose", "--env-file", "/dev/null", "-p", project]
        self.opener = build_opener(ProxyHandler({}))
        self.base = ""

    def run(self, *args, input=None, timeout=45):
        return subprocess.run(
            args, cwd=ROOT, env=self.env, input=input, capture_output=True, timeout=timeout,
        )

    def call(self, *args, input=None, timeout=45, check=True):
        result = self.run(*self.command, *args, input=input, timeout=timeout)
        if result.returncode and check:
            print((result.stdout + result.stderr)[-10000:].decode(errors="replace"), file=sys.stderr)
            result.check_returncode()
        return result.stdout

    def exec_worker(self, worker, code, *, input=None, check=True):
        return self.call("exec", "-T", worker, "python", "-c", textwrap.dedent(code), input=input, check=check)

    def inspect(self, service):
        container = self.call("ps", "-q", service).decode().strip()
        result = self.run("docker", "inspect", container)
        result.check_returncode()
        return json.loads(result.stdout)[0]

    def request(self, path, *, data=None, authorized=True, headers=None):
        if headers is None:
            headers = {}
        if authorized:
            headers = {**headers, "Authorization": f"Bearer {self.token}"}
        request = Request(self.base + path, data=data, headers=headers)
        try:
            response = self.opener.open(request, timeout=20)
        except HTTPError as failure:
            response = failure
        with response:
            return response.status, response.headers, response.read()

    def ready_workers(self):
        try:
            return json.loads(self.request("/readyz")[2])["workers"]["ready"]
        except (OSError, HTTPException, KeyError, ValueError):
            return None

    def close(self):
        self.call("down", "--volumes", "--remove-orphans", check=False)
        self.run("docker", "image", "rm", *self.images)


def wait_for(condition, description, timeout=30):
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() >= deadline:
            raise AssertionError(description)
        time.sleep(0.2)


def check_isolation(stack, worker):
    container = stack.inspect(worker)
    host = container["HostConfig"]
    assert host["NetworkMode"] == "none"
    assert host["ReadonlyRootfs"] and host["CapDrop"] == ["ALL"]
    assert container["Config"]["User"] == "10001:10001"
    assert "no-new-privileges:true" in host["SecurityOpt"]
    assert not any(item.startswith("APK_LENS_SERVICE_TOKEN=") for item in container["Config"]["Env"])
    stack.exec_worker(worker, """
        import errno
        import os
        import tempfile
        from pathlib import Path
        from apk_lens_service.config import ParseToolSettings, StaticAnalysisSettings
        from apk_lens_service.worker_limits import apply_process_limits
        import resource

        proc = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
        assert os.getuid() != 0
        assert proc["Seccomp"].strip() == "2" and proc["NoNewPrivs"].strip() == "1"
        assert int(proc["CapEff"], 16) == 0
        assert os.listdir("/sys/class/net") == ["lo"]

        cgroup = Path("/sys/fs/cgroup")
        quota, period = map(int, (cgroup / "cpu.max").read_text().split())
        assert quota == 2 * period
        assert int((cgroup / "memory.max").read_text()) == 4 * 1024**3
        assert int((cgroup / "memory.swap.max").read_text()) == 0
        assert int((cgroup / "pids.max").read_text()) == 192
        options = StaticAnalysisSettings()
        apply_process_limits(ParseToolSettings(cpu_seconds=options.worker_cpu_seconds,
            max_file_mib=options.worker_max_file_mib, address_space_mib=options.worker_address_space_mib))
        assert resource.getrlimit(resource.RLIMIT_CPU) == (900, 900)
        assert resource.getrlimit(resource.RLIMIT_FSIZE) == (256 * 1024**2,) * 2
        assert resource.getrlimit(resource.RLIMIT_AS) == (8192 * 1024**2,) * 2

        workspace = os.statvfs("/work")
        assert workspace.f_frsize * workspace.f_blocks == 8 * 1024**2
        with tempfile.TemporaryDirectory(dir="/work") as scratch:
            block = bytes(1024**2)
            try:
                with (Path(scratch) / "quota.bin").open("wb", buffering=0) as target:
                    for _ in range(9):
                        target.write(block)
            except OSError as exc:
                assert exc.errno == errno.ENOSPC
            else:
                raise AssertionError("Worker workspace did not enforce quota")
    """)


def build_fixture(stack):
    return stack.exec_worker("worker-1", """
        import subprocess
        import sys
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory(dir="/work") as directory:
            root = Path(directory)
            manifest = root / "AndroidManifest.xml"
            manifest.write_bytes(sys.stdin.buffer.read())
            unsigned = root / "unsigned.apk"
            key = root / "fixture.p12"
            apk = root / "fixture.apk"
            subprocess.run(["aapt", "package", "-M", str(manifest), "-F", str(unsigned)], check=True)
            subprocess.run([
                "keytool", "-genkeypair", "-alias", "fixture", "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "2", "-dname", "CN=APK Lens Integration Test", "-keystore", str(key),
                "-storetype", "PKCS12", "-storepass", "fixture-password", "-noprompt",
            ], check=True, stdout=sys.stderr)
            subprocess.run([
                "apksigner", "sign", "--min-sdk-version", "24", "--ks", str(key),
                "--ks-pass", "pass:fixture-password", "--out", str(apk), str(unsigned),
            ], check=True, stdout=sys.stderr)
            sys.stdout.buffer.write(apk.read_bytes())
    """, input=MANIFEST)


def verify_request(stack, apk):
    status, headers, body = stack.request(
        "/v1/analyze?profile=basic", data=apk,
        headers={"Content-Type": "application/vnd.android.package-archive"},
    )
    assert status == 200, body[:300]
    request_id = headers["X-Request-ID"]
    assert re.fullmatch("[0-9a-f]{32}", request_id)
    report = json.loads(body)
    assert report["modules"]["basic"]["data"]["package_name"] == PACKAGE
    assert report["attempts"][0]["duration_ms"] > 0
    return request_id


def check_standard_analysis(stack, apk):
    status, _, body = stack.request(
        "/v1/analyze?profile=standard", data=apk,
        headers={"Content-Type": "application/vnd.android.package-archive"},
    )
    assert status == 200, body[:300]
    report = json.loads(body)
    modules = report["modules"]
    assert report["status"] == "ok"
    assert {key: module["status"] for key, module in modules.items()} == {
        "basic": "ok", "packing": "ok", "permission_analysis": "ok", "certificate": "ok",
    }
    assert modules["basic"]["data"]["package_name"] == PACKAGE
    assert modules["permission_analysis"]["data"]["permissions"] == []
    assert modules["certificate"]["data"]["fingerprint_sha256"]


def check_telemetry(stack, request_id):
    assert stack.request("/metrics", authorized=False)[0] == 401
    status, headers, data = stack.request("/metrics")
    assert status == 200 and "version=0.0.4" in headers["Content-Type"]
    text = data.decode()
    assert 'apk_lens_worker_up{source="worker-1"} 1.0' in text
    assert 'apk_lens_worker_up{source="worker-2"} 1.0' in text
    assert 'apk_lens_stage_duration_seconds_count{profile="basic",source="worker-1",stage="full"} 1.0' in text
    assert request_id not in text

    containers = [stack.inspect(service)["Id"] for service in ("api", "worker-1")]

    def has_correlated_events():
        events = []
        for container in containers:
            logs = stack.run("docker", "logs", container)
            logs.check_returncode()
            events.extend(json.loads(line) for line in logs.stdout.decode().splitlines() if line.startswith("{"))
        related = {(event["source"], event["event"]) for event in events if event.get("request_id") == request_id}
        return {("api", "request_finished"), ("worker", "stage_finished")} <= related

    wait_for(has_correlated_events, "Missing structured API and worker events")


def check_recovery(stack, apk):
    api_id = stack.inspect("api")["Id"]
    stack.call("stop", "worker-1")
    wait_for(lambda: stack.ready_workers() == 1, "Gateway did not route around stopped worker")
    verify_request(stack, apk)
    stack.call("start", "worker-1")
    wait_for(lambda: stack.ready_workers() == 2, "Worker did not rejoin on its original socket")

    container = stack.inspect("worker-1")
    started_at = datetime.datetime.fromisoformat(container["State"]["StartedAt"])
    age = (datetime.datetime.now(datetime.timezone.utc) - started_at).total_seconds()
    # Docker activates its restart policy after a successful start (10 seconds).
    time.sleep(max(0, min(11, 11 - age)))
    crash_inflight = """
        import os
        import signal
        import time
        from pathlib import Path

        def processes():
            for process in Path("/proc").glob("[0-9]*"):
                try:
                    yield int(process.name), (process / "cmdline").read_bytes().split(bytes([0]))
                except (FileNotFoundError, ProcessLookupError):
                    pass

        server = next(pid for pid, args in processes() if args[1:3] == [b"-m", b"apk_lens_service"])
        Path("/work/recovery-probe-ready").touch()
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if any(b"apk_lens_service.worker" in args and b"full" in args for _, args in processes()):
                os.kill(server, signal.SIGKILL)
                break
            time.sleep(0.01)
        else:
            raise AssertionError("Worker never started the APK parsing stage")
    """

    def probe_ready():
        return stack.exec_worker(
            "worker-1", 'from pathlib import Path; print(Path("/work/recovery-probe-ready").is_file())',
            check=False,
        ).strip() == b"True"

    with ThreadPoolExecutor(max_workers=1) as probes:
        watcher = probes.submit(stack.exec_worker, "worker-1", crash_inflight, check=False)
        wait_for(probe_ready, "Crash probe did not start", timeout=8)
        status, _, body = stack.request(
            "/v1/jobs?profile=basic", data=apk,
            headers={"Content-Type": "application/vnd.android.package-archive"},
        )
        assert status == 202, body[:300]
        job = json.loads(body)
        watcher.result(timeout=16)

    def job_done():
        _, _, body = stack.request(job["status_url"])
        state = json.loads(body)
        assert state["state"] != "failed", state
        return state["state"] == "succeeded"

    wait_for(job_done, "Job did not finish on the surviving worker")
    finished = json.loads(stack.request(job["status_url"])[2])
    assert finished["attempts"] == 2, finished
    status, _, body = stack.request(job["result_url"])
    assert status == 200 and json.loads(body)["modules"]["basic"]["data"]["package_name"] == PACKAGE
    status, _, body = stack.request(
        "/v1/jobs?profile=basic&filename=alias.apk", data=apk,
        headers={"Content-Type": "application/vnd.android.package-archive"},
    )
    duplicate = json.loads(body)
    assert status == 202 and duplicate["reused"] and duplicate["job_id"] == job["job_id"]

    logs = stack.run("docker", "logs", api_id)
    logs.check_returncode()
    events = [json.loads(line) for line in logs.stdout.decode().splitlines() if line.startswith("{")]
    assert any(event.get("event") == "job_retry" and event.get("job_id") == job["job_id"]
               and event.get("error_code") == "WORKER_CONNECTION_FAILED" for event in events)

    def restarted():
        try:
            return stack.inspect("worker-1")["RestartCount"] > container["RestartCount"] and stack.ready_workers() == 2
        except subprocess.CalledProcessError:
            return False

    wait_for(restarted, "Docker did not restart the crashed worker and restore readiness")
    assert stack.inspect("api")["Id"] == api_id
    verify_request(stack, apk)


def main():
    stack = ComposeStack()
    try:
        version = stack.run("docker", "info", "--format", "{{.OSType}} {{.CgroupVersion}}")
    except FileNotFoundError:
        raise SystemExit("The Compose test needs the Docker CLI and Compose V2.") from None
    if version.returncode or version.stdout.strip() != b"linux 2":
        raise SystemExit("The Compose test needs a running Linux Docker Engine with cgroup v2.")
    try:
        stack.call("up", "--build", "--wait", "--wait-timeout", "90", timeout=650)
        published = stack.call("port", "api", "18086").decode().strip()
        assert re.fullmatch(r"127\.0\.0\.1:\d+", published), published
        stack.base = "http://" + published
        wait_for(lambda: stack.ready_workers() == 2, "Both workers must be ready")
        for worker in ("worker-1", "worker-2"):
            check_isolation(stack, worker)
        print("Both workers passed runtime isolation and resource-limit checks", flush=True)
        apk = build_fixture(stack)
        check_telemetry(stack, verify_request(stack, apk))
        check_standard_analysis(stack, apk)
        print("Signed APK standard analysis, request correlation and metrics passed", flush=True)
        check_recovery(stack, apk)
        print("In-flight job replay, result reuse and worker recovery passed", flush=True)
    except Exception:
        print(stack.call("ps", "-a", check=False).decode(errors="replace"), file=sys.stderr)
        logs = stack.call("logs", "--no-color", "--tail", "40", check=False).decode(errors="replace")
        print(logs.replace(stack.token, "[test token]"), file=sys.stderr)
        raise
    finally:
        stack.close()


if __name__ == "__main__":
    main()
