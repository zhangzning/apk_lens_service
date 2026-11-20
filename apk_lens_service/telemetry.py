"""Request correlation, structured events and bounded Prometheus metrics."""

import asyncio
import json
import logging
import re
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from time import perf_counter
from uuid import uuid4

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest
from prometheus_client.metrics_core import GaugeMetricFamily, Metric
from prometheus_client.parser import text_string_to_metric_families
from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from apk_lens_service.config import Profile

REQUEST_ID_HEADER = "X-Request-ID"
WORKER_OUTCOME_HEADER = "X-APK-Lens-Outcome"
WORKER_ERROR_HEADER = "X-APK-Lens-Error"
EVENT_LOGGER = "apk_lens_service.events"

logger = logging.getLogger(EVENT_LOGGER)
request_id_pattern = re.compile(r"[0-9a-f]{32}")
ERROR_CODES = frozenset({
    "APK_EXPANSION_LIMIT", "APK_IDENTITY_UNRESOLVED", "APK_SIZE_LIMIT", "CAPACITY_EXHAUSTED",
    "CLIENT_DISCONNECTED", "DEEP_DISABLED", "HTTP_ERROR", "INTERNAL_ERROR",
    "INVALID_APK", "INVALID_APK_FILENAME", "INVALID_ARTIFACT", "INVALID_CONTENT_LENGTH",
    "INVALID_WORKER_RESPONSE", "JADX_FAILED", "JADX_PARTIAL", "JADX_UNAVAILABLE",
    "JOB_CANCELLED", "JOB_CAPACITY_EXHAUSTED", "JOB_FAILED", "JOB_NOT_FOUND", "JOB_NOT_READY",
    "JOB_STORAGE_FULL", "JOB_STORE_UNAVAILABLE",
    "PERMISSION_ANALYSIS_FAILED", "REQUEST_CANCELLED", "REQUEST_VALIDATION_FAILED", "RESPONSE_INTERRUPTED",
    "RESULT_LIMIT", "STAGE_CANCELLED", "STAGE_CPU_LIMIT", "STAGE_MEMORY_LIMIT",
    "STAGE_PARTIAL", "STAGE_PROCESS_FAILED", "STAGE_TIMEOUT", "UNAUTHORIZED",
    "UNSUPPORTED_CONTENT_TYPE", "UPLOAD_TIMEOUT", "WORKER_CONNECTION_FAILED",
    "WORKER_LIMIT_UNAVAILABLE", "WORKER_TIMEOUT", "WORKER_UNAVAILABLE", "WORKSPACE_LIMIT",
})
BUCKETS = (0.05, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 180.0, 600.0, 1200.0)
PROFILES = {profile.value for profile in Profile} | {"unknown"}
REQUEST_OUTCOMES = {"ok", "partial", "error", "disconnected", "cancelled", "interrupted"}
STAGE_STATES = {"ok", "partial", "failed", "timed_out", "cancelled"}
STAGES = {"full", "aapt2", "certificate", "deep"}
LABEL_VALUES = {
    "profile": PROFILES, "outcome": REQUEST_OUTCOMES, "state": STAGE_STATES, "stage": STAGES,
    "error_code": ERROR_CODES | {"NONE", "OTHER_ERROR"},
    "status_code": {str(status) for status in range(100, 600)},
    "kind": {"all", "deep"}, "le": {str(bucket) for bucket in BUCKETS} | {"+Inf"},
}


def known_error(value: object) -> str | None:
    if isinstance(value, str) and value in ERROR_CODES:
        return value
    return None


class MetricsSnapshot:
    def __init__(self, families: Iterable[Metric]):
        self.families = families

    def collect(self) -> Iterable[Metric]:
        return self.families


class Telemetry:
    def __init__(self, source: str):
        self.source = source
        self.registry = CollectorRegistry()
        self.requests = Counter(
            "apk_lens_requests_total", "Completed APK HTTP requests",
            ("profile", "outcome", "status_code", "error_code"), registry=self.registry,
        )
        self.request_duration = Histogram(
            "apk_lens_request_duration_seconds", "APK request duration including upload and delivery",
            ("profile",), buckets=BUCKETS, registry=self.registry,
        )
        self.stages = Counter(
            "apk_lens_stages_total", "APK stage attempts",
            ("profile", "stage", "state", "error_code"), registry=self.registry,
        )
        self.stage_duration = Histogram(
            "apk_lens_stage_duration_seconds", "APK stage execution duration",
            ("profile", "stage"), buckets=BUCKETS, registry=self.registry,
        )
        self.jobs_active = Gauge(
            "apk_lens_active_jobs", "Active APK jobs", ("kind",), registry=self.registry,
        )
        self.jobs_active.labels("all")
        self.jobs_active.labels("deep")

    def event(self, event: str, request_id: str, duration: float, **fields) -> None:
        logger.info(json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "event": event, "source": self.source, "request_id": request_id,
            "duration_ms": round(duration * 1000, 2), **fields,
        }, ensure_ascii=False, separators=(",", ":")))

    def finish_request(
        self, request_id: str, profile: str, status: int, outcome: str,
        duration: float, reason: str | None,
    ) -> None:
        self.requests.labels(profile, outcome, str(status), reason or "NONE").inc()
        self.request_duration.labels(profile).observe(duration)
        self.event(
            "request_finished", request_id, duration, profile=profile,
            status_code=status, outcome=outcome, error_code=reason,
        )

    def finish_stage(
        self, request_id: str, profile: Profile, stage: str, state: str,
        duration: float, reason: str | None,
    ) -> None:
        self.stages.labels(profile.value, stage, state, reason or "NONE").inc()
        self.stage_duration.labels(profile.value, stage).observe(duration)
        self.event(
            "stage_finished", request_id, duration, profile=profile.value,
            stage=stage, state=state, error_code=reason,
        )

    def scrape(self, active: int, deep: int, workers: Mapping[str, bytes | None]) -> bytes:
        self.jobs_active.labels("all").set(active)
        self.jobs_active.labels("deep").set(deep)
        native = list(self.registry.collect())
        merged = {family.name: Metric(family.name, family.documentation, family.type) for family in native}
        self._add_samples(native, self.source, merged)
        if workers:
            up = GaugeMetricFamily("apk_lens_worker_up", "Worker metrics endpoint reachable", labels=["source"])
            for source, contents in workers.items():
                try:
                    families = list(text_string_to_metric_families(contents.decode("utf-8"))) if contents else []
                except ValueError:
                    families = []
                available = any(family.name == "apk_lens_active_jobs" and family.samples for family in families)
                up.add_metric([source], int(available))
                if available:
                    self._add_samples(families, source, merged)
            merged[up.name] = up
        return generate_latest(MetricsSnapshot(merged.values()))

    @staticmethod
    def _add_samples(families: Iterable[Metric], source: str, merged: dict[str, Metric]) -> None:
        seen = set()
        for family in families:
            target = merged.get(family.name)
            if target is None or family.type != target.type:
                continue
            suffixes = {
                "counter": ("_total",),
                "histogram": ("_bucket", "_count", "_sum"),
                "gauge": ("",),
            }[target.type]
            accepted_names = {family.name + suffix for suffix in suffixes}
            for sample in family.samples:
                if sample.name not in accepted_names:
                    continue
                labels = {key: value for key, value in sample.labels.items() if key != "source"}
                if any(value not in LABEL_VALUES.get(key, ()) for key, value in labels.items()):
                    continue
                key = (sample.name, tuple(sorted(labels.items())))
                if key not in seen:
                    seen.add(key)
                    target.add_sample(sample.name, {**labels, "source": source}, sample.value)


class TelemetryMiddleware:
    def __init__(self, app: ASGIApp, telemetry: Telemetry, *, private_worker: bool):
        self.app = app
        self.telemetry = telemetry
        self.private_worker = private_worker

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        incoming = Headers(scope=scope).get(REQUEST_ID_HEADER, "") if self.private_worker else ""
        request_id = incoming if request_id_pattern.fullmatch(incoming) else uuid4().hex
        state = scope.setdefault("state", {})
        state["request_id"] = request_id
        start = perf_counter()
        status = None
        completed = False
        disconnected = False
        failure = None

        async def capture_receive() -> Message:
            nonlocal disconnected
            message = await receive()
            if message["type"] == "http.disconnect":
                disconnected = True
            return message

        async def send_headers(message: Message) -> None:
            nonlocal status, completed, disconnected
            if message["type"] == "http.response.start":
                status = message["status"]
                headers = MutableHeaders(scope=message)
                headers[REQUEST_ID_HEADER] = request_id
                if self.private_worker:
                    reason = known_error(state.get("analysis_error"))
                    if reason:
                        headers[WORKER_ERROR_HEADER] = reason
                    if state.get("analysis_outcome") == "partial":
                        headers[WORKER_OUTCOME_HEADER] = "partial"
            try:
                await send(message)
            except OSError:
                disconnected = True
                raise
            if message["type"] == "http.response.pathsend" or (
                message["type"] == "http.response.body" and not message.get("more_body", False)
            ):
                completed = True

        try:
            await self.app(scope, capture_receive, send_headers)
        except asyncio.CancelledError:
            failure = "REQUEST_CANCELLED"
            raise
        except Exception:
            failure = "INTERNAL_ERROR"
            raise
        finally:
            route = getattr(scope.get("route"), "path", scope["path"])
            if scope["method"] == "POST" and route == "/v1/analyze":
                self.report_request(
                    state, request_id, status, completed, disconnected, failure, perf_counter() - start,
                )

    def report_request(
        self, state: dict, request_id: str, status: int | None, completed: bool,
        disconnected: bool, failure: str | None, duration: float,
    ) -> None:
        profile = state.get("analysis_profile", "unknown")
        reason = known_error(state.get("analysis_error"))
        if status == 499 or (disconnected and not completed):
            outcome, status, reason = "disconnected", 499, "CLIENT_DISCONNECTED"
        elif failure == "REQUEST_CANCELLED":
            outcome, status, reason = "cancelled", status or 503, failure
        elif failure or not completed:
            outcome, reason = ("error", "INTERNAL_ERROR") if status is None else (
                "interrupted", "RESPONSE_INTERRUPTED"
            )
            status = status or 500
        elif status >= 400:
            outcome = "error"
            reason = reason or ("REQUEST_VALIDATION_FAILED" if status == 422 else "HTTP_ERROR")
        else:
            outcome = "partial" if state.get("analysis_outcome") == "partial" else "ok"
        self.telemetry.finish_request(request_id, profile, status, outcome, duration, reason)
