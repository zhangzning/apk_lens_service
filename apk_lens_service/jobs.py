"""Bounded, process-local job state and temporary APK/result storage."""

import asyncio
import errno
import fcntl
import logging
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from time import monotonic
from uuid import uuid4

import anyio
from starlette.exceptions import HTTPException

from apk_lens_service.artifacts import AnalysisError
from apk_lens_service.config import MIB, OutputFormat, Profile, StaticAnalysisSettings
from apk_lens_service.http_requests import error
from apk_lens_service.telemetry import Telemetry

logger = logging.getLogger(__name__)
job_dir_name = re.compile(r"job-[0-9a-f]{32}")


def remove_job_directory(directory: Path) -> bool:
    try:
        shutil.rmtree(directory)
    except FileNotFoundError:
        pass
    except OSError:
        logger.exception("Unable to remove temporary APK job files")
        return False
    return True


class RetryableJobError(AnalysisError):
    """Temporary upstream failure. Only the spooled job path may replay the APK."""


@dataclass(frozen=True)
class JobOptions:
    profile: Profile
    output: OutputFormat
    include_file_tree: bool

    def worker_params(self) -> dict[str, str]:
        return {
            "profile": self.profile.value, "output": self.output.value,
            "include_file_tree": str(self.include_file_tree).lower(), "filename": "sample.apk",
        }


@dataclass
class Job:
    id: str
    directory: Path
    options: JobOptions
    metadata: dict
    request_id: str
    reserved: int
    submitted_at: datetime
    state: str = "queued"
    attempts: int = 0
    started_at: datetime | None = None
    completed_at: datetime | None = None
    expires: float | None = None
    result: Path | None = None
    failure: dict | None = None
    readers: int = 0
    previous_worker: Path | None = None

    @property
    def sample(self) -> Path:
        return self.directory / "sample.apk"

    @property
    def key(self) -> tuple[str, JobOptions]:
        return self.metadata["sha256"], self.options

    def view(self, ttl: float) -> dict:
        return {
            "job_id": self.id, "state": self.state, "request_id": self.request_id,
            "sha256": self.metadata["sha256"], "profile": self.options.profile.value,
            "output": self.options.output.value, "include_file_tree": self.options.include_file_tree,
            "attempts": self.attempts, "submitted_at": self.submitted_at,
            "started_at": self.started_at, "completed_at": self.completed_at,
            "expires_at": self.completed_at + timedelta(seconds=ttl) if self.completed_at else None,
            "error": self.failure,
        }


class JobStore:
    def __init__(
        self, settings: StaticAnalysisSettings, executor: Callable[[Job], Awaitable[Path]],
        telemetry: Telemetry,
    ):
        self.settings = settings
        self.executor = executor
        self.telemetry = telemetry
        self.directory = settings.jobs_dir or (
            Path(tempfile.gettempdir()) / f"apk-lens-jobs-{os.getuid()}-{settings.port}"
        )
        self.jobs: dict[str, Job] = {}
        self.by_key: dict[tuple[str, JobOptions], str] = {}
        self.tasks: set[asyncio.Task] = set()
        self.uploads = 0
        self.bytes_reserved = 0
        self.running = False

    @asynccontextmanager
    async def lifespan(self):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory = self.directory.lstat()
        if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.getuid() or directory.st_mode & 0o077:
            raise RuntimeError("APK job spool must be a private directory owned by the service user")
        fd = os.open(self.directory / ".lock", os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for entry in self.directory.iterdir():
                if job_dir_name.fullmatch(entry.name) and entry.is_dir() and not entry.is_symlink():
                    shutil.rmtree(entry)
            self.running = True
            sweeper = asyncio.create_task(self.sweep())
            try:
                yield
            finally:
                self.running = False
                pending = [sweeper, *self.tasks]
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                for job in list(self.jobs.values()):
                    self.remove(job)

    def reserve(self, size: int) -> None:
        if self.bytes_reserved + size > self.settings.jobs_storage_mib * MIB:
            raise error(503, "JOB_STORAGE_FULL", "任务暂存空间不足", headers={"Retry-After": "5"})
        self.bytes_reserved += size

    async def submit(
        self, options: JobOptions, request_id: str, upload_budget: int,
        writer: Callable[[Path], Awaitable[dict]],
    ) -> tuple[Job, bool]:
        if not self.running:
            raise error(503, "JOB_STORE_UNAVAILABLE", "异步任务暂存不可用")
        self.prune()
        pending = sum(job.completed_at is None for job in self.jobs.values())
        if (
            self.uploads >= self.settings.max_jobs
            or pending + self.uploads >= self.settings.max_pending_jobs
            or len(self.jobs) + self.uploads >= self.settings.max_retained_jobs
        ):
            raise error(503, "JOB_CAPACITY_EXHAUSTED", "异步任务已达到容量上限", headers={"Retry-After": "5"})

        reserved = upload_budget
        self.reserve(reserved)
        self.uploads += 1
        job_id = uuid4().hex
        directory = self.directory / f"job-{job_id}"
        accepted = False
        try:
            directory.mkdir(mode=0o700)
            metadata = await writer(directory / "sample.apk")
            self.bytes_reserved -= reserved - metadata["file_size"]
            reserved = metadata["file_size"]
            self.prune()
            key = (metadata["sha256"], options)
            if existing_id := self.by_key.get(key):
                existing = self.jobs[existing_id]
                if existing.expires is None or existing.expires > monotonic():
                    return existing, True
            output_reservation = self.settings.max_result_mib * MIB
            self.reserve(output_reservation)
            reserved += output_reservation
            job = Job(
                job_id, directory, options, metadata, request_id, reserved, datetime.now(timezone.utc),
            )
            self.jobs[job_id] = job
            self.by_key[key] = job_id
            task = asyncio.create_task(self.run(job))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
            accepted = True
            return job, False
        except OSError as exc:
            if exc.errno not in {errno.ENOSPC, errno.EDQUOT}:
                raise
            raise error(507, "WORKSPACE_LIMIT", "任务文件系统暂存空间不足") from exc
        finally:
            self.uploads -= 1
            if not accepted and remove_job_directory(directory):
                self.bytes_reserved -= reserved

    async def run(self, job: Job) -> None:
        start = monotonic()
        try:
            for attempt in range(1, 3):
                job.attempts = attempt
                try:
                    job.result = await self.executor(job)
                except RetryableJobError as exc:
                    if attempt == 2:
                        raise
                    self.telemetry.event(
                        "job_retry", job.request_id, monotonic() - start,
                        job_id=job.id, attempt=attempt, error_code=exc.code,
                    )
                    await asyncio.sleep(0.5)
                else:
                    job.state = "succeeded"
                    break
        except asyncio.CancelledError:
            job.state = "failed"
            job.failure = {"code": "JOB_CANCELLED", "message": "异步任务已中止"}
            raise
        except (AnalysisError, HTTPException, OSError) as exc:
            if isinstance(exc, AnalysisError):
                job.failure = {"code": exc.code, "message": str(exc)}
            elif isinstance(exc, HTTPException) and isinstance(exc.detail, dict):
                job.failure = exc.detail
            else:
                code = "WORKSPACE_LIMIT" if isinstance(exc, OSError) and exc.errno in {
                    errno.ENOSPC, errno.EDQUOT,
                } else "JOB_FAILED"
                job.failure = {"code": code, "message": "异步任务未生成结果"}
            job.state = "failed"
        except Exception:
            logger.exception("Async APK job failed")
            job.failure = {"code": "JOB_FAILED", "message": "异步任务未生成结果"}
            job.state = "failed"
        finally:
            with anyio.CancelScope(shield=True):
                self.finish(job, start)

    def finish(self, job: Job, start: float) -> None:
        keep = 0
        try:
            job.sample.unlink(missing_ok=True)
        except OSError:
            logger.exception("Unable to remove temporary APK")
            keep += job.metadata["file_size"]
        if job.result is not None:
            try:
                keep += job.result.stat().st_size
            except OSError:
                logger.exception("Unable to read temporary APK result")
                job.result = None
                job.state = "failed"
                job.failure = {"code": "JOB_FAILED", "message": "异步解析产物不可用"}
                keep = job.reserved
        self.bytes_reserved -= job.reserved - keep
        job.reserved = keep
        if job.state != "succeeded":
            self.by_key.pop(job.key, None)
        job.completed_at = datetime.now(timezone.utc)
        job.expires = monotonic() + self.settings.job_ttl_seconds
        self.telemetry.event(
            "job_finished", job.request_id, monotonic() - start, job_id=job.id, state=job.state,
            attempts=job.attempts, error_code=job.failure["code"] if job.failure else None,
        )

    def get(self, job_id: str) -> Job:
        self.prune()
        job = self.jobs.get(job_id)
        if job is None or job.expires is not None and job.expires <= monotonic():
            raise error(404, "JOB_NOT_FOUND", "任务已过期或不存在")
        return job

    def remove(self, job: Job) -> None:
        if not remove_job_directory(job.directory):
            return
        self.bytes_reserved -= job.reserved
        self.jobs.pop(job.id)
        if self.by_key.get(job.key) == job.id:
            self.by_key.pop(job.key)

    def prune(self) -> None:
        now = monotonic()
        for job in list(self.jobs.values()):
            if job.expires is not None and job.expires <= now and not job.readers:
                self.remove(job)

    async def sweep(self) -> None:
        while True:
            await asyncio.sleep(min(15, self.settings.job_ttl_seconds))
            self.prune()
