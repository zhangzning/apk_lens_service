import ipaddress
import tempfile
from enum import StrEnum
from pathlib import Path

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Profile(StrEnum):
    BASIC = "basic"
    STANDARD = "standard"
    DEEP = "deep"


class OutputFormat(StrEnum):
    JSON = "json"
    ZIP = "zip"


class StaticAnalysisSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="APK_LENS_SERVICE_")

    host: str = "127.0.0.1"
    port: int = Field(default=18086, ge=1, le=65535)
    listen_socket: Path | None = None
    worker_sockets: tuple[Path, ...] = ()
    token: SecretStr = SecretStr("")
    work_dir: Path = Field(default_factory=lambda: Path(tempfile.gettempdir()))
    max_jobs: int = Field(default=2, ge=1, le=8)
    max_deep_jobs: int = Field(default=1, ge=0, le=8)
    max_apk_mib: int = Field(default=512, ge=1, le=4096)
    max_expanded_mib: int = Field(default=1536, ge=1, le=8192)
    max_result_mib: int = Field(default=256, ge=1, le=2048)
    max_files: int = Field(default=50000, ge=1, le=200000)
    upload_timeout: float = Field(default=120, gt=0)
    full_timeout: float = Field(default=180, gt=0)
    fallback_timeout: float = Field(default=120, gt=0)
    certificate_timeout: float = Field(default=45, gt=0)
    deep_timeout: float = Field(default=900, gt=0)
    terminate_grace: float = Field(default=2, gt=0, le=10)
    aapt2_bin: str = "aapt2"
    jadx_bin: str = "jadx"
    java_home: str = ""
    jadx_max_heap_mb: int = Field(default=1536, ge=512, le=8192)
    worker_cpu_seconds: int = Field(default=0, ge=0)
    worker_address_space_mib: int = Field(default=0, ge=0)
    worker_max_file_mib: int = Field(default=0, ge=0)
    jobs_dir: Path | None = None
    job_ttl_seconds: float = Field(default=900, gt=0, le=86400)
    max_pending_jobs: int = Field(default=6, ge=1, le=64)
    max_retained_jobs: int = Field(default=128, ge=1, le=2048)
    jobs_storage_mib: int = Field(default=2048, ge=1, le=65536)

    @model_validator(mode="after")
    def check_service_limits(self):
        if self.max_deep_jobs > self.max_jobs:
            raise ValueError("max_deep_jobs 不能超过 max_jobs")
        if self.listen_socket is not None:
            if not self.listen_socket.is_absolute() or self.worker_sockets or self.max_jobs != 1:
                raise ValueError("解析实例需要一个绝对套接字路径，并且只接受一个并发任务")
            return self
        if self.worker_sockets and (
            len(set(self.worker_sockets)) != len(self.worker_sockets)
            or any(not path.is_absolute() for path in self.worker_sockets)
            or self.max_jobs > len(self.worker_sockets)
        ):
            raise ValueError("worker_sockets 需要互不相同的绝对路径，且数量须覆盖 max_jobs")
        try:
            loopback = ipaddress.ip_address(self.host).is_loopback
        except ValueError:
            loopback = self.host == "localhost"
        if not loopback and not self.token.get_secret_value():
            raise ValueError("监听非回环地址时须配置服务 token")
        return self


class ParseToolSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="APK_LENS_SERVICE_TOOL_")

    aapt2_bin: str = "aapt2"
    jadx_bin: str = "jadx"
    java_home: str = ""
    jadx_max_heap_mb: int = 1536
    jadx_timeout_seconds: int = 900
    icon_storage_dir: Path = Path("icon")
    cpu_seconds: int = Field(default=0, ge=0)
    address_space_mib: int = Field(default=0, ge=0)
    max_file_mib: int = Field(default=0, ge=0)


parse_tools = ParseToolSettings()

MIB = 1024 * 1024
MAX_REPORT_BYTES = 16 * MIB
MAX_INLINE_ICON_BYTES = 4 * MIB
