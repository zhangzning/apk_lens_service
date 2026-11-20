"""Apply per-process limits before importing parsers or launching external tools."""

import resource

from apk_lens_service.artifacts import AnalysisError
from apk_lens_service.config import MIB, ParseToolSettings


def apply_process_limits(settings: ParseToolSettings) -> None:
    limits = (
        ("RLIMIT_CPU", settings.cpu_seconds),
        ("RLIMIT_AS", settings.address_space_mib * MIB),
        ("RLIMIT_FSIZE", settings.max_file_mib * MIB),
    )
    for name, value in limits:
        if value == 0:
            continue
        kind = getattr(resource, name, None)
        if kind is None:
            raise AnalysisError("WORKER_LIMIT_UNAVAILABLE", f"当前系统无法配置 {name}")
        try:
            inherited = resource.getrlimit(kind)
            soft, hard = (
                value if limit == resource.RLIM_INFINITY else min(limit, value)
                for limit in inherited
            )
            resource.setrlimit(kind, (soft, hard))
        except (OSError, OverflowError, ValueError) as exc:
            raise AnalysisError("WORKER_LIMIT_UNAVAILABLE", f"无法应用 {name}") from exc
