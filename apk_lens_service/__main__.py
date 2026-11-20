from copy import deepcopy

import uvicorn

from apk_lens_service.config import StaticAnalysisSettings
from apk_lens_service.telemetry import EVENT_LOGGER


def main():
    settings = StaticAnalysisSettings()
    logging = deepcopy(uvicorn.config.LOGGING_CONFIG)
    logging["formatters"]["events"] = {"format": "%(message)s"}
    logging["handlers"]["events"] = {
        "class": "logging.StreamHandler", "formatter": "events", "stream": "ext://sys.stdout",
    }
    logging["loggers"][EVENT_LOGGER] = {"handlers": ["events"], "level": "INFO", "propagate": False}
    uvicorn.run(
        "apk_lens_service.api:create_app",
        factory=True,
        host=settings.host,
        port=settings.port,
        uds=str(settings.listen_socket) if settings.listen_socket is not None else None,
        workers=1,
        log_config=logging,
        access_log=False,
        timeout_graceful_shutdown=10,
    )


if __name__ == "__main__":
    main()
