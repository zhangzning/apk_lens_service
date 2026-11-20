import uvicorn

from apk_lens_service.config import StaticAnalysisSettings


def main():
    settings = StaticAnalysisSettings()
    uvicorn.run(
        "apk_lens_service.api:create_app",
        factory=True,
        host=settings.host,
        port=settings.port,
        uds=str(settings.listen_socket) if settings.listen_socket is not None else None,
        workers=1,
        timeout_graceful_shutdown=10,
    )


if __name__ == "__main__":
    main()
