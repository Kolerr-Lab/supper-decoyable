"""
DECOYABLE API Application

Refactored FastAPI application with clean architecture, dependency injection,
and modular router design.
"""

import uvicorn
from fastapi import FastAPI

from decoyable.api.service import create_api_app
from decoyable.core.config import Settings
from decoyable.core.logging import setup_logging_service
from decoyable.core.registry import ServiceRegistry


def create_application() -> FastAPI:
    """
    Create and configure the DECOYABLE FastAPI application.

    This function initializes all core services and configures the API
    with proper dependency injection and modular architecture.
    """
    # Initialize core services
    config = Settings()
    registry = ServiceRegistry()
    logging_service = setup_logging_service(config)

    # Register core services
    registry.register_instance('config', config)
    registry.register_instance('logging', logging_service)

    # Create API application with service injection
    app = create_api_app(config, registry, logging_service)

    return app


# Create the application instance
app = create_application()


def main():
    """Main entry point for running the API server."""
    config = Settings()

    uvicorn.run(
        "decoyable.api.app:app",
        host=config.api.host,
        port=config.api.port,
        reload=config.api.reload,
        workers=config.api.workers,
        log_level=config.logging.level.lower()
    )


if __name__ == "__main__":
    main()
