import os
import logging
from contextlib import contextmanager
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

OTEL_ENABLED = os.getenv("OTEL_ENABLED", "false").lower() in ("true", "1", "yes")
OTEL_SERVICE_NAME = os.getenv("OTEL_SERVICE_NAME", "enterprise-llm-security-gateway")
OTEL_EXPORTER_OTLP_ENDPOINT = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")

_tracer = None
_tracer_initialized = False


def init_tracing(app=None) -> None:
    """
    Initialize OpenTelemetry SDK if OTEL_ENABLED is True.
    Defaults to no-op when disabled.
    """
    global _tracer, _tracer_initialized
    if _tracer_initialized:
        return

    _tracer_initialized = True

    if not OTEL_ENABLED:
        logger.info("OpenTelemetry tracing is disabled (OTEL_ENABLED=false).")
        return

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

        resource = Resource.create({"service.name": OTEL_SERVICE_NAME})
        provider = TracerProvider(resource=resource)

        if OTEL_EXPORTER_OTLP_ENDPOINT:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
            exporter = OTLPSpanExporter(endpoint=OTEL_EXPORTER_OTLP_ENDPOINT)
            provider.add_span_processor(BatchSpanProcessor(exporter))
            logger.info(f"OpenTelemetry OTLP Exporter configured for {OTEL_EXPORTER_OTLP_ENDPOINT}")
        else:
            # Fallback to Console/No-op in development
            logger.info("No OTLP endpoint configured; using default trace provider.")

        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer("enterprise-security-gateway")

        # Instrument FastAPI app if provided
        if app:
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
            FastAPIInstrumentor.instrument_app(app, tracer_provider=provider)

        logger.info(f"OpenTelemetry tracing initialized successfully for {OTEL_SERVICE_NAME}")
    except Exception as e:
        logger.warning(f"Failed to initialize OpenTelemetry tracing (falling back safely to no-op): {e}")
        _tracer = None


def get_tracer():
    global _tracer
    if not _tracer and OTEL_ENABLED:
        init_tracing()
    return _tracer


# Forbidden attributes that must never enter span metadata
FORBIDDEN_TRACE_ATTRS = {
    "prompt",
    "raw_prompt",
    "response",
    "raw_response",
    "api_key",
    "x_api_key",
    "authorization",
    "password",
    "secret",
    "token"
}


@contextmanager
def trace_span(name: str, attributes: Optional[Dict[str, Any]] = None):
    """
    Context manager for creating a tracer span with sanitized, low-cardinality metadata.
    Guaranteed fail-safe: if tracing fails or is disabled, yields safely without error.
    """
    tracer = get_tracer()
    if not tracer:
        yield None
        return

    try:
        with tracer.start_as_current_span(name) as span:
            if attributes:
                for k, v in attributes.items():
                    if str(k).lower() not in FORBIDDEN_TRACE_ATTRS and v is not None:
                        # Ensure values are simple types (str, int, float, bool)
                        if isinstance(v, (str, int, float, bool)):
                            span.set_attribute(k, v)
                        else:
                            span.set_attribute(k, str(v))
            yield span
    except Exception as e:
        logger.debug(f"Span execution error ({name}): {e}")
        yield None
