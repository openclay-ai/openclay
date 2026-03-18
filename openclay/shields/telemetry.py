import logging
import time
from typing import Any, Callable, Dict, Optional, TypeVar, cast
from functools import wraps

logger = logging.getLogger("openclay")

# --- OpenTelemetry Optional Import ---
try:
    from opentelemetry import trace, metrics  # type: ignore
    from opentelemetry.trace import Tracer
    from opentelemetry.metrics import Meter, Counter, Histogram
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False
    Tracer = Any  # type: ignore
    Meter = Any   # type: ignore
    Counter = Any # type: ignore
    Histogram = Any # type: ignore

F = TypeVar('F', bound=Callable[..., Any])


class OpenClayTelemetry:
    """
    Singleton manager for OpenTelemetry metrics and traces.
    Gracefully degrades to a no-op if opentelemetry-api is not installed.
    """
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(OpenClayTelemetry, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        self.enabled = OTEL_AVAILABLE
        
        self.tracer: Optional[Tracer] = None
        self.meter: Optional[Meter] = None
        
        # Metrics
        self.blocks_counter: Optional[Counter] = None
        self.latency_histogram: Optional[Histogram] = None
        self.threat_histogram: Optional[Histogram] = None

        if self.enabled:
            logger.debug("OpenTelemetry API found. Initializing OpenClay telemetry.")
            self.tracer = trace.get_tracer("openclay")
            self.meter = metrics.get_meter("openclay")

            self.blocks_counter = self.meter.create_counter(
                "openclay.blocks.total",
                description="Total number of AI interactions blocked by OpenClay",
            )
            self.latency_histogram = self.meter.create_histogram(
                "openclay.latency.ms",
                unit="ms",
                description="Latency of OpenClay scans in milliseconds",
            )
            self.threat_histogram = self.meter.create_histogram(
                "openclay.threat.level",
                description="Distribution of threat levels detected (0.0 to 1.0)",
            )
        else:
            logger.debug("OpenTelemetry API not installed. Telemetry disabled.")

    def record_scan(self, scan_type: str, duration_ms: float, blocked: bool, threat_level: float, reason: Optional[str] = None):
        """Record metrics for a completed scan."""
        if not self.enabled:
            return

        attributes = {"scan_type": scan_type}
        
        if self.latency_histogram:
            self.latency_histogram.record(duration_ms, attributes)
            
        if self.threat_histogram:
            self.threat_histogram.record(threat_level, attributes)

        if blocked and self.blocks_counter:
            block_attrs = {"scan_type": scan_type}
            if reason:
                block_attrs["reason"] = reason
            self.blocks_counter.add(1, block_attrs)


# Global singleton instance
telemetry = OpenClayTelemetry()


class _DummySpan:
    """A no-op span for when OTEL is disabled."""
    def set_attribute(self, key: str, value: Any) -> "_DummySpan": return self
    def set_status(self, status: Any, description: Optional[str] = None) -> "_DummySpan": return self
    def record_exception(self, exception: Exception, *args, **kwargs) -> "_DummySpan": return self
    def end(self) -> None: pass
    def __enter__(self) -> "_DummySpan": return self
    def __exit__(self, exc_type, exc_val, exc_tb) -> None: pass


def trace_shield_call(scan_type: str):
    """
    Decorator to automatically trace and collect metrics for OpenClay methods.
    
    Args:
        scan_type (str): "input", "output", or "tool_call"
    """
    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            
            # If OTEL is disabled, just run the function and return
            if not telemetry.enabled or telemetry.tracer is None:
                return func(*args, **kwargs)

            # OTEL is enabled, wrap in a span
            with telemetry.tracer.start_as_current_span(f"openclay.{scan_type}") as span:
                try:
                    result = func(*args, **kwargs)
                    
                    # Extract telemetry data from result dict if it exists
                    if isinstance(result, dict):
                        blocked = result.get("blocked", False)
                        threat_level = float(result.get("threat_level", 0.0))
                        reason = result.get("reason", "unknown" if blocked else None)
                        
                        # Span Attributes
                        span.set_attribute("openclay.blocked", blocked)
                        span.set_attribute("openclay.threat_level", threat_level)
                        if reason:
                            span.set_attribute("openclay.reason", reason)
                            
                        # Record Metrics
                        duration_ms = (time.perf_counter() - start_time) * 1000
                        telemetry.record_scan(
                            scan_type=scan_type,
                            duration_ms=duration_ms,
                            blocked=blocked,
                            threat_level=threat_level,
                            reason=reason
                        )
                        
                    return result
                    
                except Exception as e:
                    span.record_exception(e)
                    from opentelemetry.trace.status import Status, StatusCode
                    span.set_status(Status(StatusCode.ERROR))
                    raise
                    
        return cast(F, wrapper)
    return decorator
