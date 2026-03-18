class OpenClayError(Exception):
    """Base class for OpenClay exceptions."""
    pass

class StreamBlockedError(OpenClayError):
    """Raised when protect_stream detects an attack mid-generation."""
    def __init__(self, reason: str, result_dict: dict = None):
        self.reason = reason
        self.result_dict = result_dict or {}
        message = f"Stream blocked by OpenClay. Reason: {reason}"
        super().__init__(message)
