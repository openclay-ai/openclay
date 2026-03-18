"""
OpenClay Tool Security.
Provides decorators and wrappers to scan tool outputs before returning them to the agent context.
"""

from typing import Callable, Any
from functools import wraps

def tool(shield=None):
    """
    Decorator to mark a function as an OpenClay tool.
    Automatically scans the output of the tool before returning it to the LLM context.
    """
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            # TODO: Pass result through the provided shield
            return result
        return wrapper
    return decorator
