"""
OpenClay Base Agent Primitives.
For developers who want to build secure-by-default agents without LangChain/CrewAI.
"""

from typing import List, Any
from .tools import tool

class Agent:
    """A fundamentally secure AI Agent."""
    def __init__(self, tools: List[Any], name: str = "Assistant"):
        self.tools = tools
        self.name = name
        
    def run(self, input_text: str):
        """Executes the agent logic securely."""
        pass
