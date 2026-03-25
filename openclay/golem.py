"""
OpenClay Golem — Autonomous Long-Running Entity  (v1.0.0)

A Golem is a persistent, self-sustaining agent built from clay.
Unlike a Knight (single-task executor), a Golem runs continuously,
processing tasks from an internal queue under full shield protection.

Usage::

    from openclay import Golem, Shield, ClayMemory

    golem = Golem(
        name="sentinel",
        llm_caller=my_llm_function,
        shield=Shield.strict(),
        memory=ClayMemory(),
    )

    golem.start()
    golem.submit("Scan incoming data for threats")
    golem.submit("Summarise today's security events")
    results = golem.collect()  # gather completed results
    golem.stop()
"""

from __future__ import annotations

import threading
import queue
import time
from typing import Any, Callable, Dict, List, Optional

from .shields import Shield
from .runtime import ClayRuntime, ClayResult
from .memory import ClayMemory
from .tracing import Trace, TraceLog
from .policies import Policy


class GolemResult:
    """Container for a single Golem task result."""

    def __init__(self, task: str, result: ClayResult, index: int):
        self.task = task
        self.result = result
        self.index = index
        self.blocked = result.blocked
        self.output = result.output
        self.trace = result.trace

    def __repr__(self) -> str:
        status = "BLOCKED" if self.blocked else "OK"
        return f"GolemResult(#{self.index}, {status}, task={self.task!r})"


class Golem:
    """
    Autonomous, long-running secure entity.

    A Golem processes tasks from a queue inside a shielded runtime,
    with persistent memory and full trace logging across its lifetime.

    Parameters
    ----------
    name : str
        Identifier for this Golem.
    llm_caller : callable
        Function called as ``llm_caller(text, context=...)`` to process tasks.
    tools : list, optional
        List of ``@ClayTool`` decorated functions.
    shield : Shield, optional
        Shield instance. Defaults to ``Shield.strict()``.
    memory : ClayMemory, optional
        Persistent memory. Shared across all tasks.
    policy : Policy, optional
        Security policy. If provided, overrides the shield preset.
    trust : str
        Trust level (``"untrusted"`` | ``"internal"``).
    """

    def __init__(
        self,
        name: str,
        llm_caller: Callable,
        tools: Optional[List[Callable]] = None,
        shield: Optional[Shield] = None,
        memory: Optional[ClayMemory] = None,
        policy: Optional[Policy] = None,
        trust: str = "untrusted",
    ):
        self.name = name
        self.llm_caller = llm_caller
        self.tools = tools or []
        self.trust = trust

        # Shield resolution
        if not shield:
            self.shield = Shield.strict() if trust == "untrusted" else Shield.balanced()
        else:
            self.shield = shield

        self.memory = memory
        self.policy = policy

        # Runtime
        if policy:
            self.runtime = ClayRuntime(policy=policy)
        else:
            self.runtime = ClayRuntime(policy=self.shield)

        # Internal state
        self._task_queue: queue.Queue = queue.Queue()
        self._results: List[GolemResult] = []
        self._trace_log = TraceLog()
        self._running = False
        self._paused = False
        self._thread: Optional[threading.Thread] = None
        self._task_counter = 0
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the Golem's event loop in a background thread."""
        if self._running:
            return
        self._running = True
        self._paused = False
        self._thread = threading.Thread(target=self._event_loop, daemon=True, name=f"golem-{self.name}")
        self._thread.start()

    def stop(self) -> None:
        """Gracefully stop the Golem. Processes remaining queued tasks first."""
        self._running = False
        self._paused = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=10)
        self._thread = None

    def pause(self) -> None:
        """Pause task processing. Queued tasks are preserved."""
        self._paused = True

    def resume(self) -> None:
        """Resume task processing after a pause."""
        self._paused = False

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def is_paused(self) -> bool:
        return self._paused

    # ------------------------------------------------------------------
    # Task submission
    # ------------------------------------------------------------------

    def submit(self, task: str, context: str = "") -> int:
        """
        Submit a task to the Golem's queue. Returns the task index.

        The task will be processed when the Golem's event loop picks it up.
        """
        with self._lock:
            self._task_counter += 1
            idx = self._task_counter
        self._task_queue.put((idx, task, context))
        return idx

    # ------------------------------------------------------------------
    # Results
    # ------------------------------------------------------------------

    def collect(self) -> List[GolemResult]:
        """Return all completed results so far."""
        with self._lock:
            return list(self._results)

    @property
    def trace_log(self) -> TraceLog:
        """Full trace log across the Golem's lifetime."""
        return self._trace_log

    @property
    def results_count(self) -> int:
        with self._lock:
            return len(self._results)

    # ------------------------------------------------------------------
    # Synchronous single-task execution (for non-threaded use)
    # ------------------------------------------------------------------

    def run(self, task: str, context: str = "") -> GolemResult:
        """
        Execute a single task synchronously (without the event loop).
        Useful for one-off invocations while retaining Golem's memory
        and trace log.
        """
        with self._lock:
            self._task_counter += 1
            idx = self._task_counter
        result = self._execute_task(idx, task, context)
        return result

    # ------------------------------------------------------------------
    # Internal event loop
    # ------------------------------------------------------------------

    def _event_loop(self) -> None:
        """Background event loop that processes the task queue."""
        while self._running:
            if self._paused:
                time.sleep(0.05)
                continue

            try:
                idx, task, context = self._task_queue.get(timeout=0.1)
            except queue.Empty:
                continue

            self._execute_task(idx, task, context)
            self._task_queue.task_done()

    def _execute_task(self, idx: int, task: str, context: str = "") -> GolemResult:
        """Execute a single task through the shielded runtime."""
        # Memory recall
        retrieved_context = ""
        if self.memory:
            safe_results = self.memory.recall(task)
            if safe_results:
                retrieved_context = "\n".join(str(r) for r in safe_results)

        full_context = context
        if retrieved_context:
            full_context = f"{context}\n\n[Golem Memory]\n{retrieved_context}"

        # Shielded execution
        def _bound_llm(text: str):
            return self.llm_caller(text, context=full_context)

        clay_result = self.runtime.run(_bound_llm, task, context=full_context)

        # Memory save
        if not clay_result.blocked and self.memory and clay_result.output is not None:
            self.memory.save({
                "input": task,
                "output": clay_result.output,
                "golem": self.name,
            })

        # Trace log
        if clay_result.trace:
            clay_result.trace.source = self.name
            self._trace_log.append(clay_result.trace)

        golem_result = GolemResult(task=task, result=clay_result, index=idx)

        with self._lock:
            self._results.append(golem_result)

        return golem_result
