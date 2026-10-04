"""Shared bounds and cancellation primitives for opt-in federation operations.

These primitives are deliberately independent from the legacy interactive paths.  A
caller must opt into a bounded operation explicitly; existing HackBot behaviour is
unchanged.
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Dict


class BoundedOperationError(RuntimeError):
    """Base class for a bounded-operation failure safe to expose to callers."""


class OperationCancelled(BoundedOperationError):
    """Raised when an operation's cancellation token is set."""


class OperationDeadlineExceeded(BoundedOperationError):
    """Raised when a bounded operation exceeds its wall-clock deadline."""


class OperationLimitExceeded(BoundedOperationError):
    """Raised when input or output crosses an enforced hard limit."""


class CancellationToken:
    """Thread-safe cooperative cancellation token with close callbacks.

    Network operations can register a callback that closes their private client or
    session.  That makes cancellation prompt in the common case while the operation's
    finite I/O timeout remains the final backstop.
    """

    def __init__(self) -> None:
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._callbacks: Dict[int, Callable[[], None]] = {}
        self._next_callback = 0

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def wait(self, timeout: float) -> bool:
        return self._event.wait(timeout)

    def cancel(self) -> None:
        """Set cancellation and invoke registered close callbacks once."""
        with self._lock:
            if self._event.is_set():
                return
            self._event.set()
            callbacks = list(self._callbacks.values())
            self._callbacks.clear()
        for callback in callbacks:
            try:
                callback()
            except Exception:
                # Cancellation must never leak client-specific close errors.
                pass

    def add_callback(self, callback: Callable[[], None]) -> int:
        """Register a close callback and return a handle for later removal."""
        with self._lock:
            if self._event.is_set():
                run_now = True
                handle = -1
            else:
                run_now = False
                handle = self._next_callback
                self._next_callback += 1
                self._callbacks[handle] = callback
        if run_now:
            try:
                callback()
            except Exception:
                pass
        return handle

    def remove_callback(self, handle: int) -> None:
        if handle < 0:
            return
        with self._lock:
            self._callbacks.pop(handle, None)

    def raise_if_cancelled(self) -> None:
        if self.cancelled:
            raise OperationCancelled("operation cancelled")


class Deadline:
    """Monotonic wall-clock deadline shared by every stage of an operation."""

    def __init__(self, seconds: float) -> None:
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or seconds <= 0:
            raise ValueError("deadline must be a positive number")
        self.started = time.monotonic()
        self.ends = self.started + float(seconds)

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started

    def remaining(self, token: CancellationToken) -> float:
        token.raise_if_cancelled()
        remaining = self.ends - time.monotonic()
        if remaining <= 0:
            raise OperationDeadlineExceeded("operation deadline exceeded")
        return remaining

