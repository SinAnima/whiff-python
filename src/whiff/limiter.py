"""Process-wide semaphore around native extraction.

Waiters are served in FIFO order. A waiter that does not get a slot within
``native_wait_ms`` raises :class:`~whiff.errors.OverloadedError`. A slot held
by a thread is released when that thread leaves the ``with`` block, including
on exception. A native ``file_timeout`` can still leave a Rust worker running
after the call returns; this limiter cannot stop it.
"""

from __future__ import annotations

import threading
from collections import deque
from types import TracebackType

from whiff.errors import InvalidOptionError, OverloadedError

_DEFAULT_MAX = 8
_DEFAULT_WAIT_MS = 60_000


class _Ticket:
    def __init__(self) -> None:
        self.event = threading.Event()
        self.granted = False


class Limiter:
    def __init__(
        self, max_concurrency: int = _DEFAULT_MAX, wait_ms: int = _DEFAULT_WAIT_MS
    ) -> None:
        self._max = max_concurrency
        self._wait_ms = wait_ms
        self._held = 0
        self._waiters: deque[_Ticket] = deque()
        self._lock = threading.Lock()

    def configure(self, *, max_concurrency: int | None = None, wait_ms: int | None = None) -> None:
        with self._lock:
            if self._held or self._waiters:
                raise InvalidOptionError(
                    "cannot reconfigure the native limiter while calls are in flight"
                )
            if max_concurrency is not None:
                if isinstance(max_concurrency, bool) or not isinstance(max_concurrency, int):
                    raise InvalidOptionError("native_max_concurrency must be an integer in 1..128")
                if not 1 <= max_concurrency <= 128:
                    raise InvalidOptionError("native_max_concurrency must be an integer in 1..128")
                self._max = max_concurrency
            if wait_ms is not None:
                if isinstance(wait_ms, bool) or not isinstance(wait_ms, int):
                    raise InvalidOptionError("native_wait_ms must be an integer in 1..3600000")
                if not 1 <= wait_ms <= 3_600_000:
                    raise InvalidOptionError("native_wait_ms must be an integer in 1..3600000")
                self._wait_ms = wait_ms

    def slot(self) -> _Hold:
        return _Hold(self)

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "current": self._held,
                "max": self._max,
                "waiting": len(self._waiters),
                "wait_ms": self._wait_ms,
            }

    def _acquire(self) -> None:
        ticket: _Ticket | None = None
        with self._lock:
            if self._held < self._max and not self._waiters:
                self._held += 1
                return
            ticket = _Ticket()
            self._waiters.append(ticket)
            wait_s = self._wait_ms / 1000
            max_slots = self._max
            wait_ms = self._wait_ms
        assert ticket is not None
        if ticket.event.wait(wait_s):
            return
        with self._lock:
            if ticket.granted:
                # Won the race with a release that granted the slot as we timed out.
                return
            try:
                self._waiters.remove(ticket)
            except ValueError:
                pass
        raise OverloadedError(
            f"no native slot within {wait_ms}ms",
            details={"max": max_slots, "wait_ms": wait_ms},
        )

    def _release(self) -> None:
        with self._lock:
            while self._waiters:
                ticket = self._waiters.popleft()
                ticket.granted = True
                ticket.event.set()
                return
            if self._held:
                self._held -= 1


class _Hold:
    def __init__(self, limiter: Limiter) -> None:
        self._limiter = limiter

    def __enter__(self) -> None:
        self._limiter._acquire()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._limiter._release()


LIMITER = Limiter()
