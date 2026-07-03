from __future__ import annotations

import os
import time
from pathlib import Path


class WaitingFileSemaphore:
    def __init__(
        self,
        lock_dir: Path,
        *,
        limit: int,
        wait_seconds: int = 1800,
        poll_seconds: int = 2,
        stale_lock_seconds: int = 7200,
    ) -> None:
        if limit <= 0:
            raise ValueError("limit must be greater than zero")
        self.lock_dir = lock_dir
        self.limit = limit
        self.wait_seconds = wait_seconds
        self.poll_seconds = poll_seconds
        self.stale_lock_seconds = stale_lock_seconds
        self.acquired_path: Path | None = None

    def __enter__(self) -> "WaitingFileSemaphore":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()

    def acquire(self) -> Path:
        self.lock_dir.mkdir(parents=True, exist_ok=True)
        deadline = time.time() + self.wait_seconds

        while True:
            self._cleanup_stale_locks()
            for slot in range(self.limit):
                candidate = self.lock_dir / f"slot-{slot}.lock"
                try:
                    fd = os.open(str(candidate), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                except FileExistsError:
                    continue
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(f"pid={os.getpid()}\ncreated_at={int(time.time())}\n")
                self.acquired_path = candidate
                return candidate

            if time.time() >= deadline:
                raise TimeoutError("semaphore wait timed out")
            time.sleep(self.poll_seconds)

    def release(self) -> None:
        if self.acquired_path is None:
            return
        try:
            self.acquired_path.unlink(missing_ok=True)
        finally:
            self.acquired_path = None

    def _cleanup_stale_locks(self) -> None:
        now = time.time()
        for lock_path in self.lock_dir.glob("*.lock"):
            try:
                age = now - lock_path.stat().st_mtime
            except FileNotFoundError:
                continue
            if age > self.stale_lock_seconds:
                lock_path.unlink(missing_ok=True)
