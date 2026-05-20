from __future__ import annotations

import os
import time
from pathlib import Path


class FileSemaphore:
    def __init__(self, slots_dir: Path, max_concurrency: int, wait_seconds: int = 1) -> None:
        self.slots_dir = Path(slots_dir)
        self.max_concurrency = max(1, int(max_concurrency))
        self.wait_seconds = max(1, int(wait_seconds))
        self.slot_path: Path | None = None

    def acquire(self) -> Path:
        self.slots_dir.mkdir(parents=True, exist_ok=True)
        while True:
            for idx in range(self.max_concurrency):
                slot = self.slots_dir / f'slot_{idx}.lock'
                try:
                    fd = os.open(str(slot), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                    with os.fdopen(fd, 'w', encoding='utf-8') as fp:
                        fp.write(str(os.getpid()))
                    self.slot_path = slot
                    return slot
                except FileExistsError:
                    continue
            time.sleep(self.wait_seconds)

    def release(self) -> None:
        if self.slot_path and self.slot_path.exists():
            try:
                self.slot_path.unlink()
            except Exception:
                pass
            self.slot_path = None

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.release()
        return False
