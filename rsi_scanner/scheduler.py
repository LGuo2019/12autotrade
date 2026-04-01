from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Callable

from .constants import SECONDS_PER_2H

logger = logging.getLogger("rsi_scanner.scheduler")
StateCallback = Callable[[str, datetime, int], None]


def next_run_at(now: datetime) -> datetime:
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    hour_block = (now.hour // 2) * 2
    base = now.replace(hour=hour_block, minute=1, second=0, microsecond=0)
    if now <= base:
        return base
    return base + timedelta(hours=2)


def latest_run_at(now: datetime) -> datetime:
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    hour_block = (now.hour // 2) * 2
    base = now.replace(hour=hour_block, minute=1, second=0, microsecond=0)
    if now >= base:
        return base
    return base - timedelta(hours=2)


def sleep_until(target: datetime, on_wait: StateCallback | None = None) -> None:
    while True:
        now = datetime.now(timezone.utc)
        delay = max(0, int((target - now).total_seconds()))
        if delay <= 0:
            return
        if on_wait is not None:
            on_wait("waiting", target, delay)
        logger.info(
            "scheduler_waiting next_run_utc=%s wait_seconds=%d",
            target.strftime("%Y-%m-%d %H:%M:%S"),
            delay,
        )
        time.sleep(min(delay, 30))


def run_every_2h(task: Callable[[], None], on_wait: StateCallback | None = None) -> None:
    logger.info("scheduler_started cadence=2h trigger_minute=01 timezone=UTC")
    last_run: datetime | None = None
    while True:
        now = datetime.now(timezone.utc)
        # Catch up exactly one missed slot when process restarts or wakes up late.
        due = latest_run_at(now)
        if last_run is None:
            if now > due:
                logger.info("scheduler_catchup run_at_utc=%s", due.strftime("%Y-%m-%d %H:%M:%S"))
                try:
                    task()
                except Exception:
                    logger.exception("scheduler_task_failed")
                last_run = due
                continue
        else:
            expected_next = last_run + timedelta(hours=2)
            if now > expected_next:
                logger.info("scheduler_catchup run_at_utc=%s", expected_next.strftime("%Y-%m-%d %H:%M:%S"))
                try:
                    task()
                except Exception:
                    logger.exception("scheduler_task_failed")
                last_run = expected_next
                continue

        run_at = next_run_at(now if last_run is None else max(now, last_run))
        sleep_until(run_at, on_wait=on_wait)
        logger.info("scheduler_trigger run_at_utc=%s", run_at.strftime("%Y-%m-%d %H:%M:%S"))
        try:
            task()
        except Exception:
            logger.exception("scheduler_task_failed")
        last_run = run_at
