import os
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from backend.db.database import AsyncSessionLocal
from backend.scheduler.engine import get_due_schedules, execute_scheduled_campaign

logger = logging.getLogger(__name__)

SCHEDULER_ENABLED = os.getenv("SCHEDULER_ENABLED", "false").lower() in ("true", "1", "yes")
SCHEDULER_POLL_INTERVAL_SECONDS = int(os.getenv("SCHEDULER_POLL_INTERVAL_SECONDS", "30"))
SCHEDULER_MAX_CONCURRENT_CAMPAIGNS = int(os.getenv("SCHEDULER_MAX_CONCURRENT_CAMPAIGNS", "2"))

_worker_task: Optional[asyncio.Task] = None
_worker_running: bool = False
_last_poll_at: Optional[datetime] = None


async def _scheduler_loop():
    global _worker_running, _last_poll_at
    _worker_running = True
    semaphore = asyncio.Semaphore(SCHEDULER_MAX_CONCURRENT_CAMPAIGNS)
    logger.info(
        f"Started Security Campaign Scheduler Worker (poll interval: {SCHEDULER_POLL_INTERVAL_SECONDS}s, "
        f"max concurrent: {SCHEDULER_MAX_CONCURRENT_CAMPAIGNS})"
    )

    while _worker_running:
        try:
            _last_poll_at = datetime.now(timezone.utc)
            async with AsyncSessionLocal() as session:
                due_schedules = await get_due_schedules(session, as_of=_last_poll_at)
                try:
                    from backend.services.governance_service import check_and_expire_exceptions
                    await check_and_expire_exceptions(session, now=_last_poll_at)
                except Exception as ge:
                    logger.debug(f"Governance expiration check error: {ge}")

            if due_schedules:
                logger.info(f"Found {len(due_schedules)} due security campaign schedule(s).")
                for sched in due_schedules:
                    if not _worker_running:
                        break

                    async def _run_with_sem(s_id):
                        async with semaphore:
                            await execute_scheduled_campaign(s_id)

                    asyncio.create_task(_run_with_sem(sched.schedule_id))

        except asyncio.CancelledError:
            logger.info("Scheduler worker task was cancelled.")
            break
        except Exception as e:
            logger.error(f"Unexpected error in scheduler worker loop: {e}", exc_info=True)

        try:
            await asyncio.sleep(SCHEDULER_POLL_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            break

    _worker_running = False
    logger.info("Security Campaign Scheduler Worker loop has stopped.")


def start_scheduler_worker() -> Optional[asyncio.Task]:
    global _worker_task
    if not SCHEDULER_ENABLED:
        logger.info("Security Campaign Scheduler Worker is disabled via SCHEDULER_ENABLED=false.")
        return None

    if _worker_task is None or _worker_task.done():
        _worker_task = asyncio.create_task(_scheduler_loop())
        logger.info("Spawned background scheduler worker task.")
    return _worker_task


async def stop_scheduler_worker():
    global _worker_task, _worker_running
    _worker_running = False
    if _worker_task and not _worker_task.done():
        _worker_task.cancel()
        try:
            await _worker_task
        except asyncio.CancelledError:
            pass
        logger.info("Stopped background scheduler worker task.")


def get_worker_status() -> dict:
    return {
        "scheduler_enabled": SCHEDULER_ENABLED,
        "worker_running": _worker_running,
        "poll_interval_seconds": SCHEDULER_POLL_INTERVAL_SECONDS,
        "max_concurrent": SCHEDULER_MAX_CONCURRENT_CAMPAIGNS,
        "last_poll_at": _last_poll_at
    }
