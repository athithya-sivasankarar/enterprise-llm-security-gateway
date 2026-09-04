from datetime import datetime
from typing import Optional, List
from enum import Enum
from pydantic import BaseModel, Field


class ScheduleType(str, Enum):
    __test__ = False
    INTERVAL = "INTERVAL"
    CRON = "CRON"


class ScheduleCreateRequest(BaseModel):
    schedule_type: str = Field(default="INTERVAL", description="INTERVAL or CRON")
    interval_minutes: Optional[int] = Field(default=1440, description="Minimum 60 minutes for INTERVAL")
    cron_expression: Optional[str] = Field(default=None, description="Standard 5-part cron expression")
    timezone: Optional[str] = Field(default="UTC", description="Timezone for schedule calculation")
    enabled: Optional[bool] = Field(default=True)


class ScheduleUpdateRequest(BaseModel):
    enabled: Optional[bool] = None
    schedule_type: Optional[str] = None
    interval_minutes: Optional[int] = None
    cron_expression: Optional[str] = None
    timezone: Optional[str] = None


class ScheduleSummary(BaseModel):
    schedule_id: str
    campaign_id: str
    enabled: bool
    schedule_type: str
    cron_expression: Optional[str] = None
    interval_minutes: Optional[int] = None
    timezone: str = "UTC"
    next_run_at: Optional[datetime] = None
    last_run_at: Optional[datetime] = None
    last_run_status: Optional[str] = None
    last_error: Optional[str] = None
    created_by: str
    created_at: datetime
    updated_at: datetime


class SchedulerStatus(BaseModel):
    scheduler_enabled: bool
    worker_running: bool
    poll_interval_seconds: int
    total_schedules: int
    enabled_schedules: int
    last_poll_at: Optional[datetime] = None


class NextRunEstimate(BaseModel):
    schedule_id: str
    campaign_id: str
    next_run_at: Optional[datetime] = None
    seconds_until_run: Optional[int] = None
