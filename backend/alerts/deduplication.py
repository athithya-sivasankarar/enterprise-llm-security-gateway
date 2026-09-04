import hashlib
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.db.models import SecurityAlertModel


def compute_alert_fingerprint(
    campaign_id: str,
    alert_type: str,
    qualifier: str = "",
    policy_version: str = "1.0.0"
) -> str:
    """
    Compute a deterministic fingerprint from safe metadata only to prevent alert fatigue.
    Never includes raw prompts, model outputs, secrets, API keys, or real PII.
    """
    raw_str = f"{campaign_id}:{alert_type}:{qualifier}:{policy_version}"
    return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()[:16]


async def has_active_alert(
    db: AsyncSession,
    campaign_id: str,
    alert_type: str,
    title: str
) -> bool:
    """
    Check if an active (OPEN or ACKNOWLEDGED) alert with the same title already exists for this campaign.
    """
    stmt = (
        select(SecurityAlertModel)
        .where(
            SecurityAlertModel.campaign_id == campaign_id,
            SecurityAlertModel.alert_type == alert_type,
            SecurityAlertModel.title == title,
            SecurityAlertModel.status.in_(["OPEN", "ACKNOWLEDGED"])
        )
    )
    res = await db.execute(stmt)
    return res.scalar_one_or_none() is not None
