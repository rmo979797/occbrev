"""Single-table data model for the isolated waitlist deployment.

The marketplace's full ORM (users, suppliers, bookings, etc.) is intentionally
NOT imported here so a compromise of this box can't leak anything beyond
waitlist signups. If the waitlist server is breached, the attacker gets:
emails + business names + IP/UA strings. Nothing else.
"""
from datetime import datetime
from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, Index, String, Text

from database import Base


def _uuid() -> str:
    return str(uuid4())


class WaitlistSignup(Base):
    __tablename__ = "waitlist_signups"
    # Composite unique on (role, email) — the same person can join the
    # supplier AND the future customer list, but not the same role twice.
    # Declared at the model level (not only the migration) so SQLAlchemy
    # creates the index for in-memory test DBs too.
    __table_args__ = (
        Index("uq_waitlist_role_email", "role", "email", unique=True),
    )

    id = Column(String, primary_key=True, default=_uuid)
    # 'supplier' today; column is kept for future customer use.
    role = Column(String, nullable=False, index=True)
    email = Column(String, nullable=False, index=True)
    business_name = Column(String, nullable=True)
    category = Column(String, nullable=True)
    # Free-text label captured when category == "other". Stored verbatim
    # (after server-side trim/length cap) so we can review and decide
    # whether to add that category as a first-class option later.
    category_other = Column(String, nullable=True)
    service_area = Column(String, nullable=True)
    instagram_handle = Column(String, nullable=True)
    feedback = Column(Text, nullable=True)
    event_types = Column(String, nullable=True)  # reserved for customer flow
    ready_to_onboard = Column(Boolean, default=False)
    # Provenance for moderation only — never displayed, never shared.
    ip = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    # Lifecycle: pending → invited → converted | rejected.
    status = Column(String, default="pending", nullable=False, index=True)
    invited_at = Column(DateTime, nullable=True)
    # Standalone deployment: no users table to FK against, so this is a free
    # text column. Once a waitlist signup is converted, we record the user id
    # of the main-app account that consumed it.
    converted_user_id = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
