"""initial — waitlist_signups table.

Standalone, no foreign keys to a users table (this deployment doesn't have one).

Revision ID: 001_initial
Revises:
Create Date: 2026-06-14 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "001_initial"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "waitlist_signups",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("role", sa.String(), nullable=False),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("business_name", sa.String(), nullable=True),
        sa.Column("category", sa.String(), nullable=True),
        sa.Column("service_area", sa.String(), nullable=True),
        sa.Column("instagram_handle", sa.String(), nullable=True),
        sa.Column("feedback", sa.Text(), nullable=True),
        sa.Column("event_types", sa.String(), nullable=True),
        sa.Column("ready_to_onboard", sa.Boolean(), server_default=sa.false()),
        sa.Column("ip", sa.String(), nullable=True),
        sa.Column("user_agent", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="pending"),
        sa.Column("invited_at", sa.DateTime(), nullable=True),
        sa.Column("converted_user_id", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_waitlist_signups_role", "waitlist_signups", ["role"])
    op.create_index("ix_waitlist_signups_email", "waitlist_signups", ["email"])
    op.create_index("ix_waitlist_signups_status", "waitlist_signups", ["status"])
    # Composite unique: same email can be on supplier AND customer list, but
    # not the same role twice. Stops drive-by duplicates without leaking
    # "this email is already on the list" via the response.
    op.create_index(
        "uq_waitlist_role_email",
        "waitlist_signups",
        ["role", "email"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("uq_waitlist_role_email", table_name="waitlist_signups")
    op.drop_index("ix_waitlist_signups_status", table_name="waitlist_signups")
    op.drop_index("ix_waitlist_signups_email", table_name="waitlist_signups")
    op.drop_index("ix_waitlist_signups_role", table_name="waitlist_signups")
    op.drop_table("waitlist_signups")
