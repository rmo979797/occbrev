"""add category_other column to waitlist_signups.

Captures the free-text label users type when they pick "Other" in the
category dropdown. Nullable, no default — old rows simply have NULL.

Revision ID: 002_category_other
Revises: 001_initial
Create Date: 2026-06-14 22:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "002_category_other"
down_revision: Union[str, Sequence[str], None] = "001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "waitlist_signups",
        sa.Column("category_other", sa.String(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("waitlist_signups", "category_other")
