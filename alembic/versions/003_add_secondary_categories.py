"""add secondary_categories column to waitlist_signups.

Suppliers often work across more than one category (a florist who also
styles tablescapes, a cake maker who also runs a dessert table). The
form lets them pick a primary plus up to two secondaries. Stored as a
comma-joined ASCII slug string — keeps the schema simple, no array
type, no JSON field, and trivially queryable with LIKE for admin
filtering.

Old rows pre-dating this column simply have NULL, which the route
treats as "no secondaries".

Revision ID: 003_secondary_cats
Revises: 002_category_other
Create Date: 2026-06-17 09:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "003_secondary_cats"
down_revision: Union[str, Sequence[str], None] = "002_category_other"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "waitlist_signups",
        sa.Column("secondary_categories", sa.String(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("waitlist_signups", "secondary_categories")
