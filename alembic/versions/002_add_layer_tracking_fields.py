"""Add is_base and command fields to image_layers for container layer tracking

Revision ID: 002
Revises: 001
Create Date: 2026-04-01

Adds is_base (boolean) to distinguish base image layers from app layers,
and command (text) to store the Dockerfile instruction that created the layer.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("image_layers", sa.Column("is_base", sa.Boolean(), server_default="false"))
    op.add_column("image_layers", sa.Column("command", sa.Text(), nullable=True))
    op.create_index("idx_image_layer_base", "image_layers", ["is_base"])


def downgrade() -> None:
    op.drop_index("idx_image_layer_base", table_name="image_layers")
    op.drop_column("image_layers", "command")
    op.drop_column("image_layers", "is_base")
