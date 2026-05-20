"""Add dependencies and component_relationships tables

Revision ID: 003
Revises: 002
Create Date: 2026-04-30

Adds dependency tracking (RPM requires/provides) and product-to-product
component relationships for provenance chain queries.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "dependencies",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("package_id", sa.Integer(), sa.ForeignKey("packages.id", ondelete="CASCADE"), nullable=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("product_id", sa.Integer(), sa.ForeignKey("products.id"), nullable=True),
        sa.Column("dependency_name", sa.Text(), nullable=False),
        sa.Column("dependency_version", sa.Text(), nullable=True),
        sa.Column("dependency_flags", sa.String(10), nullable=True),
        sa.Column("dependency_type", sa.String(20), nullable=False),
    )
    op.create_index("idx_dep_package", "dependencies", ["package_id"])
    op.create_index("idx_dep_name", "dependencies", ["dependency_name"])
    op.create_index("idx_dep_scan", "dependencies", ["scan_id"])
    op.create_index("idx_dep_product", "dependencies", ["product_id"])
    op.create_index("idx_dep_type", "dependencies", ["dependency_type"])

    op.create_table(
        "component_relationships",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("parent_product_id", sa.Integer(), sa.ForeignKey("products.id"), nullable=False),
        sa.Column("component_product_id", sa.Integer(), sa.ForeignKey("products.id"), nullable=False),
        sa.Column("relationship_type", sa.String(50), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_index("idx_cr_parent", "component_relationships", ["parent_product_id"])
    op.create_index("idx_cr_component", "component_relationships", ["component_product_id"])
    op.create_unique_constraint("uq_parent_component", "component_relationships", ["parent_product_id", "component_product_id"])


def downgrade() -> None:
    op.drop_table("component_relationships")
    op.drop_table("dependencies")
