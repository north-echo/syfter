"""Initial schema — baseline for syfter 0.9.1.0

Revision ID: 001
Revises: None
Create Date: 2026-04-01

This migration represents the full schema as of syfter 0.9.1.0.
Tables: products, systems, scans, image_layers, packages, files, api_keys.

For existing databases: stamp with `alembic stamp 001` to mark as current
without running the migration.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Products
    op.create_table(
        "products",
        sa.Column("id", sa.Integer(), autoincrement=True, primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("version", sa.String(100), nullable=False),
        sa.Column("vendor", sa.String(255), server_default="Red Hat"),
        sa.Column("cpe_vendor", sa.String(100), server_default="redhat"),
        sa.Column("cpe_product", sa.String(255), nullable=True),
        sa.Column("purl_namespace", sa.String(100), server_default="redhat"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("name", "version", name="uq_product_name_version"),
    )

    # Systems
    op.create_table(
        "systems",
        sa.Column("id", sa.Integer(), autoincrement=True, primary_key=True),
        sa.Column("hostname", sa.String(255), nullable=False, unique=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("tag", sa.String(255), nullable=True),
        sa.Column("os_name", sa.String(255), nullable=True),
        sa.Column("os_version", sa.String(100), nullable=True),
        sa.Column("arch", sa.String(50), nullable=True),
        sa.Column("last_scan_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )
    op.create_index("idx_system_hostname", "systems", ["hostname"])
    op.create_index("idx_system_tag", "systems", ["tag"])
    op.create_index("idx_system_ip", "systems", ["ip_address"])

    # Scans
    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), autoincrement=True, primary_key=True),
        sa.Column("product_id", sa.Integer(), sa.ForeignKey("products.id"), nullable=True),
        sa.Column("system_id", sa.Integer(), sa.ForeignKey("systems.id"), nullable=True),
        sa.Column("source_path", sa.Text(), nullable=False),
        sa.Column("source_type", sa.String(50), server_default="directory"),
        sa.Column("scan_timestamp", sa.DateTime(), nullable=True),
        sa.Column("syft_version", sa.String(50), nullable=True),
        sa.Column("scan_label", sa.String(100), nullable=True),
        sa.Column("image_id", sa.String(100), nullable=True),
        sa.Column("image_layers_json", sa.Text(), nullable=True),
        sa.Column("original_sbom_key", sa.String(500), nullable=False),
        sa.Column("modified_sbom_key", sa.String(500), nullable=False),
        sa.Column("package_count", sa.Integer(), server_default="0"),
        sa.Column("file_count", sa.Integer(), server_default="0"),
        sa.Column("original_size_bytes", sa.Integer(), server_default="0"),
        sa.Column("modified_size_bytes", sa.Integer(), server_default="0"),
    )
    op.create_index("idx_scan_product", "scans", ["product_id"])
    op.create_index("idx_scan_system", "scans", ["system_id"])
    op.create_index("idx_scan_timestamp", "scans", ["scan_timestamp"])

    # Image Layers
    op.create_table(
        "image_layers",
        sa.Column("id", sa.Integer(), autoincrement=True, primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("layer_id", sa.String(100), nullable=False),
        sa.Column("layer_index", sa.Integer(), nullable=False),
        sa.Column("source_image", sa.String(500), nullable=True),
    )
    op.create_index("idx_image_layer_scan", "image_layers", ["scan_id"])
    op.create_index("idx_image_layer_id", "image_layers", ["layer_id"])
    op.create_unique_constraint("uq_scan_layer", "image_layers", ["scan_id", "layer_id"])

    # Packages
    op.create_table(
        "packages",
        sa.Column("id", sa.Integer(), autoincrement=True, primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("product_id", sa.Integer(), sa.ForeignKey("products.id"), nullable=True),
        sa.Column("system_id", sa.Integer(), sa.ForeignKey("systems.id"), nullable=True),
        sa.Column("name", sa.String(500), nullable=False),
        sa.Column("version", sa.String(200), nullable=True),
        sa.Column("release", sa.String(200), nullable=True),
        sa.Column("arch", sa.String(50), nullable=True),
        sa.Column("epoch", sa.String(20), nullable=True),
        sa.Column("source_rpm", sa.String(500), nullable=True),
        sa.Column("license", sa.Text(), nullable=True),
        sa.Column("purl", sa.String(1000), nullable=True),
        sa.Column("cpes", sa.Text(), nullable=True),
        sa.Column("layer_id", sa.String(100), nullable=True),
        sa.Column("layer_index", sa.Integer(), nullable=True),
        sa.Column("source_image", sa.String(500), nullable=True),
    )
    op.create_index("idx_package_name", "packages", ["name"])
    op.create_index("idx_package_product", "packages", ["product_id"])
    op.create_index("idx_package_system", "packages", ["system_id"])
    op.create_index("idx_package_purl", "packages", ["purl"])
    op.create_index("idx_package_scan", "packages", ["scan_id"])
    op.create_index("idx_package_layer", "packages", ["layer_id"])
    op.create_index("idx_package_source_image", "packages", ["source_image"])

    # Files
    op.create_table(
        "files",
        sa.Column("id", sa.Integer(), autoincrement=True, primary_key=True),
        sa.Column("package_id", sa.Integer(), sa.ForeignKey("packages.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("product_id", sa.Integer(), sa.ForeignKey("products.id"), nullable=True),
        sa.Column("system_id", sa.Integer(), sa.ForeignKey("systems.id"), nullable=True),
        sa.Column("path", sa.String(1000), nullable=False),
        sa.Column("digest", sa.String(200), nullable=True),
        sa.Column("digest_algorithm", sa.String(20), server_default="sha256"),
    )
    op.create_index("idx_file_path", "files", ["path"])
    op.create_index("idx_file_product", "files", ["product_id"])
    op.create_index("idx_file_system", "files", ["system_id"])
    op.create_index("idx_file_digest", "files", ["digest"])
    op.create_index("idx_file_scan", "files", ["scan_id"])

    # API Keys
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Integer(), autoincrement=True, primary_key=True),
        sa.Column("key_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("key_prefix", sa.String(8), nullable=False),
        sa.Column("team_name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default="true"),
        sa.Column("is_admin", sa.Boolean(), server_default="false"),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
    )
    op.create_index("idx_apikey_hash", "api_keys", ["key_hash"])
    op.create_index("idx_apikey_team", "api_keys", ["team_name"])


def downgrade() -> None:
    op.drop_table("api_keys")
    op.drop_table("files")
    op.drop_table("packages")
    op.drop_table("image_layers")
    op.drop_table("scans")
    op.drop_table("systems")
    op.drop_table("products")
