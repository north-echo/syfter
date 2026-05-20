"""
Alembic environment configuration.

Reads database URL from SYFTER_* environment variables (same as the server).
"""

import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Add project root to path so we can import server modules
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from server.db.models import Base

# Alembic Config object
config = context.config

# Set up logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# SQLAlchemy MetaData for autogenerate
target_metadata = Base.metadata


def get_url():
    """Build database URL from environment variables."""
    db_type = os.getenv("SYFTER_DB_TYPE", "sqlite")
    if db_type == "postgresql":
        user = os.getenv("SYFTER_PG_USER", "syfter")
        password = os.getenv("SYFTER_PG_PASSWORD", "")
        host = os.getenv("SYFTER_PG_HOST", "localhost")
        port = os.getenv("SYFTER_PG_PORT", "5432")
        database = os.getenv("SYFTER_PG_DATABASE", "syfter")
        return f"postgresql://{user}:{password}@{host}:{port}/{database}"
    else:
        path = os.getenv("SYFTER_SQLITE_PATH", "~/.syfter/syfter.db")
        path = os.path.expanduser(path)
        return f"sqlite:///{path}"


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (generate SQL without connecting)."""
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode (connect to database)."""
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = get_url()

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
