"""
Scan API endpoints.
"""

import gzip
import io
import json
import logging
import time
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session

from ..config import get_config
from ..db import get_db, Product, Scan, Package, File as FileModel, ImageLayer, Attestation
from ..storage import get_storage
from .queries import invalidate_stats_cache
from .schemas import (
    ScanResponse,
    ScanMetadata,
    PackageCreate,
)

logger = logging.getLogger(__name__)
router = APIRouter()

# Maximum decompressed size to prevent zip bombs (4GB)
_MAX_DECOMPRESSED_SIZE = 4 * 1024 * 1024 * 1024  # 4GB for large distros like RHEL


def _safe_gzip_decompress(data: bytes, max_size: int = _MAX_DECOMPRESSED_SIZE) -> bytes:
    """
    Safely decompress gzip data with size limit to prevent decompression bombs.
    """
    decompressor = gzip.GzipFile(fileobj=io.BytesIO(data))
    chunks = []
    total_size = 0

    while True:
        chunk = decompressor.read(1024 * 1024)
        if not chunk:
            break
        total_size += len(chunk)
        if total_size > max_size:
            raise ValueError(
                f"Decompressed data ({total_size // (1024*1024)}MB so far) exceeds maximum size limit of {max_size // (1024*1024*1024)}GB"
            )
        chunks.append(chunk)

    return b''.join(chunks)


def _validate_sbom_json(data: bytes, name: str = "SBOM") -> dict:
    """
    Validate that compressed data is valid gzip JSON.

    Args:
        data: Compressed gzip data
        name: Name for error messages

    Returns:
        Parsed JSON dict

    Raises:
        HTTPException: If data is invalid
    """
    try:
        decompressed = _safe_gzip_decompress(data)
    except gzip.BadGzipFile:
        raise HTTPException(status_code=400, detail=f"Invalid {name}: not valid gzip data")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid {name}: {e}")

    try:
        return json.loads(decompressed.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid {name}: not valid JSON - {e}")
    except UnicodeDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid {name}: not valid UTF-8 - {e}")


def _generate_storage_key(product_name: str, product_version: str, scan_id: int, suffix: str) -> str:
    """Generate a storage key for an SBOM."""
    return f"{product_name}/{product_version}/{scan_id}/{suffix}"


@router.get("/", response_model=List[ScanResponse])
def list_scans(
    product_name: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    """List scans, optionally filtered by product."""
    query = (
        db.query(Scan, Product.name, Product.version)
        .join(Product, Scan.product_id == Product.id)
    )

    if product_name:
        query = query.filter(Product.name == product_name)

    query = query.order_by(Scan.scan_timestamp.desc()).offset(offset).limit(limit)
    results = query.all()

    return [
        ScanResponse(
            id=scan.id,
            product_id=scan.product_id,
            product_name=pname,
            product_version=pversion,
            source_path=scan.source_path,
            source_type=scan.source_type,
            scan_timestamp=scan.scan_timestamp,
            syft_version=scan.syft_version,
            package_count=scan.package_count,
            file_count=scan.file_count,
            original_size_bytes=scan.original_size_bytes,
            modified_size_bytes=scan.modified_size_bytes,
        )
        for scan, pname, pversion in results
    ]


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """Get a specific scan."""
    result = (
        db.query(Scan, Product.name, Product.version)
        .join(Product, Scan.product_id == Product.id)
        .filter(Scan.id == scan_id)
        .first()
    )

    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan, pname, pversion = result
    return ScanResponse(
        id=scan.id,
        product_id=scan.product_id,
        product_name=pname,
        product_version=pversion,
        source_path=scan.source_path,
        source_type=scan.source_type,
        scan_timestamp=scan.scan_timestamp,
        syft_version=scan.syft_version,
        package_count=scan.package_count,
        file_count=scan.file_count,
        original_size_bytes=scan.original_size_bytes,
        modified_size_bytes=scan.modified_size_bytes,
    )


@router.post("/upload", response_model=ScanResponse, status_code=201)
async def upload_scan(
    product_name: str = Form(...),
    product_version: str = Form(...),
    source_path: str = Form(...),
    source_type: str = Form("directory"),
    syft_version: Optional[str] = Form(None),
    original_sbom: UploadFile = File(..., description="Original syft-json SBOM (gzip compressed)"),
    modified_sbom: UploadFile = File(..., description="Modified syft-json SBOM (gzip compressed)"),
    packages_json: UploadFile = File(..., description="Package index JSON (gzip compressed)"),
    dependencies_json: Optional[UploadFile] = File(None, description="Dependency index JSON (gzip compressed)"),
    image_layers_json: Optional[UploadFile] = File(None, description="Container layer chain JSON (gzip compressed)"),
    attestation_json: Optional[UploadFile] = File(None, description="Cosign attestation data JSON (gzip compressed)"),
    db: Session = Depends(get_db),
):
    """
    Upload a complete scan with SBOMs and package index.

    All files should be gzip compressed JSON.
    If a scan already exists for this product, it will be replaced.
    """
    start_time = time.time()
    logger.info(f"Starting upload for {product_name}-{product_version}")

    storage = get_storage()

    # Get or create product
    product = (
        db.query(Product)
        .filter(Product.name == product_name, Product.version == product_version)
        .first()
    )
    if not product:
        product = Product(
            name=product_name,
            version=product_version,
            cpe_product=product_name,
        )
        db.add(product)
        db.commit()
        db.refresh(product)
    logger.info(f"Product resolved: id={product.id}")

    # Delete existing scan for this product (replace behavior)
    existing_scan = (
        db.query(Scan)
        .filter(Scan.product_id == product.id)
        .first()
    )
    if existing_scan:
        logger.info(f"Deleting existing scan {existing_scan.id}")
        delete_start = time.time()

        # Delete old SBOM and attestation files from storage
        try:
            storage.delete(existing_scan.original_sbom_key)
            storage.delete(existing_scan.modified_sbom_key)
        except Exception:
            pass
        for att in db.query(Attestation).filter(Attestation.scan_id == existing_scan.id).all():
            try:
                storage.delete(att.attestation_key)
            except Exception:
                pass

        # Use raw SQL for fast deletion (ORM is extremely slow for millions of rows)
        connection = db.connection()
        raw_conn = connection.connection.dbapi_connection
        cursor = raw_conn.cursor()

        # Check if PostgreSQL or SQLite
        is_postgres = 'psycopg' in type(raw_conn).__module__ or 'postgresql' in str(db.bind.url)
        param = '%s' if is_postgres else '?'

        # Delete in FK order: dependencies -> files -> packages -> layers/attestations -> scan
        logger.info("Deleting dependencies...")
        cursor.execute(f"DELETE FROM dependencies WHERE scan_id = {param}", (existing_scan.id,))
        raw_conn.commit()

        logger.info("Deleting files...")
        cursor.execute(f"DELETE FROM files WHERE scan_id = {param}", (existing_scan.id,))
        raw_conn.commit()
        files_time = time.time() - delete_start
        logger.info(f"Files deleted in {files_time:.1f}s")

        logger.info("Deleting packages...")
        pkg_start = time.time()
        cursor.execute(f"DELETE FROM packages WHERE scan_id = {param}", (existing_scan.id,))
        raw_conn.commit()
        logger.info(f"Packages deleted in {time.time() - pkg_start:.1f}s")

        cursor.execute(f"DELETE FROM image_layers WHERE scan_id = {param}", (existing_scan.id,))
        cursor.execute(f"DELETE FROM attestations WHERE scan_id = {param}", (existing_scan.id,))
        raw_conn.commit()

        logger.info("Deleting scan record...")
        cursor.execute(f"DELETE FROM scans WHERE id = {param}", (existing_scan.id,))
        raw_conn.commit()

        # Refresh ORM session
        db.expire_all()

        logger.info(f"Existing scan deleted in {time.time() - delete_start:.1f}s")

    # Read uploaded files
    logger.info("Reading uploaded files...")
    original_data = await original_sbom.read()
    modified_data = await modified_sbom.read()
    packages_data = await packages_json.read()
    logger.info(f"Files read: original={len(original_data)/1024/1024:.1f}MB, modified={len(modified_data)/1024/1024:.1f}MB, packages={len(packages_data)/1024:.1f}KB")

    # Validate SBOM files are proper gzip (check magic bytes, don't decompress)
    # Decompressing a truncated slice fails with EOFError for large SBOMs,
    # so we just verify the gzip magic bytes are present.
    logger.info("Validating SBOM files...")
    for label, sbom_data in [("original", original_data), ("modified", modified_data)]:
        if len(sbom_data) < 2 or sbom_data[:2] != b"\x1f\x8b":
            raise HTTPException(
                status_code=400,
                detail=f"Invalid {label} SBOM: not valid gzip data (missing magic bytes)",
            )

    # Parse packages for indexing - use streaming with size limit
    logger.info("Parsing packages JSON...")
    try:
        # Decompress with size limit
        packages_json_bytes = _safe_gzip_decompress(packages_data)
        # Free the compressed data immediately
        del packages_data

        # Parse JSON
        packages_list = json.loads(packages_json_bytes.decode("utf-8"))
        # Free the JSON bytes immediately
        del packages_json_bytes

        import gc
        gc.collect()
        logger.info(f"JSON parsed, memory cleaned up")
    except MemoryError:
        logger.error("Out of memory parsing packages JSON")
        raise HTTPException(status_code=507, detail="Server out of memory processing this upload. Try again or contact admin.")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Packages JSON too large: {e}")
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid packages JSON format: {e}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid packages JSON: {e}")

    total_files = sum(len(p.get("files", [])) for p in packages_list)
    logger.info(f"Parsed {len(packages_list)} packages with {total_files} files")

    # Read raw dependency data (defer parsing until insert time to reduce peak memory)
    _dep_compressed = None
    if dependencies_json is not None:
        logger.info("Reading dependencies JSON...")
        try:
            _dep_compressed = await dependencies_json.read()
            logger.info(f"Dependencies data read: {len(_dep_compressed)/1024:.0f}KB compressed")
        except Exception as e:
            logger.warning(f"Failed to read dependencies JSON, skipping: {e}")
            _dep_compressed = None

    # Create scan record first to get ID
    scan = Scan(
        product_id=product.id,
        source_path=source_path,
        source_type=source_type,
        syft_version=syft_version,
        original_sbom_key="",  # Will update after
        modified_sbom_key="",
        package_count=len(packages_list),
        file_count=total_files,
        original_size_bytes=len(original_data),
        modified_size_bytes=len(modified_data),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    logger.info(f"Scan record created: id={scan.id}")

    # Generate storage keys and store SBOMs
    logger.info("Storing SBOMs to object storage...")
    original_key = _generate_storage_key(product_name, product_version, scan.id, "original.json.gz")
    modified_key = _generate_storage_key(product_name, product_version, scan.id, "modified.json.gz")

    storage.put(original_key, original_data)
    storage.put(modified_key, modified_data)
    del original_data, modified_data
    logger.info("SBOMs stored and freed from memory")

    # Update scan with storage keys
    scan.original_sbom_key = original_key
    scan.modified_sbom_key = modified_key

    # Index packages and files using raw SQL for maximum performance
    logger.info("Indexing packages and files...")

    # Use raw connection for fast bulk inserts
    connection = db.connection()
    raw_conn = connection.connection.dbapi_connection

    # Check if PostgreSQL or SQLite by looking at the connection type
    is_postgres = 'psycopg' in type(raw_conn).__module__ or 'postgresql' in str(db.bind.url)

    # Insert packages and get their IDs
    packages_count = len(packages_list)
    logger.info(f"Inserting {packages_count} packages...")
    bulk_start = time.time()

    # Build package tuples
    package_tuples = [
        (
            scan.id,
            product.id,
            pkg.get("name", ""),
            pkg.get("version"),
            pkg.get("release"),
            pkg.get("arch"),
            pkg.get("epoch"),
            pkg.get("source_rpm"),
            pkg.get("license"),
            pkg.get("purl"),
            pkg.get("cpes"),
            pkg.get("layer_id"),
            pkg.get("layer_index"),
            pkg.get("source_image"),
        )
        for pkg in packages_list
    ]

    _pkg_cols = "scan_id, product_id, name, version, release, arch, epoch, source_rpm, license, purl, cpes, layer_id, layer_index, source_image"

    if is_postgres:
        from psycopg2.extras import execute_values
        cursor = raw_conn.cursor()
        execute_values(
            cursor,
            f"INSERT INTO packages ({_pkg_cols}) VALUES %s",
            package_tuples,
            page_size=1000
        )
        raw_conn.commit()
    else:
        cursor = raw_conn.cursor()
        cursor.executemany(
            f"INSERT INTO packages ({_pkg_cols}) VALUES ({','.join('?' * 14)})",
            package_tuples
        )
        raw_conn.commit()

    logger.info(f"Packages inserted in {time.time() - bulk_start:.1f}s")

    # Check if we should skip file indexing for large scans
    config = get_config()
    skip_threshold = config.skip_file_index_threshold
    skip_files = skip_threshold > 0 and total_files > skip_threshold

    if skip_files:
        logger.info(f"Skipping file indexing: {total_files} files exceeds threshold of {skip_threshold}")
        logger.info("File search will not be available for this scan, but packages are indexed")

    # Retrieve package IDs (needed for file and/or dependency insertion)
    need_pkg_ids = (not skip_files and total_files > 0) or _dep_compressed
    packages_by_key = {}
    if need_pkg_ids:
        logger.info("Retrieving package IDs...")
        cursor = raw_conn.cursor()
        cursor.execute("SELECT id, name, version, arch FROM packages WHERE scan_id = %s" if is_postgres else
                       "SELECT id, name, version, arch FROM packages WHERE scan_id = ?", (scan.id,))
        packages_by_key = {(row[1], row[2], row[3]): row[0] for row in cursor.fetchall()}

    file_count_actual = 0
    if not skip_files and total_files > 0:
        logger.info(f"Inserting {total_files} files...")
        bulk_start = time.time()

        if is_postgres:
            # Stream files directly to a temp file, then COPY - avoids holding all in memory
            import tempfile
            import os

            logger.info("Writing files to temp file for COPY...")
            with tempfile.NamedTemporaryFile(mode='w', suffix='.tsv', delete=False) as tmp:
                tmp_path = tmp.name
                for pkg in packages_list:
                    key = (pkg.get("name", ""), pkg.get("version"), pkg.get("arch"))
                    package_id = packages_by_key.get(key)
                    if package_id:
                        for f in pkg.get("files", []):
                            # Format for COPY: tab-separated, \N for NULL
                            path = f.get("path", "")
                            digest = f.get("digest")
                            algo = f.get("digest_algorithm", "sha256")

                            # Escape special chars
                            path = path.replace('\\', '\\\\').replace('\t', '\\t').replace('\n', '\\n') if path else ''
                            digest_str = digest.replace('\\', '\\\\') if digest else '\\N'
                            algo_str = algo.replace('\\', '\\\\') if algo else '\\N'

                            tmp.write(f"{package_id}\t{scan.id}\t{product.id}\t{path}\t{digest_str}\t{algo_str}\n")
                            file_count_actual += 1

                            # Log progress periodically
                            if file_count_actual % 1000000 == 0:
                                logger.info(f"Files written to temp: {file_count_actual}/{total_files}")

            logger.info(f"Temp file written: {file_count_actual} files, {os.path.getsize(tmp_path)/1024/1024:.1f}MB")

            # Free packages_list memory before COPY
            if not _dep_compressed:
                del packages_list
                import gc
                gc.collect()
                logger.info("Memory freed, starting COPY...")

            # COPY from file
            cursor = raw_conn.cursor()
            with open(tmp_path, 'r') as f:
                cursor.copy_from(
                    f,
                    'files',
                    columns=('package_id', 'scan_id', 'product_id', 'path', 'digest', 'digest_algorithm'),
                    null='\\N'
                )
            raw_conn.commit()

            # Clean up temp file
            os.unlink(tmp_path)
            logger.info(f"COPY complete")
        else:
            # SQLite - stream directly without building full list
            cursor = raw_conn.cursor()
            batch = []
            batch_size = 50000

            for pkg in packages_list:
                key = (pkg.get("name", ""), pkg.get("version"), pkg.get("arch"))
                package_id = packages_by_key.get(key)
                if package_id:
                    for f in pkg.get("files", []):
                        batch.append((
                            package_id,
                            scan.id,
                            product.id,
                            f.get("path", ""),
                            f.get("digest"),
                            f.get("digest_algorithm", "sha256"),
                        ))
                        file_count_actual += 1

                        if len(batch) >= batch_size:
                            cursor.executemany(
                                """INSERT INTO files (package_id, scan_id, product_id, path, digest, digest_algorithm)
                                   VALUES (?, ?, ?, ?, ?, ?)""",
                                batch
                            )
                            batch = []
                            if file_count_actual % 500000 == 0:
                                raw_conn.commit()
                                logger.info(f"Files progress: {file_count_actual}/{total_files}")

            # Insert remaining
            if batch:
                cursor.executemany(
                    """INSERT INTO files (package_id, scan_id, product_id, path, digest, digest_algorithm)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    batch
                )
            raw_conn.commit()

        logger.info(f"Files inserted in {time.time() - bulk_start:.1f}s")

    # Insert dependencies -- stream-decompress to avoid holding full list in memory
    dep_count = 0
    if _dep_compressed:
        logger.info("Streaming dependency inserts...")
        dep_start = time.time()
        DEP_BATCH = 10000
        cursor = raw_conn.cursor()

        if is_postgres:
            from psycopg2.extras import execute_values
            dep_sql = """INSERT INTO dependencies (package_id, scan_id, product_id, dependency_name, dependency_version, dependency_flags, dependency_type)
                         VALUES %s"""
        else:
            dep_sql = """INSERT INTO dependencies (package_id, scan_id, product_id, dependency_name, dependency_version, dependency_flags, dependency_type)
                         VALUES (?, ?, ?, ?, ?, ?, ?)"""

        try:
            dep_json_bytes = _safe_gzip_decompress(_dep_compressed)
            del _dep_compressed

            dep_text = dep_json_bytes.decode("utf-8")
            del dep_json_bytes
            import gc
            gc.collect()

            # Stream-parse JSON array one object at a time via raw_decode().
            # Avoids json.loads() which materializes 1M+ dicts (~3GB) at once.
            decoder = json.JSONDecoder()
            pos = 0
            length = len(dep_text)

            while pos < length and dep_text[pos] in ' \t\n\r':
                pos += 1
            if pos < length and dep_text[pos] == '[':
                pos += 1

            batch = []
            while pos < length:
                while pos < length and dep_text[pos] in ' \t\n\r,':
                    pos += 1
                if pos >= length or dep_text[pos] == ']':
                    break

                dep, end_pos = decoder.raw_decode(dep_text, pos)
                pos = end_pos

                pkg_key = (dep.get("package_name", ""), dep.get("package_version"), dep.get("package_arch"))
                package_id = packages_by_key.get(pkg_key)
                batch.append((
                    package_id,
                    scan.id,
                    product.id,
                    dep.get("dependency_name", ""),
                    dep.get("dependency_version"),
                    dep.get("dependency_flags"),
                    dep.get("dependency_type", "requires"),
                ))
                if len(batch) >= DEP_BATCH:
                    if is_postgres:
                        execute_values(cursor, dep_sql, batch, page_size=1000)
                    else:
                        cursor.executemany(dep_sql, batch)
                    raw_conn.commit()
                    dep_count += len(batch)
                    logger.info(f"  Dependencies batch: {dep_count} inserted so far")
                    batch = []

            if batch:
                if is_postgres:
                    execute_values(cursor, dep_sql, batch, page_size=1000)
                else:
                    cursor.executemany(dep_sql, batch)
                raw_conn.commit()
                dep_count += len(batch)

            del dep_text
            gc.collect()
        except Exception as e:
            logger.warning(f"Failed to process dependencies: {e}")

        logger.info(f"Dependencies inserted: {dep_count} in {time.time() - dep_start:.1f}s")

    # Process image layers (container scans)
    if image_layers_json is not None:
        try:
            layers_data = await image_layers_json.read()
            layers_list = json.loads(_safe_gzip_decompress(layers_data).decode("utf-8"))
            scan.image_layers_json = json.dumps(layers_list)

            layer_tuples = [
                (scan.id, layer.get("layer_id", ""), layer.get("layer_index", i),
                 layer.get("source_image"), bool(layer.get("is_base", False)))
                for i, layer in enumerate(layers_list)
            ]
            cursor = raw_conn.cursor()
            if is_postgres:
                from psycopg2.extras import execute_values
                execute_values(
                    cursor,
                    "INSERT INTO image_layers (scan_id, layer_id, layer_index, source_image, is_base) VALUES %s",
                    layer_tuples,
                )
            else:
                cursor.executemany(
                    "INSERT INTO image_layers (scan_id, layer_id, layer_index, source_image, is_base) VALUES (?, ?, ?, ?, ?)",
                    layer_tuples,
                )
            raw_conn.commit()
            logger.info(f"Stored {len(layers_list)} image layers")
        except Exception as e:
            logger.warning(f"Failed to process image layers: {e}")

    # Process attestations (container scans)
    if attestation_json is not None:
        import base64
        from datetime import datetime as dt
        try:
            att_data = await attestation_json.read()
            att_list = json.loads(_safe_gzip_decompress(att_data).decode("utf-8"))

            att_key = _generate_storage_key(product_name, product_version, scan.id, "attestation.json.gz")
            storage.put(att_key, gzip.compress(json.dumps(att_list).encode()))

            for envelope in att_list:
                predicate_type = None
                builder_id = None
                build_type = None
                build_started = None
                build_finished = None

                payload_b64 = envelope.get("payload", "")
                if payload_b64:
                    try:
                        statement = json.loads(base64.b64decode(payload_b64))
                        predicate_type = statement.get("predicateType")
                        predicate = statement.get("predicate", {})
                        builder_id = predicate.get("builder", {}).get("id")
                        build_type = predicate.get("buildType")
                        meta = predicate.get("metadata", {})
                        if meta.get("buildStartedOn"):
                            build_started = dt.fromisoformat(meta["buildStartedOn"].replace("Z", "+00:00"))
                        if meta.get("buildFinishedOn"):
                            build_finished = dt.fromisoformat(meta["buildFinishedOn"].replace("Z", "+00:00"))
                    except Exception:
                        predicate_type = envelope.get("_layer_annotations", {}).get("predicateType")

                att_record = Attestation(
                    scan_id=scan.id,
                    predicate_type=predicate_type,
                    builder_id=builder_id,
                    build_type=build_type,
                    build_started_on=build_started,
                    build_finished_on=build_finished,
                    attestation_key=att_key,
                )
                db.add(att_record)

            db.commit()
            logger.info(f"Stored {len(att_list)} attestation records")
        except Exception as e:
            logger.warning(f"Failed to process attestations: {e}")

    # Refresh session to pick up raw SQL changes
    db.expire_all()

    elapsed = time.time() - start_time
    logger.info(f"Upload complete: {packages_count} packages, {file_count_actual} files, {dep_count} deps indexed in {elapsed:.1f}s")

    invalidate_stats_cache()

    return ScanResponse(
        id=scan.id,
        product_id=scan.product_id,
        product_name=product.name,
        product_version=product.version,
        source_path=scan.source_path,
        source_type=scan.source_type,
        scan_timestamp=scan.scan_timestamp,
        syft_version=scan.syft_version,
        package_count=scan.package_count,
        file_count=scan.file_count,
        original_size_bytes=scan.original_size_bytes,
        modified_size_bytes=scan.modified_size_bytes,
    )


@router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    """Delete a scan and its associated data."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Delete from storage
    storage = get_storage()
    try:
        storage.delete(scan.original_sbom_key)
        storage.delete(scan.modified_sbom_key)
    except Exception:
        pass  # Ignore storage errors during deletion

    # Use raw SQL for fast deletion
    connection = db.connection()
    raw_conn = connection.connection.dbapi_connection
    cursor = raw_conn.cursor()

    is_postgres = 'psycopg' in type(raw_conn).__module__ or 'postgresql' in str(db.bind.url)
    param = '%s' if is_postgres else '?'

    cursor.execute(f"DELETE FROM dependencies WHERE scan_id = {param}", (scan_id,))
    cursor.execute(f"DELETE FROM files WHERE scan_id = {param}", (scan_id,))
    cursor.execute(f"DELETE FROM packages WHERE scan_id = {param}", (scan_id,))
    cursor.execute(f"DELETE FROM scans WHERE id = {param}", (scan_id,))
    raw_conn.commit()
    db.expire_all()

    invalidate_stats_cache()
