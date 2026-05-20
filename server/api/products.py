"""
Product API endpoints.
"""

import json
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from ..db import get_db, Product, Scan, Package, File, ImageLayer, Attestation
from .schemas import ProductCreate, ProductResponse

router = APIRouter()


@router.get("/", response_model=List[ProductResponse])
def list_products(
    limit: int = Query(default=100, le=1000, description="Maximum results"),
    offset: int = Query(default=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
):
    """List all products with scan, package, and file counts."""
    # Raw SQL with CTE + LATERAL: PostgreSQL's planner chooses Hash Join
    # (full 11M-row seq scan) for ORM subqueries. LATERAL forces Nested
    # Loop with index scan per product (233ms vs 15.8s).
    sql = text("""
        WITH page AS (
            SELECT id FROM products
            ORDER BY name, version
            LIMIT :limit OFFSET :offset
        )
        SELECT p.id, p.name, p.version, p.vendor, p.cpe_vendor,
               p.cpe_product, p.purl_namespace, p.description, p.created_at,
               COALESCE(sc.cnt, 0) AS scan_count,
               COALESCE(pc.cnt, 0) AS total_packages,
               COALESCE(fc.cnt, 0) AS total_files
        FROM products p
        JOIN page ON p.id = page.id
        LEFT JOIN LATERAL (SELECT count(*) cnt FROM scans WHERE product_id = p.id) sc ON true
        LEFT JOIN LATERAL (SELECT count(*) cnt FROM packages WHERE product_id = p.id) pc ON true
        LEFT JOIN LATERAL (SELECT count(*) cnt FROM files WHERE product_id = p.id) fc ON true
        ORDER BY p.name, p.version
    """)

    results = db.execute(sql, {"limit": limit, "offset": offset}).fetchall()

    return [
        ProductResponse(
            id=row.id,
            name=row.name,
            version=row.version,
            vendor=row.vendor,
            cpe_vendor=row.cpe_vendor,
            cpe_product=row.cpe_product,
            purl_namespace=row.purl_namespace,
            description=row.description,
            created_at=row.created_at,
            scan_count=row.scan_count,
            total_packages=row.total_packages,
            total_files=row.total_files,
        )
        for row in results
    ]


@router.get("/{product_name}/{product_version}", response_model=ProductResponse)
def get_product(product_name: str, product_version: str, db: Session = Depends(get_db)):
    """Get a specific product with counts."""
    product = (
        db.query(Product)
        .filter(Product.name == product_name, Product.version == product_version)
        .first()
    )

    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    scan_count = db.query(func.count(Scan.id)).filter(Scan.product_id == product.id).scalar() or 0
    total_packages = db.query(func.count(Package.id)).filter(Package.product_id == product.id).scalar() or 0
    total_files = db.query(func.count(File.id)).filter(File.product_id == product.id).scalar() or 0

    return ProductResponse(
        id=product.id,
        name=product.name,
        version=product.version,
        vendor=product.vendor,
        cpe_vendor=product.cpe_vendor,
        cpe_product=product.cpe_product,
        purl_namespace=product.purl_namespace,
        description=product.description,
        created_at=product.created_at,
        scan_count=scan_count,
        total_packages=total_packages,
        total_files=total_files,
    )


@router.post("/", response_model=ProductResponse, status_code=201)
def create_product(product: ProductCreate, db: Session = Depends(get_db)):
    """Create a new product."""
    existing = (
        db.query(Product)
        .filter(Product.name == product.name, Product.version == product.version)
        .first()
    )
    if existing:
        raise HTTPException(status_code=409, detail="Product already exists")

    db_product = Product(
        name=product.name,
        version=product.version,
        vendor=product.vendor,
        cpe_vendor=product.cpe_vendor,
        cpe_product=product.cpe_product or product.name,
        purl_namespace=product.purl_namespace,
        description=product.description,
    )
    db.add(db_product)
    db.commit()
    db.refresh(db_product)

    return ProductResponse(
        id=db_product.id,
        name=db_product.name,
        version=db_product.version,
        vendor=db_product.vendor,
        cpe_vendor=db_product.cpe_vendor,
        cpe_product=db_product.cpe_product,
        purl_namespace=db_product.purl_namespace,
        description=db_product.description,
        created_at=db_product.created_at,
        scan_count=0,
        total_packages=0,
        total_files=0,
    )


@router.get("/{product_name}/{product_version}/layers")
def get_product_layers(product_name: str, product_version: str, db: Session = Depends(get_db)):
    """Get container layer chain for a product (for container scans only)."""
    product = (
        db.query(Product)
        .filter(Product.name == product_name, Product.version == product_version)
        .first()
    )

    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    scan = (
        db.query(Scan)
        .filter(Scan.product_id == product.id)
        .order_by(Scan.scan_timestamp.desc())
        .first()
    )

    if not scan:
        raise HTTPException(status_code=404, detail="No scans found for this product")

    if not scan.image_layers_json:
        raise HTTPException(status_code=404, detail="No layer information available (not a container scan)")

    layers = json.loads(scan.image_layers_json)
    return {
        "product_name": product.name,
        "product_version": product.version,
        "source_path": scan.source_path,
        "source_type": scan.source_type,
        "layers": layers,
    }


@router.get("/{product_name}/{product_version}/attestations")
def get_product_attestations(product_name: str, product_version: str, db: Session = Depends(get_db)):
    """Get cosign attestation metadata for a product (container scans only)."""
    product = (
        db.query(Product)
        .filter(Product.name == product_name, Product.version == product_version)
        .first()
    )
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    scan = (
        db.query(Scan)
        .filter(Scan.product_id == product.id)
        .order_by(Scan.scan_timestamp.desc())
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="No scans found for this product")

    atts = db.query(Attestation).filter(Attestation.scan_id == scan.id).all()
    if not atts:
        raise HTTPException(status_code=404, detail="No attestation data available")

    return {
        "product_name": product.name,
        "product_version": product.version,
        "source_path": scan.source_path,
        "attestations": [
            {
                "id": a.id,
                "predicate_type": a.predicate_type,
                "builder_id": a.builder_id,
                "build_type": a.build_type,
                "build_started_on": a.build_started_on.isoformat() if a.build_started_on else None,
                "build_finished_on": a.build_finished_on.isoformat() if a.build_finished_on else None,
            }
            for a in atts
        ],
    }


@router.delete("/{product_name}/{product_version}", status_code=204)
def delete_product(product_name: str, product_version: str, db: Session = Depends(get_db)):
    """Delete a product and all its scans, packages, and files."""
    product = (
        db.query(Product)
        .filter(Product.name == product_name, Product.version == product_version)
        .first()
    )
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    product_id = product.id

    # Delete in FK-safe order: dependencies -> files -> packages -> image_layers -> attestations -> scans -> product
    db.execute(text("DELETE FROM dependencies WHERE product_id = :product_id"), {"product_id": product_id})
    db.execute(text("DELETE FROM component_relationships WHERE parent_product_id = :product_id OR component_product_id = :product_id"), {"product_id": product_id})
    db.execute(text("DELETE FROM files WHERE product_id = :product_id"), {"product_id": product_id})
    db.execute(text("DELETE FROM packages WHERE product_id = :product_id"), {"product_id": product_id})
    db.execute(text("""
        DELETE FROM image_layers WHERE scan_id IN (
            SELECT id FROM scans WHERE product_id = :product_id
        )
    """), {"product_id": product_id})
    db.execute(text("""
        DELETE FROM attestations WHERE scan_id IN (
            SELECT id FROM scans WHERE product_id = :product_id
        )
    """), {"product_id": product_id})
    db.execute(text("DELETE FROM scans WHERE product_id = :product_id"), {"product_id": product_id})
    db.execute(text("DELETE FROM products WHERE id = :product_id"), {"product_id": product_id})

    db.commit()
