"""
Component relationship API endpoints.
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, aliased

from ..db import get_db, Product, ComponentRelationship
from .schemas import ComponentRelationshipCreate, ComponentRelationshipResponse

router = APIRouter()


@router.get("/", response_model=List[ComponentRelationshipResponse])
def list_relationships(
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0),
    db: Session = Depends(get_db),
):
    """List all component relationships."""
    ParentProduct = aliased(Product)
    ComponentProduct = aliased(Product)

    results = (
        db.query(
            ComponentRelationship,
            ParentProduct.name, ParentProduct.version,
            ComponentProduct.name, ComponentProduct.version,
        )
        .join(ParentProduct, ComponentRelationship.parent_product_id == ParentProduct.id)
        .join(ComponentProduct, ComponentRelationship.component_product_id == ComponentProduct.id)
        .offset(offset)
        .limit(limit)
        .all()
    )

    return [
        ComponentRelationshipResponse(
            id=cr.id,
            parent_product_name=pn,
            parent_product_version=pv,
            component_product_name=cn,
            component_product_version=cv,
            relationship_type=cr.relationship_type,
            created_at=cr.created_at,
        )
        for cr, pn, pv, cn, cv in results
    ]


@router.post("/", response_model=ComponentRelationshipResponse, status_code=201)
def create_relationship(
    body: ComponentRelationshipCreate,
    db: Session = Depends(get_db),
):
    """Create a component relationship between two products."""
    parent = (
        db.query(Product)
        .filter(Product.name == body.parent_product_name, Product.version == body.parent_product_version)
        .first()
    )
    if not parent:
        raise HTTPException(
            status_code=404,
            detail=f"Parent product {body.parent_product_name}-{body.parent_product_version} not found",
        )

    component = (
        db.query(Product)
        .filter(Product.name == body.component_product_name, Product.version == body.component_product_version)
        .first()
    )
    if not component:
        raise HTTPException(
            status_code=404,
            detail=f"Component product {body.component_product_name}-{body.component_product_version} not found",
        )

    if body.relationship_type not in ("layered", "maintained"):
        raise HTTPException(
            status_code=400,
            detail="relationship_type must be 'layered' or 'maintained'",
        )

    existing = (
        db.query(ComponentRelationship)
        .filter(
            ComponentRelationship.parent_product_id == parent.id,
            ComponentRelationship.component_product_id == component.id,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=409,
            detail="Relationship already exists between these products",
        )

    cr = ComponentRelationship(
        parent_product_id=parent.id,
        component_product_id=component.id,
        relationship_type=body.relationship_type,
    )
    db.add(cr)
    db.commit()
    db.refresh(cr)

    return ComponentRelationshipResponse(
        id=cr.id,
        parent_product_name=parent.name,
        parent_product_version=parent.version,
        component_product_name=component.name,
        component_product_version=component.version,
        relationship_type=cr.relationship_type,
        created_at=cr.created_at,
    )


@router.delete("/{relationship_id}", status_code=204)
def delete_relationship(relationship_id: int, db: Session = Depends(get_db)):
    """Delete a component relationship."""
    cr = db.query(ComponentRelationship).filter(ComponentRelationship.id == relationship_id).first()
    if not cr:
        raise HTTPException(status_code=404, detail="Relationship not found")

    db.delete(cr)
    db.commit()
