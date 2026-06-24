"""
SBOM format detection and conversion to syfter's internal package index format.

Supports: SPDX 2.x, CycloneDX 1.x, syft-json.
"""

import json
from enum import Enum
from urllib.parse import unquote


class SBOMFormat(str, Enum):
    SPDX = "spdx"
    CYCLONEDX = "cyclonedx"
    SYFT = "syft-json"
    UNKNOWN = "unknown"


PURL_TYPE_MAP = {
    "rpm": "rpm",
    "maven": "java",
    "npm": "npm",
    "generic": "generic",
    "pypi": "python",
    "golang": "go-module",
    "gem": "gem",
    "cargo": "cargo",
}

SBOMER_TYPE_MAP = {
    "rpm": "rpm",
    "java-archive": "java",
}


def detect_format(sbom: dict) -> SBOMFormat:
    if sbom.get("spdxVersion"):
        return SBOMFormat.SPDX
    if sbom.get("bomFormat") == "CycloneDX":
        return SBOMFormat.CYCLONEDX
    if "artifacts" in sbom or "descriptor" in sbom:
        return SBOMFormat.SYFT
    return SBOMFormat.UNKNOWN


def parse_purl(purl):
    """Parse a Package URL into (type, namespace, name, version, qualifiers)."""
    if not purl or ":" not in purl:
        return None, None, None, None, {}
    scheme_rest = purl.split(":", 1)
    if len(scheme_rest) != 2:
        return None, None, None, None, {}
    rest = scheme_rest[1]
    qualifiers = {}
    if "?" in rest:
        rest, qs = rest.split("?", 1)
        for pair in qs.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                qualifiers[k] = unquote(v)
    version = None
    if "@" in rest:
        rest, version = rest.split("@", 1)
    parts = rest.split("/")
    pkg_type = parts[0] if parts else None
    if len(parts) == 3:
        namespace, name = parts[1], parts[2]
    elif len(parts) == 2:
        namespace, name = None, parts[1]
    else:
        namespace, name = None, parts[0] if parts else None
    return pkg_type, namespace, name, version, qualifiers


def _split_rpm_version(version_str):
    """Split RPM version-release string. '0.0.25-6.el8' -> ('0.0.25', '6.el8')."""
    if "-" in version_str:
        idx = version_str.rfind("-")
        return version_str[:idx], version_str[idx + 1:]
    return version_str, ""


def _extract_license_cyclonedx(comp):
    """Extract license string from a CycloneDX component."""
    for lic_entry in comp.get("licenses", []):
        if "expression" in lic_entry:
            return lic_entry["expression"]
        lic = lic_entry.get("license", {})
        if lic.get("id"):
            return lic["id"]
        if lic.get("name"):
            return lic["name"]
    return ""


def _extract_product_cpe(cdx_sbom):
    """Extract product-level CPE from CycloneDX metadata."""
    meta_comp = cdx_sbom.get("metadata", {}).get("component", {})
    for ident in meta_comp.get("evidence", {}).get("identity", []):
        if ident.get("field") == "cpe":
            return ident.get("concludedValue", "")
    return ""


def _resolve_type_cyclonedx(comp, purl_type_raw):
    """Resolve syfter package type from CycloneDX component properties or purl type."""
    for prop in comp.get("properties", []):
        if prop.get("name") == "sbomer:package:type":
            sbomer_type = prop["value"]
            if sbomer_type in SBOMER_TYPE_MAP:
                return SBOMER_TYPE_MAP[sbomer_type]
    if purl_type_raw and purl_type_raw in PURL_TYPE_MAP:
        return PURL_TYPE_MAP[purl_type_raw]
    return "unknown"


def convert_spdx(sbom: dict, source_image: str = "") -> list[dict]:
    """Convert SPDX 2.x SBOM to syfter package index."""
    index = []
    for pkg in sbom.get("packages", []):
        ext_refs = pkg.get("externalRefs", [])
        purl = ""
        cpes = []
        for ref in ext_refs:
            rtype = ref.get("referenceType", "")
            loc = ref.get("referenceLocator", "")
            if rtype == "purl":
                purl = loc
            elif rtype == "cpe23Type":
                cpes.append(loc)

        if not purl:
            continue

        pkg_type_raw, namespace, purl_name, purl_version, quals = parse_purl(purl)

        type_map = {"rpm": "rpm", "pypi": "python", "golang": "go-module",
                    "npm": "npm", "gem": "gem"}
        pkg_type = type_map.get(pkg_type_raw, pkg_type_raw or "unknown")

        if pkg_type_raw == "oci":
            continue

        name = pkg.get("name", purl_name or "")
        version = purl_version or pkg.get("versionInfo", "")

        license_val = pkg.get("licenseDeclared", "")
        if license_val == "NOASSERTION":
            license_val = ""

        vendor = ""
        originator = pkg.get("originator", "")
        if originator.startswith("Organization: "):
            vendor = originator[len("Organization: "):]

        entry = {
            "name": name,
            "version": version,
            "type": pkg_type,
            "purl": purl,
            "cpes": cpes,
            "license": license_val,
            "source_image": source_image,
            "layer_id": None,
        }

        if pkg_type == "rpm":
            ver_parts = version.rsplit("-", 1) if "-" in version else [version, ""]
            entry["version"] = ver_parts[0]
            entry["release"] = ver_parts[1] if len(ver_parts) > 1 else ""
            entry["arch"] = quals.get("arch", "")
            epoch_str = quals.get("epoch", "")
            entry["epoch"] = int(epoch_str) if epoch_str else None
            entry["source_rpm"] = quals.get("upstream", "")
            entry["vendor"] = vendor
        else:
            entry["release"] = ""
            entry["arch"] = ""
            entry["epoch"] = None
            entry["source_rpm"] = ""

        index.append(entry)

    return index


def convert_cyclonedx(sbom: dict, source_image: str = "") -> list[dict]:
    """Convert CycloneDX 1.x SBOM to syfter package index."""
    packages = []

    product_cpe = _extract_product_cpe(sbom)
    cpes_json = json.dumps([product_cpe]) if product_cpe else "[]"

    for comp in sbom.get("components", []):
        purl = comp.get("purl", "")
        if not purl:
            continue
        if purl.startswith("pkg:oci/"):
            continue

        pkg_type_raw, namespace, purl_name, purl_version, quals = parse_purl(purl)
        pkg_type = _resolve_type_cyclonedx(comp, pkg_type_raw)
        license_val = _extract_license_cyclonedx(comp)

        vendor = comp.get("publisher", "")
        if not vendor:
            vendor = comp.get("supplier", {}).get("name", "")

        name = comp.get("name", purl_name or "")
        version = purl_version or comp.get("version", "")

        entry = {
            "name": name,
            "version": version,
            "type": pkg_type,
            "purl": purl,
            "cpes": cpes_json,
            "license": license_val,
            "source_image": source_image,
            "layer_id": None,
        }

        if pkg_type == "rpm":
            ver, rel = _split_rpm_version(version)
            entry.update({
                "version": ver,
                "release": rel,
                "arch": quals.get("arch", ""),
                "epoch": int(quals["epoch"]) if quals.get("epoch") else None,
                "source_rpm": quals.get("upstream", ""),
                "vendor": vendor,
            })
        else:
            entry.update({
                "release": "",
                "arch": "",
                "epoch": None,
                "source_rpm": "",
            })

        packages.append(entry)

    return packages


def convert_syft(sbom: dict, source_image: str = "") -> list[dict]:
    """Convert syft-json SBOM to syfter package index."""
    index = []
    for artifact in sbom.get("artifacts", []):
        meta = artifact.get("metadata") or {}
        pkg_type = artifact.get("type", "unknown")

        license_val = ""
        for lic in artifact.get("licenses", []):
            if isinstance(lic, dict):
                license_val = lic.get("spdxExpression") or lic.get("value", "")
            elif isinstance(lic, str):
                license_val = lic
            if license_val:
                break

        cpes = []
        for cpe_entry in artifact.get("cpes", []):
            if isinstance(cpe_entry, dict):
                cpes.append(cpe_entry.get("cpe", ""))
            elif isinstance(cpe_entry, str):
                cpes.append(cpe_entry)

        layer_id = None
        locations = artifact.get("locations", [])
        if locations and isinstance(locations[0], dict):
            layer_id = locations[0].get("layerID")

        entry = {
            "name": artifact.get("name", ""),
            "version": artifact.get("version", ""),
            "type": pkg_type,
            "purl": artifact.get("purl", ""),
            "cpes": cpes,
            "license": license_val,
            "source_image": source_image,
            "layer_id": layer_id,
        }

        if pkg_type == "rpm":
            entry["release"] = meta.get("release", "")
            entry["arch"] = meta.get("architecture", "")
            entry["epoch"] = meta.get("epoch")
            entry["source_rpm"] = meta.get("sourceRpm", "")
            entry["vendor"] = meta.get("vendor", "")
        else:
            entry["release"] = ""
            entry["arch"] = ""
            entry["epoch"] = None
            entry["source_rpm"] = ""

        index.append(entry)

    return index


def convert_sbom(sbom: dict, source_image: str = "") -> tuple[SBOMFormat, list[dict]]:
    """Auto-detect SBOM format and convert to syfter package index.

    Returns (detected_format, packages_list).
    Raises ValueError if format is unknown.
    """
    fmt = detect_format(sbom)
    if fmt == SBOMFormat.SPDX:
        return fmt, convert_spdx(sbom, source_image)
    elif fmt == SBOMFormat.CYCLONEDX:
        return fmt, convert_cyclonedx(sbom, source_image)
    elif fmt == SBOMFormat.SYFT:
        return fmt, convert_syft(sbom, source_image)
    else:
        raise ValueError(
            "Unrecognized SBOM format. Expected SPDX (spdxVersion field), "
            "CycloneDX (bomFormat field), or syft-json (artifacts array)."
        )
