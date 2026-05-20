#!/usr/bin/env python3
"""
scan-repodata.py — Fast RPM repo scanner using repodata metadata.

Instead of mirroring entire repos with wget (5-20GB each), this downloads
only the repodata/primary.xml.gz (~1-10MB) from each repo and builds
syft-compatible SBOMs from the package metadata.

Speed comparison:
  - scan-all.py (wget): ~3.5 hours per repo (14GB download)
  - scan-repodata.py:   ~10-30 seconds per repo (1-10MB download)

Usage:
    python3 scan-repodata.py                          # Delta scan
    python3 scan-repodata.py --full                   # Full rescan
    python3 scan-repodata.py --discover-only          # List repos
    python3 scan-repodata.py --trees dist/rhel10      # Specific trees
    python3 scan-repodata.py --retry-failed           # Retry failures
    python3 scan-repodata.py --workers 8              # Parallel scanning
    python3 scan-repodata.py --reset                  # Start fresh

Prerequisites:
    - SYFTER_SERVER set to the syfter API endpoint
    - Network access to rhsm-pulp.corp.redhat.com
"""

import argparse
import gzip
import json
import logging
import os
import re
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.request import urlopen, Request

import ssl

# ─── Configuration ────────────────────────────────────────────────────────────

PULP_BASE = os.environ.get("PULP_BASE_URL", "https://rhsm-pulp.corp.redhat.com")
CONTENT_URL = f"{PULP_BASE}/content"
MAX_CRAWL_DEPTH = 15
CRAWL_DELAY = 0.15
SCAN_RETRIES = 3

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROGRESS_FILE = os.path.join(SCRIPT_DIR, "scan-progress-repodata.json")
LOG_FILE = os.path.join(SCRIPT_DIR, "scan-repodata.log")

# Content trees to crawl
DEFAULT_TREES = [
    "dist/rhel8", "dist/rhel9", "dist/rhel10",
    "dist/rhel", "dist/rhel-alt",
    "dist/layered",
    "dist/rhivos1", "dist/rhivos2",
    "dist/middleware", "dist/rhs", "dist/cf-me", "dist/rhes", "dist/suse",
    "aus", "e4s", "e6s", "els", "eus", "extended-eus", "tus",
    "beta", "public",
]

SKIP_DIRS = {
    "debug", "source", "repodata", "rhui", "hidden",
    "Packages", "listing", "images", "iso", "kickstart",
    "isos", "tree-images",
}

KNOWN_ARCHES = {
    "x86_64", "aarch64", "ppc64le", "s390x", "i386", "i686", "ia64",
    "noarch", "src",
    "arm-64", "arm", "power", "power-le", "power-9", "system-z", "itanium",
}

# XML namespaces for primary.xml
NS = {
    "common": "http://linux.duke.edu/metadata/common",
    "rpm": "http://linux.duke.edu/metadata/rpm",
}


# ─── HTML Directory Listing Parser ────────────────────────────────────────────

class DirParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.dirs = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href", "")
            if href.endswith("/") and not href.startswith(("/", "?", "..")):
                self.dirs.append(href.rstrip("/"))


def list_dirs(url, retries=2):
    target = url if url.endswith("/") else url + "/"
    for attempt in range(retries + 1):
        try:
            with urlopen(target, timeout=30) as resp:
                html = resp.read().decode("utf-8", errors="replace")
            parser = DirParser()
            parser.feed(html)
            time.sleep(CRAWL_DELAY)
            return parser.dirs
        except HTTPError as e:
            if e.code in (404, 403):
                return []
            if attempt < retries:
                time.sleep(2 ** attempt)
                continue
            return []
        except (URLError, OSError):
            if attempt < retries:
                time.sleep(2 ** attempt)
                continue
            return []


# ─── Delta Scanning ───────────────────────────────────────────────────────────

def get_last_modified(url):
    try:
        req = Request(url if url.endswith("/") else url + "/", method="HEAD")
        with urlopen(req, timeout=15) as resp:
            return resp.headers.get("Last-Modified")
    except Exception:
        try:
            with urlopen(url if url.endswith("/") else url + "/", timeout=15) as resp:
                resp.read(1)
                return resp.headers.get("Last-Modified")
        except Exception:
            return None


def repo_has_changed(packages_url, key, progress):
    timestamps = progress.get("timestamps", {})
    prev = timestamps.get(key)
    if not prev:
        return True
    prev_modified = prev.get("last_modified")
    if not prev_modified:
        return True
    current_modified = get_last_modified(packages_url)
    if not current_modified:
        return True
    return current_modified != prev_modified


def record_timestamp(progress, key, packages_url):
    if "timestamps" not in progress:
        progress["timestamps"] = {}
    last_mod = get_last_modified(packages_url)
    progress["timestamps"][key] = {
        "last_modified": last_mod,
        "scanned_at": datetime.now().isoformat(),
    }


# ─── Repo Discovery ──────────────────────────────────────────────────────────

def discover_repos(base_url, rel_path="", depth=0):
    if depth > MAX_CRAWL_DEPTH:
        return
    url = f"{base_url}/{rel_path}".rstrip("/") if rel_path else base_url
    dirs = list_dirs(url)
    if not dirs:
        return
    if "Packages" in dirs:
        yield (f"{url}/Packages", url, rel_path)
        return
    if "os" in dirs:
        sub = f"{rel_path}/os".lstrip("/")
        yield from discover_repos(base_url, sub, depth + 1)
        return
    for d in sorted(dirs):
        if d in SKIP_DIRS:
            continue
        sub = f"{rel_path}/{d}".lstrip("/")
        yield from discover_repos(base_url, sub, depth + 1)


def path_to_scan_info(tree, repo_path):
    raw = f"{tree}/{repo_path}".strip("/")
    parts = [p for p in raw.split("/") if p not in ("os", "Packages", "dist")]
    arch = "noarch"
    remaining = []
    for p in parts:
        if p in KNOWN_ARCHES:
            arch = p
        else:
            remaining.append(p)
    versions = []
    names = []
    for p in remaining:
        if re.match(r"^\d", p):
            versions.append(p)
        else:
            names.append(p)
    deduped = []
    for n in names:
        if not deduped or n != deduped[-1]:
            deduped.append(n)
    names = deduped
    product = "-".join(names) if names else tree.replace("/", "-")
    version = ("-".join(versions) + "-" + arch) if versions else arch
    description = " ".join([p for p in raw.split("/") if p not in ("os", "Packages")])
    return product, version, description


# ─── Repodata Parsing ─────────────────────────────────────────────────────────

def find_primary_xml_url(repo_url):
    """Find the primary.xml.gz URL from a repo's repodata/ directory."""
    repodata_url = repo_url.rstrip("/") + "/repodata/"
    try:
        with urlopen(repodata_url, timeout=15) as resp:
            html = resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None

    # Find all primary.xml.gz files, pick the latest (alphabetically last)
    primaries = re.findall(r'href="([^"]*primary\.xml\.gz)"', html)
    if not primaries:
        return None
    return repodata_url + sorted(primaries)[-1]


def download_primary_xml(url):
    """Download and decompress primary.xml.gz, return parsed XML root."""
    with urlopen(url, timeout=60) as resp:
        compressed = resp.read()
    xml_data = gzip.decompress(compressed)
    return ET.fromstring(xml_data), len(compressed)


def parse_packages_from_primary(root):
    """Parse all packages from primary.xml into a list of dicts."""
    packages = []
    for pkg_elem in root.findall("common:package", NS):
        if pkg_elem.get("type") != "rpm":
            continue

        name = pkg_elem.findtext("common:name", "", NS)
        arch = pkg_elem.findtext("common:arch", "", NS)

        # Skip debuginfo/debugsource
        if "-debuginfo" in name or "-debugsource" in name:
            continue
        # Skip source RPMs
        if arch == "src":
            continue

        ver_elem = pkg_elem.find("common:version", NS)
        epoch = ver_elem.get("epoch", "0") if ver_elem is not None else "0"
        version = ver_elem.get("ver", "") if ver_elem is not None else ""
        release = ver_elem.get("rel", "") if ver_elem is not None else ""

        summary = pkg_elem.findtext("common:summary", "", NS)
        # Skip description — it bloats the SBOM significantly and the server's
        # validation truncates gzip data >10KB then fails decompression
        url = pkg_elem.findtext("common:url", "", NS)
        packager = pkg_elem.findtext("common:packager", "", NS)

        size_elem = pkg_elem.find("common:size", NS)
        pkg_size = int(size_elem.get("package", "0")) if size_elem is not None else 0
        installed_size = int(size_elem.get("installed", "0")) if size_elem is not None else 0

        checksum_elem = pkg_elem.find("common:checksum", NS)
        checksum_type = checksum_elem.get("type", "sha256") if checksum_elem is not None else "sha256"
        checksum_val = checksum_elem.text if checksum_elem is not None else ""

        location_elem = pkg_elem.find("common:location", NS)
        location = location_elem.get("href", "") if location_elem is not None else ""

        time_elem = pkg_elem.find("common:time", NS)
        build_time = int(time_elem.get("build", "0")) if time_elem is not None else 0

        # Fields from <format> element (rpm: namespace)
        format_elem = pkg_elem.find("common:format", NS)
        license_val = ""
        source_rpm = ""
        vendor = ""
        if format_elem is not None:
            license_val = format_elem.findtext("rpm:license", "", NS)
            source_rpm = format_elem.findtext("rpm:sourcerpm", "", NS)
            vendor = format_elem.findtext("rpm:vendor", "", NS)

        # Build PURL
        purl = f"pkg:rpm/redhat/{name}@{version}-{release}?arch={arch}"
        if epoch and epoch != "0":
            purl += f"&epoch={epoch}"

        packages.append({
            "name": name,
            "version": f"{version}-{release}",
            "epoch": epoch,
            "arch": arch,
            "summary": summary,
            "description": "",
            "url": url,
            "packager": packager,
            "license": license_val,
            "source_rpm": source_rpm,
            "vendor": vendor or packager or "Red Hat, Inc.",
            "size": pkg_size,
            "installed_size": installed_size,
            "checksum_type": checksum_type,
            "checksum": checksum_val,
            "location": location,
            "build_time": build_time,
            "purl": purl,
        })
    return packages


# ─── SBOM Generation ──────────────────────────────────────────────────────────

def build_syft_sbom(packages, source_path, source_name="", source_version=""):
    """Build a syft-json compatible SBOM from parsed package metadata."""
    artifacts = []
    for i, pkg in enumerate(packages):
        # Build license list in syft format
        licenses = []
        if pkg.get("license"):
            licenses = [{"value": pkg["license"], "type": "declared"}]

        artifact = {
            "id": str(uuid.uuid4()),
            "name": pkg["name"],
            "version": pkg["version"],
            "type": "rpm",
            "foundBy": "repodata-cataloger",
            "locations": [{"path": pkg["location"]}],
            "licenses": licenses,
            "language": "",
            "cpes": [],
            "purl": pkg["purl"],
            "metadata": {
                "name": pkg["name"],
                "version": pkg["version"],
                "epoch": int(pkg["epoch"]) if pkg["epoch"] else None,
                "architecture": pkg["arch"],
                "release": pkg["version"].split("-")[-1] if "-" in pkg["version"] else "",
                "sourceRpm": pkg.get("source_rpm", ""),
                "size": pkg["installed_size"],
                "vendor": pkg.get("vendor", "Red Hat, Inc."),
                "modularityLabel": "",
                "summary": pkg["summary"],
            },
        }
        artifacts.append(artifact)

    sbom = {
        "artifacts": artifacts,
        "artifactRelationships": [],
        "files": [],
        "source": {
            "id": str(uuid.uuid4()),
            "name": source_name or source_path,
            "version": source_version,
            "type": "directory",
            "metadata": {
                "path": source_path,
            },
        },
        "distro": {
            "name": "redhat",
            "version": "",
            "idLike": ["rhel", "fedora"],
        },
        "descriptor": {
            "name": "syft",
            "version": "repodata-scanner-1.0",
        },
        "schema": {
            "version": "16.0.18",
            "url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.0.18.json",
        },
    }
    return sbom


def build_packages_index(packages):
    """Build the packages_json index that syfter expects."""
    index = []
    for pkg in packages:
        entry = {
            "name": pkg["name"],
            "version": pkg["version"],
            "release": pkg["version"].split("-")[-1] if "-" in pkg["version"] else "",
            "arch": pkg["arch"],
            "type": "rpm",
            "purl": pkg["purl"],
            "cpes": [],
            "license": pkg.get("license", ""),
            "source_rpm": pkg.get("source_rpm", ""),
            "epoch": int(pkg["epoch"]) if pkg["epoch"] else None,
            "metadata": {
                "architecture": pkg["arch"],
                "epoch": int(pkg["epoch"]) if pkg["epoch"] else None,
                "source_rpm": pkg.get("source_rpm", ""),
                "summary": pkg["summary"],
            },
        }
        index.append(entry)
    return index


# ─── Upload ───────────────────────────────────────────────────────────────────

def upload_to_syfter(server_url, product, version, source_path,
                     original_sbom, packages_index):
    """Upload a scan to the syfter server using curl."""
    import subprocess
    import tempfile
    from urllib.parse import urlparse

    original_gz = gzip.compress(json.dumps(original_sbom).encode())
    modified_gz = gzip.compress(json.dumps(original_sbom).encode())  # Same for repodata scans
    packages_gz = gzip.compress(json.dumps(packages_index).encode())

    parsed = urlparse(server_url)
    clean_url = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port:
        clean_url += f":{parsed.port}"
    url = f"{clean_url}/api/v1/scans/upload"

    # Write gzip data to temp files
    tmp_files = []
    try:
        for data in (original_gz, modified_gz, packages_gz):
            f = tempfile.NamedTemporaryFile(suffix=".gz", delete=False)
            f.write(data)
            f.close()
            tmp_files.append(f.name)

        cmd = [
            "curl", "-sk", url,
            "-F", f"product_name={product}",
            "-F", f"product_version={version}",
            "-F", f"source_path={source_path}",
            "-F", "source_type=directory",
            "-F", "syft_version=repodata-scanner-1.0",
            "-F", f"original_sbom=@{tmp_files[0]};type=application/gzip",
            "-F", f"modified_sbom=@{tmp_files[1]};type=application/gzip",
            "-F", f"packages_json=@{tmp_files[2]};type=application/gzip",
        ]

        api_key = os.environ.get("SYFTER_API_KEY")
        if api_key:
            cmd.extend(["-H", f"X-API-Key: {api_key}"])
        elif parsed.username:
            cmd.extend(["-u", f"{parsed.username}:{parsed.password or ''}"])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            raise RuntimeError(f"curl failed: {result.stderr}")

        resp_data = json.loads(result.stdout)
        return resp_data
    finally:
        for path in tmp_files:
            try:
                os.unlink(path)
            except OSError:
                pass


# ─── Scanning ─────────────────────────────────────────────────────────────────

def scan_repo(repo_url, packages_url, product, version, description, server_url):
    """Scan a single repo via repodata. Returns (status, package_count, message)."""
    # Find primary.xml.gz
    primary_url = find_primary_xml_url(repo_url)
    if not primary_url:
        return "skipped", 0, "No repodata/primary.xml.gz found"

    # Download and parse
    try:
        root, dl_size = download_primary_xml(primary_url)
    except Exception as e:
        return "failed", 0, f"Failed to download primary.xml: {e}"

    # Parse packages
    packages = parse_packages_from_primary(root)
    if not packages:
        return "skipped", 0, "No non-debug packages in repodata"

    # Build the full SBOM with all packages
    full_sbom = build_syft_sbom(packages, packages_url, product, version)
    packages_index = build_packages_index(packages)

    # Upload
    try:
        result = upload_to_syfter(server_url, product, version, packages_url,
                                  full_sbom, packages_index)
        return "completed", len(packages), f"Uploaded ({dl_size/1024:.0f}KB repodata, {len(packages)} pkgs)"
    except Exception as e:
        return "failed", 0, f"Upload failed: {e}"


# ─── Progress Tracking ────────────────────────────────────────────────────────

def load_progress():
    if os.path.exists(PROGRESS_FILE):
        with open(PROGRESS_FILE) as f:
            data = json.load(f)
        data.setdefault("completed", [])
        data.setdefault("failed", [])
        data.setdefault("skipped", [])
        data.setdefault("timestamps", {})
        return data
    return {"completed": [], "failed": [], "skipped": [], "timestamps": {}}


def save_progress(progress):
    tmp = PROGRESS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(progress, f, indent=2)
    os.replace(tmp, PROGRESS_FILE)


# ─── Connectivity ─────────────────────────────────────────────────────────────

def check_pulp_reachable():
    test_url = f"{PULP_BASE}/content/dist/rhel10/"
    while True:
        try:
            with urlopen(test_url, timeout=10) as resp:
                resp.read(100)
            return
        except Exception:
            logging.warning("  rhsm-pulp unreachable — retrying in 30s...")
            time.sleep(30)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Fast RPM repo scanner using repodata metadata"
    )
    ap.add_argument("--discover-only", action="store_true")
    ap.add_argument("--trees", nargs="+")
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--retry-failed", action="store_true")
    ap.add_argument("--reset", action="store_true")
    ap.add_argument("--workers", type=int, default=4,
                    help="Number of parallel workers (default: 4)")
    args = ap.parse_args()

    server_url = os.environ.get("SYFTER_SERVER")
    if not server_url and not args.discover_only:
        sys.exit("Error: SYFTER_SERVER not set")

    # Logging
    log_fmt = logging.Formatter("%(asctime)s  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler(LOG_FILE)
    fh.setFormatter(log_fmt)
    logger.addHandler(fh)
    if sys.stdout.isatty() or os.environ.get("SCAN_ALL_VERBOSE"):
        sh = logging.StreamHandler()
        sh.setFormatter(log_fmt)
        logger.addHandler(sh)

    if args.reset and os.path.exists(PROGRESS_FILE):
        os.remove(PROGRESS_FILE)
    progress = load_progress()

    if args.retry_failed and progress["failed"]:
        logging.info(f"Retrying {len(progress['failed'])} previously failed repos")
        progress["failed"] = []
        save_progress(progress)

    trees = args.trees or DEFAULT_TREES

    # ── Discovery ──
    check_pulp_reachable()
    all_repos = []
    logging.info(f"Discovering repos across {len(trees)} content trees...")

    for tree in trees:
        tree_url = f"{CONTENT_URL}/{tree}"
        logging.info(f"  {tree} ...")
        count = 0
        for packages_url, repo_url, repo_path in discover_repos(tree_url):
            product, version, desc = path_to_scan_info(tree, repo_path)
            key = f"{product}:{version}"
            all_repos.append((packages_url, repo_url, product, version, desc, key))
            count += 1
        if count:
            logging.info(f"    → {count} repos")

    logging.info(f"\nDiscovered {len(all_repos)} total repos\n")

    # ── Discover-only ──
    if args.discover_only:
        completed = set(progress["completed"])
        skipped = set(progress["skipped"])
        failed = set(progress["failed"])
        for _, _, product, version, desc, key in all_repos:
            if key in completed:
                tag = "DONE"
            elif key in skipped:
                tag = "SKIP"
            elif key in failed:
                tag = "FAIL"
            else:
                tag = "TODO"
            print(f"[{tag}] {product}  {version}  —  {desc}")
        todo = sum(1 for *_, k in all_repos
                   if k not in completed and k not in skipped and k not in failed)
        print(f"\n{len(all_repos)} total | {len(completed)} done | "
              f"{len(skipped)} skipped | {len(failed)} failed | {todo} new")
        return

    # ── Build scan queue ──
    completed = set(progress["completed"])
    skipped = set(progress["skipped"])
    failed = set(progress["failed"])

    scan_queue = []
    delta_skipped = 0

    for url, repo_url, product, version, desc, key in all_repos:
        if key in failed and not args.full:
            continue
        if key not in completed and key not in skipped:
            scan_queue.append((url, repo_url, product, version, desc, key))
            continue
        if key in skipped:
            scan_queue.append((url, repo_url, product, version, desc, key))
            continue
        if key in completed:
            if args.full:
                scan_queue.append((url, repo_url, product, version, desc, key))
                continue
            if repo_has_changed(url, key, progress):
                scan_queue.append((url, repo_url, product, version, desc, key))
                continue
            delta_skipped += 1

    logging.info(f"Completed (previous): {len(completed)}")
    logging.info(f"Skipped (empty):      {len(skipped)}")
    logging.info(f"Failed:               {len(failed)}")
    logging.info(f"Unchanged (delta):    {delta_skipped}")
    logging.info(f"To scan:              {len(scan_queue)}")

    if not scan_queue:
        logging.info("\nNothing to scan — all repos are up to date.")
        return

    # ── Scanning ──
    scan_start = time.time()
    scanned_count = 0
    new_completed = 0
    new_skipped = 0
    new_failed = 0

    def process_repo(item):
        url, repo_url, product, version, desc, key = item
        check_pulp_reachable()
        for attempt in range(1, SCAN_RETRIES + 1):
            try:
                status, pkg_count, msg = scan_repo(
                    repo_url, url, product, version, desc, server_url
                )
                return key, url, product, version, desc, status, pkg_count, msg
            except Exception as e:
                if attempt < SCAN_RETRIES:
                    time.sleep(5 * attempt)
                    continue
                return key, url, product, version, desc, "failed", 0, str(e)

    workers = min(args.workers, len(scan_queue))
    logging.info(f"Scanning with {workers} parallel workers...\n")

    if workers <= 1:
        # Sequential mode
        for i, item in enumerate(scan_queue, 1):
            url, repo_url, product, version, desc, key = item
            logging.info(f"[{i}/{len(scan_queue)}] {desc}")

            if scanned_count > 0:
                elapsed = time.time() - scan_start
                avg = elapsed / scanned_count
                eta_secs = avg * (len(scan_queue) - i + 1)
                eta_m = int(eta_secs // 60)
                logging.info(f"  ETA: ~{eta_m}m remaining")

            key, _, _, _, _, status, pkg_count, msg = process_repo(item)
            logging.info(f"  {status}: {msg}")

            for lst in ("completed", "skipped", "failed"):
                while key in progress[lst]:
                    progress[lst].remove(key)
            progress[status].append(key)
            if status == "completed":
                record_timestamp(progress, key, url)
                new_completed += 1
            elif status == "skipped":
                new_skipped += 1
            else:
                new_failed += 1
            save_progress(progress)
            scanned_count += 1
    else:
        # Parallel mode
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {}
            for i, item in enumerate(scan_queue):
                f = executor.submit(process_repo, item)
                futures[f] = (i + 1, item)

            for future in as_completed(futures):
                idx, item = futures[future]
                try:
                    key, url, product, version, desc, status, pkg_count, msg = future.result()
                except Exception as e:
                    key = item[5]
                    url = item[0]
                    status = "failed"
                    msg = str(e)
                    pkg_count = 0

                logging.info(f"[{idx}/{len(scan_queue)}] {item[4]}: {status} — {msg}")

                for lst in ("completed", "skipped", "failed"):
                    while key in progress[lst]:
                        progress[lst].remove(key)
                progress[status].append(key)
                if status == "completed":
                    record_timestamp(progress, key, url)
                    new_completed += 1
                elif status == "skipped":
                    new_skipped += 1
                else:
                    new_failed += 1
                save_progress(progress)
                scanned_count += 1

                if scanned_count % 50 == 0:
                    elapsed = time.time() - scan_start
                    rate = scanned_count / elapsed * 60
                    logging.info(f"  Progress: {scanned_count}/{len(scan_queue)} ({rate:.0f}/min)")

    # ── Summary ──
    elapsed = time.time() - scan_start
    hours = int(elapsed // 3600)
    mins = int((elapsed % 3600) // 60)

    logging.info(f"\n{'='*60}")
    logging.info(f"COMPLETE  ({hours}h {mins}m elapsed)")
    logging.info(f"  This run:  {new_completed} scanned, {new_skipped} empty, {new_failed} failed")
    logging.info(f"  Overall:   {len(progress['completed'])} completed, "
                 f"{len(progress['skipped'])} skipped, {len(progress['failed'])} failed")
    if delta_skipped:
        logging.info(f"  Unchanged: {delta_skipped} repos skipped (delta)")
    logging.info(f"{'='*60}")

    if progress["failed"]:
        logging.info("\nFailed repos:")
        for key in progress["failed"]:
            logging.info(f"  {key}")


if __name__ == "__main__":
    main()
