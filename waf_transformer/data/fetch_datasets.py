"""Fetch the public attack corpora (Step 4) into data/raw/.

Primary source is the canonical GSI GitLab mirror of the CSIC 2010 and
ECML/PKDD 2007 datasets. Because that host is unreachable from some networks
(and from this sandbox), a GitHub mirror of the same converted files is tried
as fallback, then a shallow ``git clone`` of that mirror. Every fetched file's
sha256 lands in ``data/raw/MANIFEST.json`` so datasets stay reproducible.

Stdlib-only. Usage::

    python3 -m waf_transformer.data.fetch_datasets --dest data/raw
    python3 -m waf_transformer.data.fetch_datasets --dataset csic_2010 --dest data/raw
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

USER_AGENT = "waf-transformer-data-pipeline/0.1 (+https://github.com/praveen-gk18/waf_transformer)"

# Canonical GSI mirror (https://gitlab.fing.edu.uy/gsi/web-application-attacks-datasets).
# The tar.gz files contain the annotated train/test conversions of each corpus.
GSI_RAW = "https://gitlab.fing.edu.uy/gsi/web-application-attacks-datasets/-/raw/master"

DATASETS: dict[str, dict] = {
    "csic_2010": {
        "description": "HTTP DATASET CSIC 2010 — 72k benign + 25k anomalous requests "
        "against an e-commerce app (Paros/w3af-generated attacks).",
        "canonical": f"{GSI_RAW}/csic_2010/dataset_cisc_train_test.tar.gz",
        "tarball_members": [
            "cisc_normalTraffic_train.txt",
            "cisc_normalTraffic_test.txt",
            "cisc_anomalousTraffic_test.txt",
        ],
        "github_mirror_repo": "https://github.com/rashimo/ChCNN.git",
        "github_mirror_ref": "master",
        # file name in data/raw/<dataset>/ -> path inside the GitHub mirror repo
        "github_mirror_files": {
            "cisc_normalTraffic_train.txt": "CSIC2010/cisc_normalTraffic_train.txt",
            "cisc_normalTraffic_test.txt": "CSIC2010/cisc_normalTraffic_test.txt",
            "cisc_anomalousTraffic_test.txt": "CSIC2010/cisc_anomalousTraffic_test.txt",
        },
    },
    "ecml_pkdd_2007": {
        "description": "ECML/PKDD 2007 Discovery Challenge traffic — 35k benign + 15k "
        "attacks across 7 families (SqlInjection, XSS, LdapInjection, ...).",
        "canonical": f"{GSI_RAW}/ecml_pkdd/dataset_ecml_pkdd_train_test.tar.gz",
        "tarball_members": ["xml_train.txt", "xml_test.txt"],
        "github_mirror_repo": "https://github.com/rashimo/ChCNN.git",
        "github_mirror_ref": "master",
        "github_mirror_files": {
            "xml_train.txt": "ecml_pkdd/xml_train.txt",
            "xml_test.txt": "ecml_pkdd/xml_test.txt",
        },
    },
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _download(url: str, dest: Path, timeout: int = 120) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp, dest.open("wb") as out:
        shutil.copyfileobj(resp, out)


def _fetch_via_gitlab_tarball(spec: dict, dest_dir: Path) -> bool:
    """Download + extract the GSI tarball. Returns True on success."""
    with tempfile.TemporaryDirectory() as tmp:
        tarball = Path(tmp) / "dataset.tar.gz"
        try:
            _download(spec["canonical"], tarball)
        except Exception as exc:  # noqa: BLE001 — any transport failure => fallback
            print(f"    canonical fetch failed: {type(exc).__name__}: {exc}")
            return False
        try:
            with tarfile.open(tarball, "r:gz") as tf:
                members = {Path(m.name).name: m for m in tf.getmembers() if m.isfile()}
                for want in spec["tarball_members"]:
                    match = next((m for name, m in members.items() if name == want), None)
                    if match is None:
                        # tarball may nest names differently; accept suffix match
                        match = next((m for name, m in members.items() if name.endswith(want)), None)
                    if match is None:
                        print(f"    tarball missing member {want}")
                        return False
                    out = dest_dir / want
                    with tf.extractfile(match) as src, out.open("wb") as dst:  # type: ignore[union-attr]
                        shutil.copyfileobj(src, dst)  # type: ignore[union-attr]
        except tarfile.TarError as exc:
            print(f"    tarball unreadable: {exc}")
            return False
    return True


def _fetch_via_github_raw(spec: dict, dest_dir: Path) -> bool:
    """Download the converted files one by one from the GitHub mirror."""
    ref = spec["github_mirror_ref"]
    base = spec["github_mirror_repo"].replace("github.com", "raw.githubusercontent.com").removesuffix(".git")
    for dest_name, repo_path in spec["github_mirror_files"].items():
        url = f"{base}/{ref}/{repo_path}"
        try:
            _download(url, dest_dir / dest_name)
        except Exception as exc:  # noqa: BLE001
            print(f"    github raw fetch failed for {dest_name}: {type(exc).__name__}: {exc}")
            return False
    return True


def _fetch_via_git_clone(spec: dict, dest_dir: Path) -> bool:
    """Last resort: shallow-clone the mirror repo and copy the files out."""
    with tempfile.TemporaryDirectory() as tmp:
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", "--quiet", spec["github_mirror_repo"], tmp + "/repo"],
                check=True,
                timeout=180,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            print(f"    git clone failed: {exc}")
            return False
        repo = Path(tmp) / "repo"
        for dest_name, repo_path in spec["github_mirror_files"].items():
            src = repo / repo_path
            if not src.exists():
                print(f"    mirror repo missing {repo_path}")
                return False
            shutil.copyfile(src, dest_dir / dest_name)
    return True


def fetch_dataset(name: str, dest_root: Path) -> dict:
    """Fetch one dataset into dest_root/<name>/. Returns manifest entry."""
    spec = DATASETS[name]
    dest_dir = dest_root / name
    dest_dir.mkdir(parents=True, exist_ok=True)
    print(f"[{name}] {spec['description']}")

    strategies = [
        ("gitlab_tarball", _fetch_via_gitlab_tarball),
        ("github_raw", _fetch_via_github_raw),
        ("git_clone", _fetch_via_git_clone),
    ]
    used = None
    for label, fn in strategies:
        print(f"  trying {label} ...")
        if fn(spec, dest_dir):
            used = label
            print(f"  ok via {label}")
            break
    if used is None:
        raise RuntimeError(
            f"all fetch strategies failed for {name}; download manually from "
            f"{spec['canonical']} into {dest_dir}"
        )

    files = {}
    for f in sorted(dest_dir.glob("*.txt")):
        files[f.name] = {"sha256": sha256_file(f), "bytes": f.stat().st_size}
    return {
        "dataset": name,
        "description": spec["description"],
        "strategy": used,
        "canonical_url": spec["canonical"],
        "files": files,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Download public HTTP attack corpora into data/raw/")
    ap.add_argument("--dest", type=Path, default=Path("data/raw"), help="destination directory")
    ap.add_argument(
        "--dataset",
        choices=["all", *DATASETS.keys()],
        default="all",
        help="which dataset to fetch (default: all)",
    )
    args = ap.parse_args(argv)

    args.dest.mkdir(parents=True, exist_ok=True)
    manifest_path = args.dest / "MANIFEST.json"
    manifest = {}
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())

    names = list(DATASETS) if args.dataset == "all" else [args.dataset]
    for name in names:
        manifest[name] = fetch_dataset(name, args.dest)

    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(f"manifest written to {manifest_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
