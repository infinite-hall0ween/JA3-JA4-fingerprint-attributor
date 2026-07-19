#!/usr/bin/env python3
"""
ja_attributor.py — Lightweight JA3/JA4 fingerprint attribution tool.

Takes JA3 (MD5) or JA4 fingerprints and attributes them to a likely source
(tool, malware family, library, browser) using a local, user-extensible
signature database. Supports single lookups, batch CSV, and STIX-lite JSON
export for OpenCTI ingestion.

No network calls — designed to run fully offline against a local DB you
curate/update (e.g. from SSLBL, JA3er, Abuse.ch dumps, or your own captures).

Usage:
    python3 ja_attributor.py lookup <fingerprint>
    python3 ja_attributor.py batch fingerprints.csv --out results.csv
    python3 ja_attributor.py add <fingerprint> --source "Cobalt Strike default" --category malware --confidence high
    python3 ja_attributor.py stats
"""

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass, asdict, field
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = Path(__file__).parent / "ja_signatures.json"

JA3_RE = re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE)
JA4_RE = re.compile(r"^[a-z0-9]{1,4}\d{2}[a-z]\d{4}[a-z0-9]{2}_[a-f0-9]{12}_[a-f0-9]{12}$", re.IGNORECASE)

CONFIDENCE_LEVELS = ("low", "medium", "high", "confirmed")


@dataclass
class Signature:
    fingerprint: str
    fp_type: str          # "JA3" or "JA4"
    source: str            # e.g. "Cobalt Strike", "curl/8.4", "Chrome 124"
    category: str          # malware | c2_framework | legit_tool | browser | scanner | unknown
    confidence: str        # low | medium | high | confirmed
    notes: str = ""
    added: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# Seed DB: well-known public JA3/JA4 hashes for common tools/frameworks.
# These are widely published (SSLBL, JA3er, public research) — extend freely.
SEED_SIGNATURES = [
    Signature("e7d705a3286e19ea42f587b344ee6865", "JA3", "Cobalt Strike (default Malleable profile)", "c2_framework", "medium",
              "Commonly reported for stock CS beacons; verify against JA3S pair."),
    Signature("72a589da586844d7f0818ce684948eea", "JA3", "curl (generic, OpenSSL default)", "legit_tool", "medium",
              "Highly common — curl/libcurl default cipher ordering."),
    Signature("a0e9f5d64349fb13191bc781f81f42e1", "JA3", "Python-requests / urllib3 default", "legit_tool", "medium",
              "Common on scripted scanners and simple malware droppers alike."),
    Signature("6734f37431670b3ab4292b8f60f29984", "JA3", "Go net/http default client", "legit_tool", "low",
              "Very common baseline Go TLS client — low specificity."),
    Signature("b32309a26951912be7dba376398abc3b", "JA3", "Trickbot (historical sample)", "malware", "low",
              "Reported historically; hashes shift across TLS stack updates — treat as low-confidence indicator."),
    Signature("579ccef312d18482fc42e2b822ca2430", "JA3", "Metasploit Meterpreter (reverse_https, stock)", "c2_framework", "medium",
              "Stock Meterpreter TLS stager — profile changes if attacker customizes."),
]


def load_db() -> list[Signature]:
    if not DB_PATH.exists():
        save_db(SEED_SIGNATURES)
        return list(SEED_SIGNATURES)
    with open(DB_PATH) as f:
        raw = json.load(f)
    return [Signature(**r) for r in raw]


def save_db(sigs: list[Signature]) -> None:
    with open(DB_PATH, "w") as f:
        json.dump([asdict(s) for s in sigs], f, indent=2)


def detect_fp_type(fp: str) -> str | None:
    fp = fp.strip()
    if JA3_RE.match(fp):
        return "JA3"
    if JA4_RE.match(fp):
        return "JA4"
    return None


def lookup(fp: str, db: list[Signature]) -> dict:
    fp = fp.strip()
    fp_type = detect_fp_type(fp)
    match = next((s for s in db if s.fingerprint.lower() == fp.lower()), None)

    if not fp_type:
        return {
            "fingerprint": fp, "fp_type": "UNKNOWN_FORMAT", "attributed": False,
            "source": None, "category": None, "confidence": None,
            "notes": "Does not match JA3 (32-char MD5) or JA4 pattern — check input."
        }

    if match:
        return {
            "fingerprint": fp, "fp_type": fp_type, "attributed": True,
            "source": match.source, "category": match.category,
            "confidence": match.confidence, "notes": match.notes,
        }

    return {
        "fingerprint": fp, "fp_type": fp_type, "attributed": False,
        "source": "Unknown / not in local DB", "category": "unattributed",
        "confidence": None,
        "notes": "No local match. Consider cross-referencing SSLBL, JA3er.com, or your OpenCTI instance.",
    }


def cmd_lookup(args):
    db = load_db()
    result = lookup(args.fingerprint, db)
    print(json.dumps(result, indent=2))


def cmd_batch(args):
    db = load_db()
    in_path = Path(args.csv_file)
    if not in_path.exists():
        sys.exit(f"File not found: {in_path}")

    with open(in_path) as f:
        reader = csv.reader(f)
        rows = [r[0] for r in reader if r and r[0].strip()]
        # skip header-looking first row
        if rows and not detect_fp_type(rows[0]):
            rows = rows[1:]

    results = [lookup(fp, db) for fp in rows]

    out_path = Path(args.out) if args.out else in_path.with_suffix(".attributed.csv")
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["fingerprint", "fp_type", "attributed", "source", "category", "confidence", "notes"])
        writer.writeheader()
        writer.writerows(results)

    attributed = sum(1 for r in results if r["attributed"])
    print(f"Processed {len(results)} fingerprints — {attributed} attributed, {len(results) - attributed} unknown.")
    print(f"Written to {out_path}")

    if args.stix:
        stix_path = out_path.with_suffix(".stix.json")
        write_stix_bundle(results, stix_path)
        print(f"STIX-lite bundle written to {stix_path}")


def write_stix_bundle(results: list[dict], path: Path):
    """Minimal STIX 2.1-flavored indicator bundle for OpenCTI import."""
    objects = []
    for r in results:
        if not r["attributed"]:
            continue
        pattern_field = "tls_client_ja3_hash" if r["fp_type"] == "JA3" else "tls_client_ja4_hash"
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "pattern_type": "stix",
            "pattern": f"[network-traffic:{pattern_field} = '{r['fingerprint']}']",
            "name": f"{r['fp_type']} — {r['source']}",
            "description": r["notes"] or "",
            "confidence": {"low": 25, "medium": 50, "high": 75, "confirmed": 95}.get(r["confidence"], 50),
            "labels": [r["category"]],
        })
    bundle = {"type": "bundle", "id": "bundle--ja-attributor-export", "objects": objects}
    with open(path, "w") as f:
        json.dump(bundle, f, indent=2)


def cmd_add(args):
    if not detect_fp_type(args.fingerprint):
        sys.exit("Fingerprint doesn't match JA3/JA4 format.")
    if args.confidence not in CONFIDENCE_LEVELS:
        sys.exit(f"Confidence must be one of {CONFIDENCE_LEVELS}")

    db = load_db()
    fp_type = detect_fp_type(args.fingerprint)
    db = [s for s in db if s.fingerprint.lower() != args.fingerprint.lower()]  # replace if exists
    db.append(Signature(args.fingerprint, fp_type, args.source, args.category, args.confidence, args.notes or ""))
    save_db(db)
    print(f"Added/updated: {args.fingerprint} -> {args.source} ({args.category}, {args.confidence})")


def cmd_stats(args):
    db = load_db()
    print(f"Total signatures: {len(db)}")
    by_cat = {}
    for s in db:
        by_cat[s.category] = by_cat.get(s.category, 0) + 1
    for cat, n in sorted(by_cat.items(), key=lambda x: -x[1]):
        print(f"  {cat:15s} {n}")
    print(f"\nDB file: {DB_PATH}")


def main():
    parser = argparse.ArgumentParser(description="JA3/JA4 fingerprint attribution tool")
    sub = parser.add_subparsers(dest="command", required=True)

    p_lookup = sub.add_parser("lookup", help="Look up a single fingerprint")
    p_lookup.add_argument("fingerprint")
    p_lookup.set_defaults(func=cmd_lookup)

    p_batch = sub.add_parser("batch", help="Attribute a CSV of fingerprints (one per line)")
    p_batch.add_argument("csv_file")
    p_batch.add_argument("--out", help="Output CSV path")
    p_batch.add_argument("--stix", action="store_true", help="Also emit a STIX-lite JSON bundle for OpenCTI")
    p_batch.set_defaults(func=cmd_batch)

    p_add = sub.add_parser("add", help="Add/update a signature in the local DB")
    p_add.add_argument("fingerprint")
    p_add.add_argument("--source", required=True)
    p_add.add_argument("--category", required=True, choices=["malware", "c2_framework", "legit_tool", "browser", "scanner", "unknown"])
    p_add.add_argument("--confidence", required=True, choices=CONFIDENCE_LEVELS)
    p_add.add_argument("--notes")
    p_add.set_defaults(func=cmd_add)

    p_stats = sub.add_parser("stats", help="Show DB stats")
    p_stats.set_defaults(func=cmd_stats)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
