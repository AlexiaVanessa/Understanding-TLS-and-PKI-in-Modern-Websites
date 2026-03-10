#!/usr/bin/env python3

"""
Deterministically select 1,000 domains from a Tranco snapshot based ONLY on 
your name. The Tranco CSV (decompressed) must be in the same directory
with filename: top-1m.csv

Usage example:
    python3 select_domains.py --name name_surname --out domains.txt
"""

import argparse
import csv
import hashlib
import os
import random
import sys

TRANCO_FILE = "top-1m.csv"   # must be decompressed and in the same directory
N_DOMAINS = 1000

def load_domains(path: str):
    domains = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        try:
            first = next(reader)
        except StopIteration:
            return domains

        # Detect a header (e.g., ["rank","domain"]) vs first data row (["1","example.com"])
        def is_int(s):
            try:
                int(s)
                return True
            except Exception:
                return False

        # If first cell isn't an integer, assume it's a header row and skip it
        if not first or not is_int(first[0]):
            pass
        else:
            if len(first) >= 2 and first[1]:
                domains.append(first[1].strip().lower())

        for row in reader:
            if len(row) >= 2 and row[1]:
                domains.append(row[1].strip().lower())
    return domains

def main():
    parser = argparse.ArgumentParser(
        description="Deterministically select 1,000 domains from top-1m.csv based on your name."
    )
    parser.add_argument(
        "--name",
        required=True,
        help="Your full name in the format name_surname (e.g., maria_nikolaou)",
    )
    parser.add_argument(
        "--out",
        required=True,
        help="Output filename, e.g., domains.txt",
    )
    args = parser.parse_args()

    if not os.path.exists(TRANCO_FILE):
        sys.exit(
            f"Error: '{TRANCO_FILE}' not found in the current directory.\n"
            f"Make sure you decompressed the Tranco archive first."
        )

    # Seed derived ONLY from the provided name (stable & deterministic).
    seed_int = int(hashlib.sha256(args.name.encode("utf-8")).hexdigest(), 16)
    random.seed(seed_int)

    domains = load_domains(TRANCO_FILE)
    if len(domains) < N_DOMAINS:
        sys.exit(
            f"Error: Tranco list too small ({len(domains)} domains) — need at least {N_DOMAINS}."
        )

    # Deterministically sample 1,000 distinct indices, then write domains sorted by index
    indices = random.sample(range(len(domains)), N_DOMAINS)
    indices.sort()
    selected = [domains[i] for i in indices]

    with open(args.out, "w", encoding="utf-8") as out:
        out.write("\n".join(selected))

    print(f"Selected {len(selected)} domains → {args.out}")
    print(f"Seed (derived from name): {seed_int}")

if __name__ == "__main__":
    main()
