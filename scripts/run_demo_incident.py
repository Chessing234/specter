#!/usr/bin/env python3
"""Trigger the pre-built SPECTER demo incident via the API."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--api-url",
        default="http://localhost:8000",
        help="SPECTER API base URL (default: http://localhost:8000)",
    )
    args = parser.parse_args()

    url = f"{args.api_url.rstrip('/')}/api/v1/incidents/demo"
    req = urllib.request.Request(url, method="POST", data=b"{}", headers={"Content-Type": "application/json"})

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode())
    except urllib.error.URLError as exc:
        print(f"Failed to reach API at {url}: {exc}", file=sys.stderr)
        sys.exit(1)

    print("Demo incident created:")
    print(f"  ID:     {body.get('id')}")
    print(f"  Title:  {body.get('title')}")
    print(f"  Status: {body.get('status')}")
    print(f"\nOpen: http://localhost:3000/incidents/{body.get('id')}")


if __name__ == "__main__":
    main()
