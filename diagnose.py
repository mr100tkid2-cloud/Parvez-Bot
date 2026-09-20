#!/usr/bin/env python3
"""Print the same report as GET /diagnose, straight from a terminal.

Useful when the deployed bot looks broken: it tells you whether the token
provider still mints tokens, which release version those tokens carry, and
which game cluster answers - instead of a bare "Failed to get player info".

Garena geo-gates some clusters against datacenter IPs, so run it twice when
something is wrong: once on the server (Render/Vercel shell) and once from a
phone hotspot. If it works from the phone but not the server, the egress IP is
the problem, not the code.

Usage:
    python3 diagnose.py [accounts_to_check]      # default 3
    FF_CLIENT_HOSTS=clientbp.ggpolarbear.com python3 diagnose.py

Environment variables (all optional):
    FF_RELEASE_VERSION, FF_X_GA_SV, FF_REGION, FF_CLIENT_HOSTS, FF_TOKEN_URL,
    FF_ACCOUNT_FILE, FF_TOKEN_FILE
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import app  # noqa: E402


def main():
    limit = 3
    if len(sys.argv) > 1:
        try:
            limit = max(1, int(sys.argv[1]))
        except ValueError:
            print(f"ignoring non-numeric argument: {sys.argv[1]}")

    report = app.build_diagnosis(limit=limit, probe_clusters=True)
    print(json.dumps(report, indent=2, default=str))

    provider_ok = report["provider"]["ok"] > 0
    cluster_ok = any(entry.get("ok") for entry in report["clusters"])
    if provider_ok and cluster_ok:
        print("\nEverything looks healthy - /like should work.")
        return 0
    if not provider_ok:
        print("\nThe token provider is the broken hop (accounts, credentials or provider).")
    else:
        print("\nTokens are fine but no cluster accepted them: check FF_RELEASE_VERSION, "
              "FF_X_GA_SV, the cluster host list and the server's egress IP.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
