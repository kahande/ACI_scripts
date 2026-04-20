#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
ndo_peer_check.py — NDO PeerContext Symmetry Checker
═════════════════════════════════════════════════════
Logs into NDO, fetches all tenants, then for each tenant calls
/mso/api/v1/policy-report and checks that peerContexts is symmetric
across ALL sites for every EPG, External EPG (L3Out instP), and VRF.

Requires Python 3.6+ (f-strings, pathlib, etc). No external dependencies.

Usage:
  python3 ndo_peer_check.py
  python3 ndo_peer_check.py --ndo 10.197.205.114
  python3 ndo_peer_check.py --ndo 10.197.205.114 --user admin
  python3 ndo_peer_check.py ... --tenant OTP-MGMT,PWR-SCADA   # limit tenants
  python3 ndo_peer_check.py ... --verbose                      # show full per-site lists
  python3 ndo_peer_check.py ... --save gaps.json               # save results to JSON
  python3 ndo_peer_check.py ... --no-verify                    # skip SSL cert check

  (https:// is added automatically — just provide the IP or hostname)
  (use interactive password prompt instead of --password to avoid shell history exposure)

Exit codes:
  0  No gaps found
  1  One or more peerContext gaps detected
  2  Usage/argument error
  130  Interrupted (Ctrl+C)
"""

__version__ = "1.1.0"

import argparse
import getpass
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict

DEFAULT_TIMEOUT = 30  # seconds for all HTTP requests


# ── URL normalisation ─────────────────────────────────────────────────────────

def normalise_url(raw):
    """Ensure the NDO address always has an https:// scheme."""
    raw = raw.strip().rstrip("/")
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw
    return f"https://{raw}"


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _ssl_ctx(verify=True):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _get(url, token, timeout=DEFAULT_TIMEOUT, verify=True):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(verify), timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:300]
        sys.exit(f"[ERROR] GET {url} → HTTP {e.code}: {body}")
    except urllib.error.URLError as e:
        sys.exit(f"[ERROR] GET {url} → {e.reason}")


def _post(url, payload, timeout=DEFAULT_TIMEOUT, verify=True):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(verify), timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:300]
        sys.exit(f"[ERROR] POST {url} → HTTP {e.code}: {body}")
    except urllib.error.URLError as e:
        sys.exit(f"[ERROR] POST {url} → {e.reason}")


# ── Authentication ─────────────────────────────────────────────────────────────

def login(base, user, pw, timeout=DEFAULT_TIMEOUT, verify=True):
    """
    Tries the two common NDO login endpoints and returns a bearer token.
    Postman collection uses /login with userName/userPasswd/domain.
    Newer NDO versions use /api/v1/auth/login with username/password.
    """
    # Attempt 1: legacy /login (matches the Postman collection)
    d = _post(f"{base}/login", {"userName": user, "userPasswd": pw, "domain": "DefaultAuth"},
              timeout=timeout, verify=verify)
    token = d.get("jwttoken") or d.get("token") or d.get("jwtToken") or d.get("accessToken")
    if token:
        return token

    # Attempt 2: newer /api/v1/auth/login
    d = _post(f"{base}/api/v1/auth/login", {"username": user, "password": pw},
              timeout=timeout, verify=verify)
    token = d.get("token") or d.get("jwtToken") or d.get("accessToken")
    if token:
        return token

    # Do not include response body in error — it may echo credentials
    sys.exit("[ERROR] Login failed: no token in response. Check credentials and NDO URL.")


# ── Data fetching ──────────────────────────────────────────────────────────────

def fetch_tenants(base, token, timeout=DEFAULT_TIMEOUT, verify=True):
    """Returns list of {id, name} dicts."""
    d = _get(f"{base}/mso/api/v1/tenants", token, timeout=timeout, verify=verify)
    items = d.get("tenants", d) if isinstance(d, dict) else d
    return [{"id": t["id"], "name": t["name"]} for t in items if "id" in t and "name" in t]


def fetch_policy_report(base, token, tenant_name, timeout=DEFAULT_TIMEOUT, verify=True):
    """Returns raw policy-report dict for a single tenant."""
    tenant_enc = urllib.parse.quote(tenant_name, safe="")
    url = f"{base}/mso/api/v1/policy-report?tenants={tenant_enc}&validate=true"
    return _get(url, token, timeout=timeout, verify=verify)


def fetch_epg_schema_map(base, token, tenant_id_to_name,
                         timeout=DEFAULT_TIMEOUT, verify=True):
    """
    Loads all schemas and returns a lookup:
      (tenant_name, ap_name, epg_name) → [(schema_display_name, template_name), ...]
    Also covers External EPGs (L3Out instP).

    An EPG may legitimately appear in multiple templates (e.g. one per site-local
    template), so each key maps to a *list* of (schema, template) pairs.

    Accepts tenant_id_to_name from the caller to avoid a redundant API call.
    """
    epg_map = defaultdict(list)  # (tenant, ap_or_l3out, epg_or_instP) → [(schema, template)]

    d = _get(f"{base}/mso/api/v1/schemas", token, timeout=timeout, verify=verify)
    summaries = d.get("schemas", [])

    for s in summaries:
        sid = s.get("id")
        sname = s.get("displayName", sid)
        full = _get(f"{base}/mso/api/v1/schemas/{sid}", token, timeout=timeout, verify=verify)
        for tmpl in full.get("templates", []):
            tname = tmpl.get("name", "")
            tid = tmpl.get("tenantId", "")
            tenant_name = tenant_id_to_name.get(tid, "")
            if not tenant_name:
                continue
            entry = (sname, tname)
            for anp in tmpl.get("anps", []):
                ap_name = anp.get("name", "")
                for epg in anp.get("epgs", []):
                    key = (tenant_name, ap_name, epg.get("name", ""))
                    if entry not in epg_map[key]:
                        epg_map[key].append(entry)
            for ext in tmpl.get("externalEpgs", []):
                l3out = ext.get("l3outName", "") or ext.get("name", "")
                key = (tenant_name, l3out, ext.get("name", ""))
                if entry not in epg_map[key]:
                    epg_map[key].append(entry)
            for bd in tmpl.get("bds", []):
                key = (tenant_name, "__BD__", bd.get("name", ""))
                if entry not in epg_map[key]:
                    epg_map[key].append(entry)
    return dict(epg_map)


# ── Object type classification ────────────────────────────────────────────────

def classify_dn(dn):
    """
    Returns one of: 'EPG', 'ExtEPG', 'VRF', or None (skip).
    EPG:     uni/tn-X/ap-Y/epg-Z
    ExtEPG:  uni/tn-X/out-Y/instP-Z
    VRF:     uni/tn-X/ctx-Z
    """
    if "/ap-" in dn and "/epg-" in dn:
        return "EPG"
    if "/out-" in dn and "/instP-" in dn:
        return "ExtEPG"
    if "/ctx-" in dn and dn.count("/") == 2:   # uni/tn-X/ctx-Z (no deeper nesting)
        return "VRF"
    return None


# ── Symmetry analysis ─────────────────────────────────────────────────────────

def analyse_tenant(report, tenant_name):
    """
    Parses a policy-report for one tenant.
    Returns:
      site_map:         {apicId (str) → site_name}
      gaps:             list of gap dicts (peerContext asymmetries)
      validation_errors: list of {dn, messages} dicts from the report's
                        'validation' section (pcTag / remote-mapping mismatches)
    """
    # Build site map
    site_map = {}
    for s in report.get("sites", []):
        site_map[str(s.get("apicId", ""))] = s.get("name", f"site-{s.get('apicId','?')}")

    policies = report.get("policies", {})

    # ── peerContext symmetry ──
    by_dn = defaultdict(dict)
    for dn, entries in policies.items():
        obj_type = classify_dn(dn)
        if obj_type is None:
            continue
        for entry in entries:
            apic_id = str(entry.get("apicId", ""))
            site_name = site_map.get(apic_id, f"site-{apic_id}")
            ctxs = set(entry.get("peerContexts") or [])
            by_dn[dn][site_name] = ctxs

    gaps = []
    for dn, site_ctxs in by_dn.items():
        if len(site_ctxs) < 2:
            continue
        union = set()
        for ctxs in site_ctxs.values():
            union |= ctxs
        if not union:
            continue
        for site, ctxs in site_ctxs.items():
            missing = union - ctxs
            if missing:
                gaps.append({
                    "tenant": tenant_name,
                    "dn": dn,
                    "type": classify_dn(dn),
                    "site": site,
                    "missing": sorted(missing),
                    "present": sorted(ctxs),
                    "all_sites": {s: sorted(c) for s, c in site_ctxs.items()},
                })

    # ── Validation errors (pcTag / remote-mapping mismatches) ──
    validation_errors = []
    for dn, messages in report.get("validation", {}).items():
        if messages:  # skip empty lists
            validation_errors.append({
                "tenant": tenant_name,
                "dn": dn,
                "messages": messages,
            })

    return site_map, gaps, validation_errors


# ── Reporting ──────────────────────────────────────────────────────────────────

def _parse_dn_parts(dn):
    """
    Extracts a schema-map lookup key from a DN.
    Returns None if the DN type cannot be mapped.

    EPG:    uni/tn-X/ap-Y/epg-Z  → (tenant, ap, epg)
    ExtEPG: uni/tn-X/out-Y/instP-Z → (tenant, l3out, instP)
    BD:     uni/tn-X/BD-Y         → (tenant, "__BD__", bd)
    """
    parts = dn.split("/")
    try:
        tenant = next(p[3:] for p in parts if p.startswith("tn-"))
    except StopIteration:
        return None
    # EPG: ap-X/epg-Y
    if "/ap-" in dn and "/epg-" in dn:
        ap  = next((p[3:] for p in parts if p.startswith("ap-")),  "")
        epg = next((p[4:] for p in parts if p.startswith("epg-")), "")
        return (tenant, ap, epg)
    # ExtEPG: out-X/instP-Y
    if "/out-" in dn and "/instP-" in dn:
        l3out = next((p[4:]  for p in parts if p.startswith("out-")),   "")
        instp = next((p[6:]  for p in parts if p.startswith("instP-")), "")
        return (tenant, l3out, instp)
    # BD: BD-Y
    if "/BD-" in dn:
        bd = next((p[3:] for p in parts if p.startswith("BD-")), "")
        return (tenant, "__BD__", bd)
    return None


def print_report(all_gaps, verbose, epg_schema_map=None, all_validation_errors=None):
    SEP  = "─" * 72
    WIDE = "═" * 72

    # Count unique (dn, site) pairs
    unique_objects = len({(g["dn"], g["site"]) for g in all_gaps})

    print()
    print(WIDE)
    print("  NDO PEERCONTEXT SYMMETRY REPORT")
    print(WIDE)

    if not all_gaps:
        print("\n  No peerContext discrepancies found across all tenants.")

    # Group by tenant, then by DN
    by_tenant = defaultdict(lambda: defaultdict(list))
    for g in all_gaps:
        by_tenant[g["tenant"]][g["dn"]].append(g)

    if by_tenant:
        for tenant, by_dn in sorted(by_tenant.items()):
            print(f"\n  Tenant: {tenant}")
            print(SEP)

            # Sub-group by object type
            epgs     = {dn: gs for dn, gs in by_dn.items() if gs[0]["type"] == "EPG"}
            ext_epgs = {dn: gs for dn, gs in by_dn.items() if gs[0]["type"] == "ExtEPG"}
            vrfs     = {dn: gs for dn, gs in by_dn.items() if gs[0]["type"] == "VRF"}

            for section_label, section in [("EPG", epgs), ("External EPG (L3Out)", ext_epgs), ("VRF", vrfs)]:
                if not section:
                    continue
                print(f"\n  ┌─ {section_label} ({len(section)} object(s) with gaps)")
                for dn in sorted(section):
                    gaps_for_dn = section[dn]
                    print(f"\n  │  DN  : {dn}")
                    # Schema / template lookup — an EPG may appear in multiple templates
                    if epg_schema_map:
                        key = _parse_dn_parts(dn)
                        if key and key in epg_schema_map:
                            for sname, tname in epg_schema_map[key]:
                                print(f"  │  Schema  : {sname}  /  Template: {tname}")
                    for g in sorted(gaps_for_dn, key=lambda x: x["site"]):
                        print(f"  │  Site: {g['site']:20s}  ✗ Missing: {', '.join(g['missing'])}")
                    if verbose:
                        all_s = gaps_for_dn[0]["all_sites"]
                        for s, ctxs in sorted(all_s.items()):
                            marker = "  │    "
                            label = f"[{s}]"
                            print(f"{marker}{label:10s} {ctxs if ctxs else '(empty)'}")
                print(f"  └{'─' * 68}")

    # ── Validation errors (pcTag / fvRemoteId mismatches) ──
    if all_validation_errors:
        by_tenant_v = defaultdict(list)
        for v in all_validation_errors:
            by_tenant_v[v["tenant"]].append(v)

        print(f"\n\n{WIDE}")
        print(f"  NDO VALIDATION ERRORS")
        print(WIDE)
        for tenant in sorted(by_tenant_v):
            print(f"\n  Tenant: {tenant}")
            for v in sorted(by_tenant_v[tenant], key=lambda x: x["dn"]):
                print(f"\n  │  DN  : {v['dn']}")
                if epg_schema_map:
                    key = _parse_dn_parts(v["dn"])
                    if key and key in epg_schema_map:
                        for sname, tname in epg_schema_map[key]:
                            print(f"  │  Schema  : {sname}  /  Template: {tname}")
                for msg in v["messages"]:
                    print(f"  │  ⚠  {msg}")
        print(SEP)

    else:
        print(f"\n\n{WIDE}")
        print(f"  NDO VALIDATION ERRORS")
        print(WIDE)
        print("\n  No validation errors found across all tenants.")
        print(WIDE)

    # Summary
    all_tenants_affected = set(g["tenant"] for g in all_gaps) | \
                           set(v["tenant"] for v in (all_validation_errors or []))
    print(f"\n\n{WIDE}")
    print(f"  SUMMARY")
    print(SEP)
    print(f"  Tenants checked  : {len(by_tenant) or len(all_tenants_affected)}")
    print(f"  Objects affected : {unique_objects}")
    print(f"  Gap entries total: {len(all_gaps)}")
    print(f"    EPG gaps       : {sum(1 for g in all_gaps if g['type'] == 'EPG')}")
    print(f"    ExtEPG gaps    : {sum(1 for g in all_gaps if g['type'] == 'ExtEPG')}")
    print(f"    VRF gaps       : {sum(1 for g in all_gaps if g['type'] == 'VRF')}")

    # ── Templates requiring re-deploy ──
    if epg_schema_map:
        redeploy = {}   # (schema, template) → set of tenant names

        # From peerContext gaps
        for tenant, by_dn in by_tenant.items():
            for dn in by_dn:
                key = _parse_dn_parts(dn)
                if key and key in epg_schema_map:
                    for sname, tname in epg_schema_map[key]:
                        redeploy.setdefault((sname, tname), set()).add(tenant)

        # From validation errors
        for v in (all_validation_errors or []):
            key = _parse_dn_parts(v["dn"])
            if key and key in epg_schema_map:
                for sname, tname in epg_schema_map[key]:
                    redeploy.setdefault((sname, tname), set()).add(v["tenant"])

        if redeploy:
            print(f"\n  Following templates may require Re-Deploy")
            print(SEP)
            for (sname, tname), tenants_set in sorted(redeploy.items()):
                print(f"  Schema   : {sname}")
                print(f"  Template : {tname}")
                print(f"  Tenant(s): {', '.join(sorted(tenants_set))}")
                print()

    print(WIDE)
    print()


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Check NDO policy-report for peerContext asymmetries across all sites",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--ndo", default="",
                        help="NDO IP or hostname (https:// added automatically)")
    parser.add_argument("--user", default="",
                        help="NDO username (prompted if omitted)")
    parser.add_argument("--password", default="",
                        help="NDO password. WARNING: passing passwords via CLI arguments "
                             "exposes them in shell history and process listings (ps/top). "
                             "Use the interactive prompt instead whenever possible.")
    parser.add_argument("--tenant", default="",
                        help="Comma-separated tenant names to check (default: all tenants)")
    parser.add_argument("--verbose", action="store_true",
                        help="Show full per-site peerContext lists in output")
    parser.add_argument("--save", metavar="FILE",
                        help="Save gap results to JSON file")
    parser.add_argument("--no-verify", action="store_true",
                        help="Disable SSL certificate verification. Required for NDO nodes "
                             "using self-signed certificates. Use only on trusted networks.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"HTTP request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    args = parser.parse_args()

    verify  = not args.no_verify
    timeout = args.timeout

    # ── Prompt for missing inputs ──
    if not args.ndo:
        args.ndo = input("NDO IP/hostname (e.g. 10.197.205.114): ").strip()
    args.ndo = normalise_url(args.ndo)
    if not args.user:
        args.user = input(f"Username [{args.ndo}]: ").strip() or "admin"
    if not args.password:
        args.password = getpass.getpass(f"Password for {args.user}@{args.ndo}: ")

    # ── SSL warning ──
    if not verify:
        print("[WARN] SSL certificate verification is DISABLED (--no-verify). "
              "Ensure you are on a trusted network.", file=sys.stderr)

    try:
        # ── Login ──
        print(f"\n[*] Logging in to {args.ndo} as '{args.user}' ...")
        token = login(args.ndo, args.user, args.password, timeout=timeout, verify=verify)
        print("[*] Login successful.")

        # ── Tenants ──
        print("[*] Fetching tenants ...")
        all_tenants = fetch_tenants(args.ndo, token, timeout=timeout, verify=verify)

        if args.tenant:
            wanted = {t.strip() for t in args.tenant.split(",") if t.strip()}
            tenants = [t for t in all_tenants if t["name"] in wanted]
            not_found = wanted - {t["name"] for t in tenants}
            if not_found:
                print(f"[WARN] Tenant(s) not found: {', '.join(sorted(not_found))}",
                      file=sys.stderr)
        else:
            # Skip built-in system tenants
            skip = {"common", "infra", "mgmt", "dcnm-default-tn"}
            tenants = [t for t in all_tenants if t["name"].lower() not in skip]

        print(f"[*] Checking {len(tenants)} tenant(s): "
              f"{', '.join(t['name'] for t in tenants)}")

        # ── Per-tenant analysis ──
        all_gaps = []
        all_validation_errors = []
        for t in tenants:
            name = t["name"]
            print(f"  → {name} ...", end=" ", flush=True)
            report = fetch_policy_report(args.ndo, token, name,
                                         timeout=timeout, verify=verify)
            site_map, gaps, v_errors = analyse_tenant(report, name)
            sites_str = ", ".join(site_map.values()) if site_map else "?"
            v_str = f", {len(v_errors)} validation error(s)" if v_errors else ""
            print(f"{len(gaps)} gap(s)  [sites: {sites_str}]{v_str}")
            all_gaps.extend(gaps)
            all_validation_errors.extend(v_errors)

        # ── Schema/template lookup (lazy — only when there are gaps or validation errors) ──
        epg_schema_map = None
        if all_gaps or all_validation_errors:
            print("[*] Loading schemas for template/schema info ...")
            tenant_id_to_name = {t["id"]: t["name"] for t in all_tenants}
            epg_schema_map = fetch_epg_schema_map(
                args.ndo, token, tenant_id_to_name, timeout=timeout, verify=verify)

        # ── Report ──
        print_report(all_gaps, args.verbose, epg_schema_map, all_validation_errors)

        # ── Save ──
        if args.save:
            with open(args.save, "w") as f:
                json.dump(all_gaps, f, indent=2)
            print(f"[*] Results saved to: {args.save}")

        sys.exit(1 if (all_gaps or all_validation_errors) else 0)

    except KeyboardInterrupt:
        print("\n[!] Interrupted.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
