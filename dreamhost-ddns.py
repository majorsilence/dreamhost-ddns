#!/usr/bin/env python3
"""Keep DreamHost A records pointed at this host's current public IPv4 address.

Standard library only (Python 3.9+), so there is nothing to install alongside it.
Configured with command-line options or DREAMHOST_DDNS_* environment variables.

Design, in order of what protects the DNS you already have:
  - The public IP is only trusted when at least two independent services
    agree on the same globally-routable IPv4 address.
  - DreamHost's API is called only when the IP changed, the mode changed, a
    previous run left work undone, or the periodic reconcile is due -- it has
    per-hour/per-day rate limits ("slow_down_bucko"), and normal minutes make
    no API call at all.
  - A new record is added BEFORE stale ones are removed, so a name never
    ends up with none. A CNAME is only replaced when explicitly allowed, and
    is put back if adding the A record then fails.
  - Only the names you list (--record / DREAMHOST_DDNS_RECORDS) are touched, and only their A (and,
    when allowed, CNAME) records; anything else at a name is left alone.
  - --dry-run logs what would change and changes nothing.
  - After a change, the authoritative nameservers are asked directly (if
    --verify-ns is given) and the time until the record is visible is logged,
    so real propagation is measured, not assumed.
The API key is never written to logs.
"""
import argparse
import fcntl
import ipaddress
import json
import os
import random
import re
import socket
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

__version__ = "1.0.0"

DEFAULT_IP_SERVICES = [
    "https://api.ipify.org",
    "https://checkip.amazonaws.com",
    "https://icanhazip.com",
]
DEFAULT_API_URL = "https://api.dreamhost.com/"
PENDING_VERIFY_GIVE_UP_SECONDS = 24 * 3600

_secrets = []


def _now():
    return time.time()


def log(level, message):
    for secret in _secrets:
        if secret:
            message = message.replace(secret, "***")
    print(f"{level}: {message}", flush=True)


class ApiError(Exception):
    def __init__(self, message, rate_limited=False):
        super().__init__(message)
        self.rate_limited = rate_limited


# --------------------------------------------------------------------------
# public IP detection
# --------------------------------------------------------------------------
def fetch_text(url, timeout):
    request = urllib.request.Request(url, headers={"User-Agent": "dreamhost-ddns"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", "replace")


def detect_public_ip(services, timeout=5):
    """Return an IPv4 string that >=2 services agree on, else None."""
    answers = []
    for url in services:
        try:
            value = fetch_text(url, timeout).strip()
            address = ipaddress.ip_address(value)
        except (OSError, ValueError) as error:
            if isinstance(error, urllib.error.HTTPError):
                error.close()
            log("WARN", f"ip service {url} unusable: {error}")
            continue
        if address.version != 4 or not address.is_global:
            log("WARN", f"ip service {url} returned {value}, not a global IPv4 address")
            continue
        answers.append(value)
    for candidate in set(answers):
        if answers.count(candidate) >= 2:
            return candidate
    log("ERROR", f"no two ip services agree (got {answers or 'nothing usable'}); changing nothing")
    return None


# --------------------------------------------------------------------------
# DreamHost API
# --------------------------------------------------------------------------
def parse_response(text):
    """Return the `data` of a successful response; raise ApiError otherwise.

    Requested as format=json, but the response shape is not documented, so the
    tab format (first line success/error, optional header line) is understood
    too.
    """
    text = text.strip()
    try:
        obj = json.loads(text)
    except ValueError:
        obj = None
    if isinstance(obj, dict):
        if obj.get("result") == "success":
            return obj.get("data", [])
        detail = str(obj.get("data", obj))
        if obj.get("reason"):
            detail += f" ({obj['reason']})"
        raise ApiError(detail, rate_limited="slow_down" in detail)
    lines = text.splitlines()
    if not lines:
        raise ApiError("empty response")
    if lines[0].split("\t")[0] != "success":
        detail = text[:300]
        raise ApiError(detail, rate_limited="slow_down" in detail)
    if len(lines) > 1 and lines[1].startswith("account_id"):
        header = lines[1].split("\t")
        return [dict(zip(header, line.split("\t"))) for line in lines[2:] if line.strip()]
    return lines[1:]


class DreamHostApi:
    def __init__(self, base_url, key, timeout=20):
        self.base_url = base_url
        self.key = key
        self.timeout = timeout

    def call(self, cmd, **params):
        query = {"key": self.key, "cmd": cmd, "format": "json", "unique_id": str(uuid.uuid4())}
        query.update(params)
        url = self.base_url + "?" + urllib.parse.urlencode(query)
        try:
            text = fetch_text(url, self.timeout)
        except urllib.error.HTTPError as error:
            error.close()
            raise ApiError(f"{cmd}: HTTP {error.code}") from None
        except OSError as error:
            raise ApiError(f"{cmd}: {error}") from None
        return parse_response(text)

    def list_records(self):
        rows = self.call("dns-list_records")
        if not isinstance(rows, list):
            raise ApiError(f"dns-list_records: unexpected data {str(rows)[:120]}")
        return [dict(row) for row in rows if isinstance(row, dict)]

    def add(self, record, rtype, value):
        self.call("dns-add_record", record=record, type=rtype, value=value)

    def remove(self, record, rtype, value):
        self.call("dns-remove_record", record=record, type=rtype, value=value)


# --------------------------------------------------------------------------
# reconcile
# --------------------------------------------------------------------------
def reconcile(api, names, ip, replace_cname, dry_run):
    """Bring every name to exactly one A record: ip. Returns (ok, changed, rate_limited)."""
    existing = api.list_records()
    ok, changed, rate_limited = True, [], False
    for name in names:
        rows = [r for r in existing if str(r.get("record", "")).lower() == name.lower()]
        a_records = [r for r in rows if r.get("type") == "A"]
        cnames = [r for r in rows if r.get("type") == "CNAME"]
        if cnames and not replace_cname:
            log("ERROR", f"{name} is a CNAME ({cnames[0].get('value')}); delete it at DreamHost or "
                         f"enable replace_cname -- leaving it alone")
            ok = False
            continue
        removed_cnames, added = [], False
        try:
            for record in cnames:
                if dry_run:
                    log("INFO", f"[dry-run] would remove CNAME {name} -> {record.get('value')}")
                else:
                    api.remove(name, "CNAME", record["value"])
                    removed_cnames.append(record)
                    log("INFO", f"removed CNAME {name} -> {record['value']}")
            if ip not in [r.get("value") for r in a_records]:
                if dry_run:
                    log("INFO", f"[dry-run] would add A {name} -> {ip}")
                else:
                    api.add(name, "A", ip)
                    added = True
                    changed.append(name)
                    log("INFO", f"added A {name} -> {ip}")
            for record in a_records:
                if record.get("value") == ip:
                    continue
                if str(record.get("editable", "1")) == "0":
                    log("WARN", f"A {name} -> {record.get('value')} is not editable; leaving it")
                    continue
                if dry_run:
                    log("INFO", f"[dry-run] would remove stale A {name} -> {record.get('value')}")
                else:
                    api.remove(name, "A", record["value"])
                    changed.append(name)
                    log("INFO", f"removed stale A {name} -> {record['value']}")
        except ApiError as error:
            ok = False
            rate_limited = rate_limited or error.rate_limited
            log("ERROR", f"{name}: {error}")
            if removed_cnames and not added:
                for record in removed_cnames:
                    try:
                        api.add(name, "CNAME", record["value"])
                        log("WARN", f"restored CNAME {name} -> {record['value']} after the failure")
                    except ApiError as restore_error:
                        log("ERROR", f"COULD NOT RESTORE CNAME {name} -> {record['value']}: {restore_error}")
            if rate_limited:
                break
    return ok, sorted(set(changed)), rate_limited


# --------------------------------------------------------------------------
# minimal DNS client, to ask the authoritative servers directly
# --------------------------------------------------------------------------
def _encode_name(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.rstrip(".").split(".")) + b"\0"


def _read_name(data, offset):
    parts, jumped, end = [], False, offset
    for _ in range(64):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            offset, jumped = pointer, True
            continue
        parts.append(data[offset + 1: offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
    if not jumped:
        end = offset
    return ".".join(parts), end


def dns_query_a(server, name, port=53, timeout=3.0):
    """Ask `server` (no recursion) for `name`. Returns (rcode, [(type, ttl, value)])."""
    query_id = random.randrange(65536)
    packet = struct.pack(">HHHHHH", query_id, 0, 1, 0, 0, 0) + _encode_name(name) + struct.pack(">HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, port))
        data, _ = sock.recvfrom(4096)
    reply_id, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
    if reply_id != query_id:
        raise OSError("mismatched DNS reply id")
    offset = 12
    for _ in range(qdcount):
        _, offset = _read_name(data, offset)
        offset += 4
    answers = []
    for _ in range(ancount):
        _, offset = _read_name(data, offset)
        rtype, _, ttl, rdlength = struct.unpack(">HHIH", data[offset: offset + 10])
        offset += 10
        if rtype == 1 and rdlength == 4:
            value = ".".join(str(b) for b in data[offset: offset + 4])
        elif rtype == 5:
            value, _ = _read_name(data, offset)
        else:
            value = None
        answers.append((rtype, ttl, value))
        offset += rdlength
    return flags & 0xF, answers


def check_visibility(verify_servers, name, ip, port=53):
    """Return (visible_on, total, ttl) -- how many authoritative servers already answer A=ip."""
    visible, ttl_seen = 0, None
    for server in verify_servers:
        try:
            address = socket.gethostbyname(server)
            _, answers = dns_query_a(address, name, port=port)
        except OSError:
            continue
        for rtype, ttl, value in answers:
            if rtype == 1 and value == ip:
                visible += 1
                ttl_seen = ttl
                break
    return visible, len(verify_servers), ttl_seen


def verify_pending(state, args):
    pending = state.get("pending_verify", {})
    if not pending or not args.verify_ns:
        return
    now = _now()
    for name in list(pending):
        entry = pending[name]
        elapsed = int(now - entry["applied_at"])
        visible, total, ttl = check_visibility(args.verify_ns, name, entry["ip"], args.dns_port)
        if total and visible == total:
            log("INFO", f"VERIFIED {name} -> {entry['ip']} on all {total} nameservers "
                        f"{elapsed}s after the change (record TTL {ttl}s)")
            del pending[name]
        elif elapsed > PENDING_VERIFY_GIVE_UP_SECONDS:
            log("WARN", f"{name} -> {entry['ip']} still not on all nameservers after {elapsed}s "
                        f"({visible}/{total}); no longer checking")
            del pending[name]
        else:
            log("INFO", f"waiting: {name} -> {entry['ip']} on {visible}/{total} nameservers after {elapsed}s")


# --------------------------------------------------------------------------
# state + main
# --------------------------------------------------------------------------
def load_state(path):
    try:
        with open(path) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def save_state(path, state):
    tmp = path + ".tmp"
    with open(tmp, "w") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)
    os.replace(tmp, path)


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--record", action="append", default=[], help="FQDN to manage (repeatable)")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--replace-cname", action="store_true",
                        help="allow removing an existing CNAME at a managed name")
    parser.add_argument("--state-dir", default=os.environ.get("STATE_DIRECTORY", "/var/lib/dreamhost-ddns"))
    parser.add_argument("--reconcile-hours", type=float, default=None,
                        help="re-list records at least this often to repair drift (default 6)")
    parser.add_argument("--ip-service", action="append", default=None)
    parser.add_argument("--api-url", default=DEFAULT_API_URL)
    parser.add_argument("--verify-ns", action="append", default=[],
                        help="authoritative nameserver to ask after a change (repeatable)")
    parser.add_argument("--dns-port", type=int, default=53, help=argparse.SUPPRESS)
    parser.add_argument("--status", action="store_true", help="print the saved state and exit")
    parser.add_argument("--version", action="version", version=f"dreamhost-ddns {__version__}")
    return apply_env(parser.parse_args(argv))


def _truthy(value):
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _words(value):
    return [word for word in re.split(r"[\s,]+", value.strip()) if word]


def apply_env(args, environ=None):
    """Fill in whatever the command line left unset from DREAMHOST_DDNS_* variables.

    Lets one static systemd unit plus an EnvironmentFile configure everything.
    Command-line values win; flags can only be switched on from the environment.
    """
    environ = os.environ if environ is None else environ
    if not args.record:
        args.record = _words(environ.get("DREAMHOST_DDNS_RECORDS", ""))
    if not args.verify_ns:
        args.verify_ns = _words(environ.get("DREAMHOST_DDNS_VERIFY_NS", ""))
    if args.ip_service is None:
        args.ip_service = _words(environ.get("DREAMHOST_DDNS_IP_SERVICES", "")) or None
    args.dry_run = args.dry_run or _truthy(environ.get("DREAMHOST_DDNS_DRY_RUN", ""))
    args.replace_cname = args.replace_cname or _truthy(environ.get("DREAMHOST_DDNS_REPLACE_CNAME", ""))
    if args.reconcile_hours is None:
        args.reconcile_hours = float(environ.get("DREAMHOST_DDNS_RECONCILE_HOURS") or 6.0)
    return args


def run_locked(args, key, state_path):
    state = load_state(state_path)
    now = _now()
    mode = "dry" if args.dry_run else "live"

    verify_pending(state, args)

    if now < state.get("backoff_until", 0):
        log("INFO", f"backing off for another {int(state['backoff_until'] - now)}s after earlier errors")
        save_state(state_path, state)
        return 0

    ip = detect_public_ip(args.ip_service or DEFAULT_IP_SERVICES)
    if ip is None:
        save_state(state_path, state)
        return 1

    reconcile_due = now - state.get("last_reconcile", 0) >= args.reconcile_hours * 3600
    needs_run = (state.get("ip") != ip or state.get("mode") != mode
                 or state.get("dirty") or reconcile_due
                 or sorted(state.get("records", [])) != sorted(args.record))
    if not needs_run:
        save_state(state_path, state)
        return 0

    log("INFO", f"public IP {ip} ({'changed' if state.get('ip') not in (None, ip) else 'checking'}); "
                f"reconciling {', '.join(args.record)} [{mode}]")
    api = DreamHostApi(args.api_url, key)
    try:
        ok, changed, rate_limited = reconcile(api, args.record, ip, args.replace_cname, args.dry_run)
    except ApiError as error:
        ok, changed, rate_limited = False, [], error.rate_limited
        log("ERROR", str(error))

    if ok:
        state.update(ip=ip, mode=mode, last_reconcile=now, dirty=False, failures=0, records=list(args.record))
        state.pop("backoff_until", None)
    else:
        failures = state.get("failures", 0) + 1
        state.update(dirty=True, failures=failures)
        state["backoff_until"] = now + (3600 if rate_limited else min(3600, 60 * 2 ** failures))
    for name in changed:
        state.setdefault("pending_verify", {})[name] = {"ip": ip, "applied_at": now}
    save_state(state_path, state)
    if changed:
        verify_pending(state, args)
        save_state(state_path, state)
    return 0 if ok else 1


def main(argv=None):
    args = parse_args(argv)
    os.makedirs(args.state_dir, exist_ok=True)
    state_path = os.path.join(args.state_dir, "state.json")
    if args.status:
        print(json.dumps(load_state(state_path), indent=2, sort_keys=True))
        return 0

    key = os.environ.get("DREAMHOST_API_KEY", "")
    _secrets.append(key)
    if not key or not args.record:
        log("ERROR", "DREAMHOST_API_KEY and at least one record (--record, or DREAMHOST_DDNS_RECORDS) are required")
        return 2

    with open(os.path.join(args.state_dir, "lock"), "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            log("INFO", "another run is in progress; exiting")
            return 0
        return run_locked(args, key, state_path)


if __name__ == "__main__":
    sys.exit(main())
