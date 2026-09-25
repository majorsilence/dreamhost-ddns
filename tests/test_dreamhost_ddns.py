"""Tests for dreamhost-ddns.py against mock DreamHost, IP-lookup and DNS servers.

Run: python3 -m unittest discover -s tests
"""
import contextlib
import http.server
import importlib.util
import io
import json
import os
import socket
import struct
import tempfile
import threading
import unittest
import urllib.parse
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("ddns", os.path.join(HERE, "..", "dreamhost-ddns.py"))
ddns = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ddns)

KEY = "SECRETKEY-do-not-log"
IP1, IP2 = "93.184.216.34", "93.184.216.35"
NAME = "home.example.com"
OTHER = "office.example.com"


class MockDreamHost(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        srv = self.server
        query = {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).items()}
        if query.get("key") != KEY:
            return self._reply({"result": "error", "data": "invalid_api_key"})
        cmd = query["cmd"]
        srv.calls.append((cmd, query.get("record"), query.get("type"), query.get("value")))
        if cmd in srv.fail:
            mode = srv.fail[cmd]
            if mode == "http500":
                self.send_response(500)
                self.end_headers()
                return
            return self._reply({"result": "error", "data": mode})
        if cmd == "dns-list_records":
            return self._reply({"result": "success", "data": [dict(r) for r in srv.records]})
        key = (query["record"], query["type"], query["value"])
        if cmd == "dns-add_record":
            same_name = [r for r in srv.records if r["record"] == query["record"]]
            if query["type"] == "A" and any(r["type"] == "CNAME" for r in same_name):
                return self._reply({"result": "error", "data": "record_conflicts_with_cname"})
            srv.records.append({"record": key[0], "type": key[1], "value": key[2], "editable": "1"})
            return self._reply({"result": "success", "data": "record_added"})
        if cmd == "dns-remove_record":
            for r in srv.records:
                if (r["record"], r["type"], r["value"]) == key:
                    srv.records.remove(r)
                    return self._reply({"result": "success", "data": "record_removed"})
            return self._reply({"result": "error", "data": "no_such_record"})
        return self._reply({"result": "error", "data": "unknown_cmd"})

    def _reply(self, obj):
        body = obj if isinstance(obj, str) else json.dumps(obj)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())


class MockIpService(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        answer = self.server.answer
        if answer is None:
            self.send_response(503)
            self.end_headers()
            return
        body = (answer + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve(handler):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class MockDns(threading.Thread):
    """UDP DNS server: answers A queries from self.table {name: (ip, ttl)}."""

    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.table = {}

    def run(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(512)
            except OSError:
                return
            qid = data[:2]
            labels, off = [], 12
            while data[off]:
                labels.append(data[off + 1: off + 1 + data[off]].decode())
                off += 1 + data[off]
            question = data[12: off + 5]
            hit = self.table.get(".".join(labels))
            if hit:
                ip, ttl = hit
                answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, ttl, 4) + bytes(int(o) for o in ip.split("."))
                reply = qid + struct.pack(">HHHHH", 0x8400, 1, 1, 0, 0) + question + answer
            else:
                reply = qid + struct.pack(">HHHHH", 0x8403, 1, 0, 0, 0) + question
            self.sock.sendto(reply, addr)


class DdnsTest(unittest.TestCase):
    def setUp(self):
        self.dh = serve(MockDreamHost)
        self.dh.records, self.dh.calls, self.dh.fail = [], [], {}
        self.ips = [serve(MockIpService) for _ in range(3)]
        self.set_ip(IP1)
        self.dns = MockDns()
        self.dns.start()
        self.state_dir = tempfile.mkdtemp()
        self.clock = 1_000_000.0
        patch = mock.patch.object(ddns, "_now", lambda: self.clock)
        patch.start()
        self.addCleanup(patch.stop)
        env = mock.patch.dict(os.environ, {"DREAMHOST_API_KEY": KEY})
        env.start()
        self.addCleanup(env.stop)
        ddns._secrets.clear()
        self.addCleanup(lambda: [(s.shutdown(), s.server_close()) for s in [self.dh, *self.ips]])
        self.addCleanup(self.dns.sock.close)

    def set_ip(self, value, index=None):
        for i, server in enumerate(self.ips):
            if index is None or i == index:
                server.answer = value

    def record(self, name, rtype, value, editable="1"):
        self.dh.records.append({"record": name, "type": rtype, "value": value, "editable": editable})

    def values(self, name, rtype="A"):
        return sorted(r["value"] for r in self.dh.records if r["record"] == name and r["type"] == rtype)

    def run_ddns(self, *extra, names=(NAME,)):
        argv = ["--state-dir", self.state_dir, "--api-url", f"http://127.0.0.1:{self.dh.server_port}/"]
        for server in self.ips:
            argv += ["--ip-service", f"http://127.0.0.1:{server.server_port}/"]
        for name in names:
            argv += ["--record", name]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = ddns.main(argv + list(extra))
        text = out.getvalue()
        self.assertNotIn(KEY, text, "the API key must never appear in output")
        return code, text

    def mutating_calls(self):
        return [c for c in self.dh.calls if c[0] != "dns-list_records"]

    # ---------------------------------------------------------------- basics
    def test_first_run_adds_the_a_record(self):
        code, _ = self.run_ddns()
        self.assertEqual(code, 0)
        self.assertEqual(self.values(NAME), [IP1])

    def test_steady_state_makes_no_dreamhost_calls(self):
        self.run_ddns()
        calls_after_first = len(self.dh.calls)
        self.clock += 60
        for _ in range(5):
            self.assertEqual(self.run_ddns()[0], 0)
            self.clock += 60
        self.assertEqual(len(self.dh.calls), calls_after_first)

    def test_ip_change_adds_new_before_removing_old(self):
        self.record(NAME, "A", IP1)
        self.run_ddns()
        self.dh.calls.clear()
        self.set_ip(IP2)
        self.clock += 60
        self.assertEqual(self.run_ddns()[0], 0)
        self.assertEqual(self.values(NAME), [IP2])
        order = [c[0] for c in self.mutating_calls()]
        self.assertEqual(order, ["dns-add_record", "dns-remove_record"], "add must come before remove")

    def test_add_failure_leaves_the_old_record_in_place(self):
        self.record(NAME, "A", IP1)
        self.run_ddns()
        self.set_ip(IP2)
        self.dh.fail["dns-add_record"] = "boom"
        self.clock += 60
        code, _ = self.run_ddns()
        self.assertEqual(code, 1)
        self.assertEqual(self.values(NAME), [IP1], "a failed add must not cost us the existing record")
        self.assertNotIn("dns-remove_record", [c[0] for c in self.dh.calls])

    def test_failed_run_is_retried_after_backoff_not_before(self):
        self.record(NAME, "A", IP1)
        self.run_ddns()
        self.set_ip(IP2)
        self.dh.fail["dns-add_record"] = "boom"
        self.clock += 60
        self.run_ddns()
        del self.dh.fail["dns-add_record"]
        self.dh.calls.clear()
        self.clock += 30
        self.run_ddns()
        self.assertEqual(self.dh.calls, [], "must back off, not hammer the API")
        self.clock += 4000
        self.assertEqual(self.run_ddns()[0], 0)
        self.assertEqual(self.values(NAME), [IP2])

    def test_rate_limit_backs_off_for_an_hour(self):
        self.dh.fail["dns-list_records"] = "slow_down_bucko (hourly limit)"
        code, _ = self.run_ddns()
        self.assertEqual(code, 1)
        self.dh.fail.clear()
        self.dh.calls.clear()
        self.clock += 1800
        self.run_ddns()
        self.assertEqual(self.dh.calls, [])
        self.clock += 2000
        self.assertEqual(self.run_ddns()[0], 0)
        self.assertEqual(self.values(NAME), [IP1])

    def test_reconcile_repairs_drift_without_an_ip_change(self):
        self.run_ddns()
        self.dh.records.clear()
        self.clock += 3600
        self.run_ddns()
        self.assertEqual(self.values(NAME), [], "before the reconcile interval nothing is checked")
        self.clock += 6 * 3600
        self.run_ddns()
        self.assertEqual(self.values(NAME), [IP1])

    def test_only_managed_names_and_types_are_touched(self):
        self.record(NAME, "A", IP2)
        self.record(NAME, "TXT", "keep-me")
        self.record(OTHER, "A", IP2)
        self.record("example.com", "A", IP2)
        self.run_ddns()
        self.assertEqual(self.values(NAME), [IP1])
        self.assertEqual(self.values(NAME, "TXT"), ["keep-me"])
        self.assertEqual(self.values(OTHER), [IP2])
        self.assertEqual(self.values("example.com"), [IP2])

    def test_non_editable_records_are_not_removed(self):
        self.record(NAME, "A", IP2, editable="0")
        code, text = self.run_ddns()
        self.assertEqual(code, 0)
        self.assertEqual(self.values(NAME), [IP1, IP2])
        self.assertIn("not editable", text)

    def test_multiple_names_are_managed_independently(self):
        self.record(OTHER, "A", IP2)
        self.run_ddns(names=(NAME, OTHER))
        self.assertEqual(self.values(NAME), [IP1])
        self.assertEqual(self.values(OTHER), [IP1])

    # ---------------------------------------------------------------- cname
    def test_cname_is_left_alone_by_default(self):
        self.record(NAME, "CNAME", "target.example.net.")
        code, text = self.run_ddns()
        self.assertEqual(code, 1)
        self.assertEqual(self.mutating_calls(), [])
        self.assertIn("CNAME", text)

    def test_cname_is_replaced_when_allowed(self):
        self.record(NAME, "CNAME", "target.example.net.")
        code, _ = self.run_ddns("--replace-cname")
        self.assertEqual(code, 0)
        self.assertEqual(self.values(NAME, "CNAME"), [])
        self.assertEqual(self.values(NAME), [IP1])

    def test_cname_is_restored_if_adding_the_a_record_fails(self):
        self.record(NAME, "CNAME", "target.example.net.")
        self.dh.fail["dns-add_record"] = "boom"
        original_add = MockDreamHost.do_GET

        # fail only the A add; let the CNAME restore through
        def selective(handler):
            query = {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlparse(handler.path).query).items()}
            if query.get("cmd") == "dns-add_record" and query.get("type") == "CNAME":
                self.dh.fail.pop("dns-add_record", None)
            return original_add(handler)

        with mock.patch.object(MockDreamHost, "do_GET", selective):
            code, text = self.run_ddns("--replace-cname")
        self.assertEqual(code, 1)
        self.assertEqual(self.values(NAME, "CNAME"), ["target.example.net."], "the name must not be left empty")
        self.assertIn("restored CNAME", text)

    # ---------------------------------------------------------------- safety
    def test_dry_run_changes_nothing_but_says_what_it_would_do(self):
        self.record(NAME, "CNAME", "target.example.net.")
        self.record(OTHER, "A", IP2)
        code, text = self.run_ddns("--dry-run", "--replace-cname", names=(NAME, OTHER))
        self.assertEqual(code, 0)
        self.assertEqual(self.mutating_calls(), [])
        self.assertIn("[dry-run] would remove CNAME", text)
        self.assertIn(f"[dry-run] would add A {NAME} -> {IP1}", text)
        self.assertIn(f"[dry-run] would remove stale A {OTHER} -> {IP2}", text)

    def test_switching_from_dry_run_to_live_applies_immediately(self):
        self.run_ddns("--dry-run")
        self.assertEqual(self.values(NAME), [])
        self.clock += 60
        self.run_ddns()
        self.assertEqual(self.values(NAME), [IP1])

    def test_disagreeing_ip_services_change_nothing(self):
        self.set_ip(IP2, index=0)
        self.set_ip("93.184.216.99", index=1)
        code, text = self.run_ddns()
        self.assertEqual(code, 1)
        self.assertEqual(self.dh.calls, [])
        self.assertIn("no two ip services agree", text)

    def test_one_reachable_service_is_not_enough(self):
        self.set_ip(None, index=1)
        self.set_ip(None, index=2)
        self.assertEqual(self.run_ddns()[0], 1)
        self.assertEqual(self.dh.calls, [])

    def test_two_of_three_agreeing_is_enough(self):
        self.set_ip(None, index=2)
        self.assertEqual(self.run_ddns()[0], 0)
        self.assertEqual(self.values(NAME), [IP1])

    def test_private_or_bogus_addresses_are_never_published(self):
        for bad in ("192.168.1.10", "10.1.2.3", "100.64.1.1", "127.0.0.1", "not-an-ip"):
            self.set_ip(bad)
            self.assertEqual(self.run_ddns()[0], 1, bad)
            self.assertEqual(self.dh.calls, [], bad)

    def test_http_error_from_dreamhost_is_reported_without_leaking_the_key(self):
        self.dh.fail["dns-list_records"] = "http500"
        code, text = self.run_ddns()
        self.assertEqual(code, 1)
        self.assertIn("HTTP 500", text)

    def test_missing_key_or_records_is_a_usage_error(self):
        with mock.patch.dict(os.environ, {"DREAMHOST_API_KEY": ""}):
            self.assertEqual(self.run_ddns()[0], 2)

    # ---------------------------------------------------------------- verify
    def test_change_is_verified_against_the_nameservers_and_timed(self):
        self.dns.table[NAME] = (IP1, 60)
        code, text = self.run_ddns("--verify-ns", "127.0.0.1", "--dns-port", str(self.dns.port))
        self.assertEqual(code, 0)
        self.assertIn(f"VERIFIED {NAME} -> {IP1} on all 1 nameservers", text)
        self.assertIn("TTL 60s", text)

    def test_unpropagated_change_keeps_being_checked_until_it_appears(self):
        argv = ("--verify-ns", "127.0.0.1", "--dns-port", str(self.dns.port))
        _, text = self.run_ddns(*argv)
        self.assertIn("waiting:", text)
        self.assertEqual(self.dh.calls.count(("dns-list_records", None, None, None)), 1)
        self.clock += 120
        self.dns.table[NAME] = (IP1, 60)
        _, text = self.run_ddns(*argv)
        self.assertIn(f"VERIFIED {NAME} -> {IP1}", text)
        self.assertIn("120s after the change", text)
        self.assertEqual(self.dh.calls.count(("dns-list_records", None, None, None)), 1, "verifying needs no API calls")

    # ---------------------------------------------------------------- environment
    def env_argv(self, *extra):
        argv = ["--state-dir", self.state_dir, "--api-url", f"http://127.0.0.1:{self.dh.server_port}/"]
        for server in self.ips:
            argv += ["--ip-service", f"http://127.0.0.1:{server.server_port}/"]
        return argv + list(extra)

    def run_env(self, environ, *extra):
        out = io.StringIO()
        with mock.patch.dict(os.environ, environ), contextlib.redirect_stdout(out):
            code = ddns.main(self.env_argv(*extra))
        self.assertNotIn(KEY, out.getvalue())
        return code, out.getvalue()

    def test_records_can_come_from_the_environment(self):
        code, _ = self.run_env({"DREAMHOST_DDNS_RECORDS": f"{NAME}, {OTHER}"})
        self.assertEqual(code, 0)
        self.assertEqual(self.values(NAME), [IP1])
        self.assertEqual(self.values(OTHER), [IP1])

    def test_dry_run_and_cname_flags_can_come_from_the_environment(self):
        self.record(NAME, "CNAME", "target.example.net.")
        code, text = self.run_env({"DREAMHOST_DDNS_RECORDS": NAME, "DREAMHOST_DDNS_DRY_RUN": "1",
                                   "DREAMHOST_DDNS_REPLACE_CNAME": "yes"})
        self.assertEqual(code, 0)
        self.assertEqual(self.mutating_calls(), [])
        self.assertIn("[dry-run] would remove CNAME", text)

    def test_falsey_environment_flags_stay_off(self):
        self.record(NAME, "CNAME", "target.example.net.")
        code, _ = self.run_env({"DREAMHOST_DDNS_RECORDS": NAME, "DREAMHOST_DDNS_DRY_RUN": "0",
                                "DREAMHOST_DDNS_REPLACE_CNAME": "no"})
        self.assertEqual(code, 1, "a CNAME must be left alone unless replacing it is switched on")
        self.assertEqual(self.mutating_calls(), [])

    def test_command_line_records_win_over_the_environment(self):
        self.run_env({"DREAMHOST_DDNS_RECORDS": OTHER}, "--record", NAME)
        self.assertEqual(self.values(NAME), [IP1])
        self.assertEqual(self.values(OTHER), [])

    def test_environment_supplies_verify_servers_and_reconcile_hours(self):
        args = ddns.apply_env(ddns.argparse.Namespace(
            record=[], verify_ns=[], ip_service=None, dry_run=False, replace_cname=False, reconcile_hours=None),
            {"DREAMHOST_DDNS_VERIFY_NS": "ns1.example.net\nns2.example.net", "DREAMHOST_DDNS_RECONCILE_HOURS": "2",
             "DREAMHOST_DDNS_IP_SERVICES": "https://a.example https://b.example"})
        self.assertEqual(args.verify_ns, ["ns1.example.net", "ns2.example.net"])
        self.assertEqual(args.reconcile_hours, 2.0)
        self.assertEqual(args.ip_service, ["https://a.example", "https://b.example"])

    def test_version_flag(self):
        out = io.StringIO()
        with self.assertRaises(SystemExit) as ctx, contextlib.redirect_stdout(out):
            ddns.main(["--version"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn(ddns.__version__, out.getvalue())

    # ---------------------------------------------------------------- parsing
    def test_tab_format_responses_are_understood(self):
        tab = "success\naccount_id\tzone\trecord\ttype\tvalue\tcomment\teditable\n1\texample.com\thome.example.com\tA\t1.2.3.4\t\t1\n"
        rows = ddns.parse_response(tab)
        self.assertEqual(rows[0]["record"], "home.example.com")
        self.assertEqual(rows[0]["value"], "1.2.3.4")
        self.assertEqual(ddns.parse_response("success"), [])
        with self.assertRaises(ddns.ApiError) as ctx:
            ddns.parse_response("error\tslow_down_bucko (limit)")
        self.assertTrue(ctx.exception.rate_limited)

    def test_json_error_responses_raise_with_the_reason(self):
        # shape captured from the live API with a deliberately invalid key
        live = '{"result":"error","data":"invalid_api_key","reason":"The API key you provided does not exist."}'
        with self.assertRaises(ddns.ApiError) as ctx:
            ddns.parse_response(live)
        self.assertIn("invalid_api_key", str(ctx.exception))
        self.assertIn("does not exist", str(ctx.exception))
        with self.assertRaises(ddns.ApiError) as ctx:
            ddns.parse_response("error\ninvalid_api_key\tThe API key you provided does not exist.\n")
        self.assertIn("invalid_api_key", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
