# dreamhost-ddns

Dynamic DNS for domains whose DNS is hosted at [DreamHost](https://www.dreamhost.com/):
keeps one or more **A records** pointed at the machine's current public IPv4 address.
A single standard-library Python file plus a hardened systemd service and timer. No
dependencies, no daemon.

DreamHost has no dynamic-DNS feature of its own, but it does have a
[DNS API](https://help.dreamhost.com/hc/en-us/articles/217555707-DNS-API-commands);
this drives it carefully.

## Why not just CNAME to a DDNS provider?

That works until it doesn't. Some dynamic-DNS providers' nameservers mis-answer
queries for names that *do* exist (for example `NXDOMAIN` with no SOA for an `AAAA`
lookup where the name only has an `A` record). Resolvers disagree about that
(one public resolver intermittently returns `NXDOMAIN` for the whole chain), and
Let's Encrypt's validator gets `SERVFAIL` and refuses to issue or renew. Serving the
A record from your own DreamHost zone takes the provider's nameservers out of the path.

## What it does, and what it deliberately doesn't

- **The public IP is only trusted when at least two independent services agree** on the
  same globally-routable IPv4 address. Private, CGNAT and malformed answers are never
  published, and nothing changes if the services disagree.
- **DreamHost's API is called only when something changed**: the IP, dry-run vs live mode,
  a previous run left work undone, or the periodic reconcile is due. The API has hourly and
  daily rate limits, so ordinary minutes make no API call at all. Errors back off; a rate
  limit backs off for an hour.
- **A new record is added before stale ones are removed**, so a name is never left empty. If
  the add fails, the existing record is left alone.
- **It only touches the names you list, and only their A records.** Other record types at the
  same name (TXT, MX…), other names, and records DreamHost marks non-editable are never
  modified. An existing CNAME at a listed name is left alone and reported, unless you
  opt in to replacing it; if adding the A record then fails, the CNAME is put back.
- **Dry run** logs exactly what it would do and changes nothing.
- **Propagation is measured, not assumed.** After a change it asks DreamHost's authoritative
  nameservers directly and logs how long the record took to appear and its TTL.
- The API key is read from a root-only file and scrubbed from all output.

## Status

Tested against mock DreamHost, IP-lookup and DNS servers (`tests/`, run in CI) and against a
live DreamHost account: listing records, adding an A record, replacing a CNAME with an A record
(three names in one run) and the propagation check all behave as documented. Removing a stale
A record after the IP changes is covered by the mock tests but has not yet been exercised
against a live account. Start in dry-run mode and read the plan first. Reports of what you see
are welcome.

### Propagation timing

DreamHost's own help pages say API changes take "several hours to propagate". In two live tests
(a single new A record, then three CNAMEs replaced by A records at once; TTL 60 seconds) the
change began to appear on some of DreamHost's three authoritative nameservers within a few
minutes, then **flapped between the old and new answers** for several more, and all three
nameservers answered consistently about 12–14 minutes after the change; public resolvers followed
within the record's TTL. Two observations are not a guarantee.

Plan for up to about 15 minutes after a change, and wait for the
`VERIFIED … on all N nameservers` log line before anything that validates the name from the
outside, such as requesting a certificate: until then some nameservers still answer with the old
record (or `NXDOMAIN` for a new name), and a validator that hits one of them will fail.

## Requirements

- Python 3.9 or newer (standard library only).
- A DreamHost account with the domain's DNS hosted at DreamHost, and an API key.
- systemd for the supplied units. Anywhere else, run the script from cron (see below).
- Outbound HTTPS, and UDP/53 to DreamHost's nameservers if you use `DREAMHOST_DDNS_VERIFY_NS`.

## Install

1. **Create an API key** in the DreamHost panel's API page
   (<https://panel.dreamhost.com/?tree=home.api>), limited to the functions
   `dns-list_records`, `dns-add_record` and `dns-remove_record`.

2. **Install** from a checkout or an extracted release (same layout):

   ```bash
   git clone https://github.com/majorsilence/dreamhost-ddns.git && cd dreamhost-ddns
   sudo install -m 0755 dreamhost-ddns.py /usr/local/sbin/dreamhost-ddns
   sudo install -m 0644 systemd/dreamhost-ddns.service systemd/dreamhost-ddns.timer /etc/systemd/system/
   sudo install -m 0600 -o root -g root systemd/dreamhost-ddns.env.example /etc/dreamhost-ddns.env
   ```

3. **Configure** — edit `/etc/dreamhost-ddns.env`: your `DREAMHOST_API_KEY` and the
   `DREAMHOST_DDNS_RECORDS` to manage. It ships with `DREAMHOST_DDNS_DRY_RUN=1`.

4. **Start it and read the plan:**

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now dreamhost-ddns.timer
   journalctl -u dreamhost-ddns -f
   ```

   You should see the detected public IP and lines such as
   `[dry-run] would add A home.example.com -> <ip>`.

5. **Go live** once the plan is what you expect: set `DREAMHOST_DDNS_DRY_RUN=0` (or delete
   the line) in `/etc/dreamhost-ddns.env`. The next run applies it; you should then see
   `VERIFIED home.example.com -> <ip> on all 3 nameservers <N>s after the change (record TTL <T>s)`.

The API key file is read by systemd itself, so the service can run as a throwaway
dynamic user with a locked-down sandbox (`systemd/dreamhost-ddns.service`).

### Without systemd

```bash
DREAMHOST_API_KEY=… dreamhost-ddns --record home.example.com --state-dir ~/.local/state/dreamhost-ddns
```

Run it every minute from cron. The default state directory is `/var/lib/dreamhost-ddns`.

## Moving a name off a CNAME

If the name currently has a CNAME, the updater refuses to touch it and says so. Either delete
the CNAME at DreamHost yourself, or set `DREAMHOST_DDNS_REPLACE_CNAME=1`: the CNAME is removed
and the A record added straight away (and the CNAME is restored if the add fails). Expect a few
seconds with no record, plus DreamHost's propagation (see [Status](#status)) — do this for a
name you can afford to lose briefly, and try a dry run first.

## Configuration

Everything can be set as a command-line option or an environment variable
(the command line wins). The API key is environment-only: `DREAMHOST_API_KEY`.

| Environment variable | Option | Meaning |
|---|---|---|
| `DREAMHOST_API_KEY` | – | DreamHost API key (required) |
| `DREAMHOST_DDNS_RECORDS` | `--record NAME` (repeatable) | names to manage, space/comma separated (required) |
| `DREAMHOST_DDNS_DRY_RUN` | `--dry-run` | log the plan, change nothing |
| `DREAMHOST_DDNS_REPLACE_CNAME` | `--replace-cname` | allow replacing a CNAME at a listed name |
| `DREAMHOST_DDNS_VERIFY_NS` | `--verify-ns HOST` (repeatable) | authoritative servers to check after a change |
| `DREAMHOST_DDNS_RECONCILE_HOURS` | `--reconcile-hours N` | re-list records at least this often (default 6) |
| `DREAMHOST_DDNS_IP_SERVICES` | `--ip-service URL` (repeatable) | IP-lookup services; two must agree |
| – | `--state-dir DIR` | state directory (default `$STATE_DIRECTORY` or `/var/lib/dreamhost-ddns`) |
| – | `--status` | print the saved state and exit |
| – | `--version` | print the version |

## How it works

Every minute (the timer interval) it asks the IP services for the public address. Only if the
address changed, the mode changed, work was left undone, or the reconcile is due does it call
DreamHost: list the zone's records, then for each managed name add the new A record, then remove
stale ones. State (last IP, pending verification, backoff) is a small JSON file in the state
directory; `dreamhost-ddns --status` prints it. A lock file prevents overlapping runs.

## Limitations

- IPv4 only, one address per name, one host per name.
- It reconciles A records; it doesn't manage AAAA, subdomain delegation or wildcard records.
- DreamHost's rate limits apply; the number of API calls is kept minimal but not zero.
- If your ISP puts you behind carrier-grade NAT, the public address isn't yours and DNS can't
  fix that — the updater refuses non-global addresses but can't detect every such case.

## Development

```bash
python3 -W error -m unittest discover -s tests -v
```

The tests need no network or credentials: they run the updater against local mock DreamHost,
IP-lookup and UDP DNS servers, covering add-before-remove ordering, CNAME restore, rate-limit
backoff, dry run, propagation verification and that the key never reaches the output.

## Releasing

Bump `__version__` in `dreamhost-ddns.py`, commit, and push a matching tag
(`git tag vX.Y.Z && git push origin vX.Y.Z`). CI verifies the tag matches, runs the tests, and
publishes a release with a tarball (script, systemd units, README, LICENSE) and `sha256sums.txt`.

## Disclaimer

Not affiliated with or endorsed by DreamHost. It changes live DNS records: try a dry run first
and keep your own record of what your zone should contain. Use at your own risk.

## License

MIT
