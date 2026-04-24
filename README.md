# CVE-2026-25895 — FUXA <= 1.2.9 Unauthenticated Path Traversal to Remote Code Execution

Unauthenticated, pre-auth arbitrary file write against FUXA, a Node.js-based
SCADA/HMI platform. Chains to remote code execution via several distinct
post-write primitives. Works even when `secureEnabled = true` (authentication
on) because the vulnerable endpoint has no middleware attached.

| Field          | Value                                           |
| -------------- | ----------------------------------------------- |
| CVE ID         | CVE-2026-25895                                  |
| Affected       | FUXA `<= 1.2.9`                                 |
| Patched        | FUXA `1.2.10`                                   |
| Vendor         | frangoteam / FUXA                               |
| Attack vector  | Network (HTTP/HTTPS)                            |
| Authentication | None required                                   |
| Impact         | Arbitrary file write, remote code execution     |
| CVSS v3.1      | 9.8 (Critical) — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Researcher     | Anthony Cihan (`Hann1bl3L3ct3r`)                |

## Summary

FUXA's `POST /api/upload` endpoint (`server/api/projects/index.js:193`) is
registered without middleware, bypassing both the `secureFnc` JWT / API-key
check and the admin permission gate applied to every other project-management
endpoint. Inside the handler, the JSON body field `destination` is concatenated
into a filesystem path with only a leading underscore and no normalization or
containment check:

```js
let destinationDir = path.resolve(runtime.settings.appDir, `_${destination}`);
filePath          = path.join(destinationDir, fullPath || fileName);
fs.writeFileSync(filePath, basedata, encoding);
```

A `destination` value of the form `a/../../../../../etc` (where `a` absorbs
the leading underscore prefix) makes Node's `path.resolve` climb out of
`appDir` to any location the FUXA process can write. Because `fs.writeFileSync`
is preceded by a conditional `fs.mkdirSync(dir, { recursive: true })`, the
attacker can also create parent directories as needed.

The result is an unauthenticated arbitrary file write primitive reachable on
the default HTTP port (`1881`), exploitable pre-auth regardless of whether
the FUXA admin has enabled login.

## Impact

An unauthenticated remote attacker can:

- Write or overwrite any file the FUXA service account can reach
- Replace `settings.js` to achieve code execution on the next FUXA restart
- Drop a cron job (`/etc/cron.d/<file>`) for code execution within 60 seconds
  when FUXA runs as `root` (the default in the vendor's Docker image)
- Install an HTTP webshell listener bound inside the FUXA Node process
- Drop SSH public keys into `/root/.ssh/authorized_keys` or any user's
  `~/.ssh/authorized_keys`
- Enumerate the local user account running FUXA and other accounts present
  on the host via a filesystem-level side channel

This is a pre-auth critical severity finding on an ICS/SCADA platform used
to operate industrial processes.

## Affected Versions

| Version    | Status         |
| ---------- | -------------- |
| `<= 1.2.9` | Vulnerable     |
| `1.2.10+`  | Patched        |

Confirmed exploitable against a clean install of FUXA 1.2.9 on Ubuntu Server.

## Proof of Concept

Single-file Python 3 script, one third-party dependency (`requests`).

```bash
pip install requests
python3 fuxapwn.py --help
```

### Quick unauthenticated recon

Identify the running OS user, Node-RED exposure, and any other accounts on
the host without writing anything unusual:

```bash
python3 fuxapwn.py -u http://target:1881 --mode recon \
    --probe-root --probe-home
```

### Prove the write primitive

Write a neutral `/tmp/healthcheck` marker (no CVE-specific IOCs in the
filename or content):

```bash
python3 fuxapwn.py -u http://target:1881 --mode canary
```

### One-shot RCE

If FUXA runs as `root`, drop a cron file that fires within 60 seconds with
no FUXA restart required:

```bash
python3 fuxapwn.py -u http://target:1881 --mode cron \
    --cron-cmd 'id > /tmp/fx.txt 2>&1'
```

### Persistent webshell via `settings.js` replacement

Install an HTTP webshell listener inside the FUXA Node process (activates on
next cold start, since `require()` caches modules), then drop into an
interactive REPL once FUXA restarts:

```bash
# Stage the payload — replaces settings.js but preserves the target's
# real configuration (uiPort, allowedOrigins, secureEnabled, etc.) so the
# application keeps serving normally.
python3 fuxapwn.py -u http://target:1881 --mode webshell \
    --appdata /opt/FUXA/server/_appdata --ws-port 31337

# Once FUXA restarts, connect to the installed webshell.
python3 fuxapwn.py -u http://target:1881 --mode webshell-exec \
    --ws-host target --ws-port 31337 \
    --ws-path /_abc123 --ws-token <printed-above> --interact
```

## Operating Modes

| Mode            | Purpose                                                       |
| --------------- | ------------------------------------------------------------- |
| `recon`         | Unauthenticated info leak via `GET /api/settings`; infers running OS user from absolute paths; reports Node-RED status; optional `--probe-root` and `--probe-home` active probes |
| `canary`        | Proof of the file-write primitive with a neutral default path |
| `settings-rce`  | Replaces `settings.js` with a payload that runs a configurable command on the next FUXA cold start |
| `ssh-key`       | Writes a public key to a target user's `authorized_keys`      |
| `drop`          | Arbitrary file drop to any absolute path                      |
| `cron`          | Drops `/etc/cron.d/<name>` for RCE within 60 seconds without waiting for a FUXA restart (requires FUXA running as `root`) |
| `webshell`      | Installs an HTTP webshell listener inside the FUXA Node process via `settings.js` replacement (activates on next cold start) |
| `webshell-exec` | Client for an already-installed webshell; single command or `--interact` REPL |

Full per-mode flag reference: `python3 fuxapwn.py --help`.

## Technical Notes

### Unauthenticated configuration leak

`GET /api/settings` (`server/api/index.js:103`) is registered without
middleware and returns the live runtime configuration, lightly redacted
(the server deletes `secretCode` and `smtp.password` before sending). The
remaining fields leak absolute paths (`appDir`, `workDir`, `userSettingsFile`,
`logsDir`, `uploadFileDir`) that typically identify the service user, plus
`nodeRedEnabled`, which is a direct tell for a secondary unauthenticated
RCE path (see below).

### Running-user enumeration on non-root, non-Docker installs

When FUXA is launched via `npm start` under a local user account and install
paths don't encode the user (e.g. the install lives under `/opt`, `/tmp`, or
a generic `/app`), and `/root/` is not writable, the POC falls back to
iterating `/home/<candidate>/` with zero-byte writes.

The FUXA upload handler conditionally calls
`fs.mkdirSync(parent, { recursive: true })` before `fs.writeFileSync`, which
creates an EACCES ambiguity: a non-existent `/home/<user>/` fails with
`EACCES` on the `mkdir` attempt (the process cannot create directories under
root-owned `/home/`), while an existing `/home/<other>/` with mode `0700`
fails `EACCES` on the write itself. Same errno, different meaning. The POC
disambiguates by parsing the syscall token out of the server-forwarded
`err.message` (libuv format `"<CODE>: <reason>, <syscall> '<path>'"`) and
only reports `EACCES`-on-open (or any non-`mkdir` syscall) as "other user
exists." This eliminates the false-positive lateral-movement list that a
naive errno-only probe would produce.

### Node-RED secondary RCE path

If `nodeRedEnabled = true` in the leaked settings, FUXA's embedded Node-RED
admin endpoints (`/nodered/flows/deploy`, etc.) are reachable
unauthenticated because of a Referer-header whitelist check
(`node-red/index.js:134-136`) that accepts any request whose `Referer`
contains `/editor`, `/viewer`, or `/lab`. This yields instant unauthenticated
RCE via a function node without requiring a restart. The `recon` mode flags
this condition; operators should prefer it when available.

### `settings.js` payloads preserve target configuration

When generating a `settings.js` replacement (modes `settings-rce` and
`webshell`), the POC first fetches the live config via `/api/settings` and
JSON-serializes it as the `module.exports` body (JSON is a valid JavaScript
object literal subset). This preserves the target's `uiPort`,
`allowedOrigins`, `secureEnabled`, and other runtime settings so the
application continues to serve normally after the replacement. The POC warns
explicitly when the target has `secureEnabled = true` or an `smtp` block,
since the server-side redaction removes `secretCode` (JWT fallback will kick
in) and `smtp.password` (email will break until manually restored).

## Detection / Indicators

- HTTP access log entries: `POST /api/upload` from unauthenticated sources,
  particularly with `destination` values containing `..` or absolute
  filesystem paths in the response
- `GET /api/settings` from unauthenticated sources (normally only used by
  the authenticated UI)
- Files matching `/tmp/healthcheck*`, `/tmp/.fuxa-probe-*`, or
  `/home/*/.fuxa-probe-*` (default canary and probe marker filenames — the
  POC allows overriding these to avoid obvious IOCs, so absence does not
  rule out exploitation)
- Modified timestamps on `settings.js`, `/etc/cron.d/*`, or
  `~/.ssh/authorized_keys` that do not correspond to an administrator
  action
- New listeners on the FUXA host bound to unexpected ports (webshell mode
  binds a configurable port inside the Node process)

## Mitigation

- **Upgrade to FUXA 1.2.10 or later.** The `/api/upload` endpoint is
  protected by the standard middleware chain in the patched release.
- Network-segment the FUXA management interface. ICS/SCADA HMIs should not
  be reachable from untrusted networks.
- If immediate upgrade is not possible, front FUXA with a reverse proxy
  that blocks unauthenticated requests to `/api/upload` and `/api/settings`.
- Run FUXA as a dedicated unprivileged service account. This does not
  prevent exploitation but significantly reduces blast radius (no `/root/`
  write, no `/etc/cron.d/` write, no host-wide persistence via cron).
- Disable Node-RED (`nodeRedEnabled = false`) if it is not actively used.


## References

- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-25895>
- Vendor: <https://github.com/frangoteam/FUXA>
- Patch: FUXA release `1.2.10`
- Vulnerable source: `server/api/projects/index.js:193` in FUXA `1.2.9`

## Credit

Research, PoC, and writeup by **Anthony Cihan** (`Hann1bl3L3ct3r`), Lead of
Offensive Security.

## Authorization and Legal

This repository contains functional exploit code for a critical vulnerability
in an ICS/SCADA product. It is published under responsible-disclosure
principles, after vendor patching, for the benefit of defenders (detection
authors, incident responders) and authorized security testers.

**Use only against systems you own or for which you have explicit, written
authorization to test.** Unauthorized use of this code against third-party
systems is illegal in most jurisdictions and will be treated as such by the
author. The author accepts no liability for misuse.

If you are a FUXA operator and want help validating your patch level against
this PoC under controlled conditions, contact the author.

## License

Released for authorized security-testing and defensive-research purposes.
See `LICENSE` for full terms.
