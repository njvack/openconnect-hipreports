# openconnect-hipreports

`hipreport` writes an honest GlobalProtect HIP report for [OpenConnect](https://www.infradead.org/openconnect/)'s `--protocol=gp` mode. It reports what is actually installed and running on a Mac, described by a library of check files.

```sh
openconnect --protocol=gp --csd-user="$USER" --csd-wrapper=/usr/local/bin/hipreport vpn.example.edu
```

OpenConnect runs it with `--cookie`, `--client-ip`, `--client-ipv6`, `--md5` and `--client-os`, and submits whatever it prints. Unknown options are warned about and ignored, so a newer openconnect still gets a report. `--client-version` (or openconnect's `APP_VERSION`) sets the GlobalProtect version we claim; the default is 6.2.8-1045.

Nothing here needs root. Facts only root can read, such as whether Packet Filter is on, are reported as `n/a` unless `hipreport` runs as root.

## Build

```sh
go build -o hipreport ./cmd/hipreport
```

## Check files

Each `.toml` file describes one product in one HIP category. The built-in library in [`internal/checks/library`](internal/checks/library) is compiled into the binary, so a code signature on the binary covers it too. Apple's XProtect, Gatekeeper and FileVault are ordinary check files there.

```toml
# anti-malware/10-apple-xprotect.toml
category = "anti-malware"
vendor = "Apple Inc."
name = "Xprotect"
when.exists = "/Library/Apple/System/Library/CoreServices/XProtect.bundle"   # report only if installed

[fields]
version = { probe = "bundle_version", path = "/Library/Apple/System/Library/CoreServices/XProtect.bundle" }
defver = { probe = "bundle_version", path = "/Library/Apple/System/Library/CoreServices/XProtect.app" }
updated = { probe = "mtime", path = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist" }
real-time-protection = { value = "yes" }
```

Checks load from, in order:

1. the built-in library;
2. each `--checks-dir DIR` (default `/Library/Application Support/hipreport/checks.d`);
3. each `--dev-checks DIR`.

A file replaces one with the same relative path in an earlier source, so `checks.d/disk-backup/10-apple-time-machine.toml` containing `disabled = true` removes the built-in Time Machine check. Within a category, products are listed by file name.

Files in a `--checks-dir` are refused unless the file and every directory above it are owned by root and writable by nobody else (group-writable only for group wheel), the way `sudo` treats `sudoers`. Symlinks are followed and held to the same rule. `--dev-checks` skips that, for writing new checks, and marks the result untrusted on stderr and in `facts --json`.

### Categories

| Category | Fields (* required) |
| --- | --- |
| `anti-malware` | `version`*, `real-time-protection`*, `defver`, `engver`, `updated` (Unix time), `last-full-scan-time` (default `n/a`) |
| `disk-backup` | `version`*, `last-backup-time` (default `n/a`) |
| `disk-encryption` | `version`*, `drives`* (the `volumes` probe) |
| `firewall` | `version`*, `is-enabled`* |
| `patch-management` | `version`*, `is-enabled`* |
| `data-loss-prevention` | `version`* |
| `custom-plist` | no fields; `path` and `keys` for a custom plist check configured on the gateway |

### Probes

Each field is either `{ value = "..." }` or one probe. Check files cannot run code except through `command`.

| Probe | Parameters | Gives |
| --- | --- | --- |
| `bundle_version` | `path` | `CFBundleShortVersionString` of an app or bundle, or empty |
| `plist` | `path`, `key` (dotted for nested keys) | one value from a plist, XML or binary |
| `mtime` | `path` | modification time, as a Unix time |
| `exists` | `path` | `yes` or `no` |
| `process` | `path` | `yes` if that executable is running |
| `launchd` | `label` such as `system/com.example.d` or `gui/com.example.agent` | `yes` if loaded; `gui/` means the current user's session |
| `command` | `argv` (absolute path), `map` (list of `{ match = "regexp", value = "..." }`), optional `default` and `timeout` (seconds) | the value of the first `map` entry matching stdout, else `default` (`n/a`). Runs with `PATH=/usr/bin:/bin:/usr/sbin:/sbin`, no stdin, stderr discarded, 10 s timeout |
| `volumes` | | FileVault state of the boot volume, its Data volume and browsable internal disks, plus `All` |
| `os_version` | | `sw_vers -productVersion` |
| `privileged` | `fact`: `pf.enabled` | a fact only root can read; `n/a` otherwise |
| `all` | `all`: a list of probes | `yes` if every one is `yes`, `no` if any is `no`, else `n/a` |

## Commands

```sh
hipreport [--md5 ... --cookie ...]   # the report (wrapper mode)
hipreport facts [--json]             # what each check found, and how
hipreport check --policy FILE        # pass or fail per expected condition
hipreport lint [PATH...]             # validate the library, checks.d, and any files or dirs given
hipreport record [-o FILE]           # record this machine's answers as a test fixture
```

`--debug` (or `HIPREPORT_DEBUG=1`) logs every command and its output to stderr.

### Policies

The gateway never says whether a report passed. Write down what the firewall admins say it requires, and `hipreport check` tells you whether this Mac meets it, with the value and the probe behind each answer:

```toml
[[require]]
category = "disk-encryption"
field = "drive:All"
equals = "encrypted"

[[require]]
description = "XProtect definitions are recent"
category = "anti-malware"
name = "Xprotect"
field = "version"
min_version = "5300"

[[require]]
category = "patch-management"      # some product present
```

Each requirement passes if any matching product passes. Tests are `equals`, `matches` (regexp) and `min_version`.

## Tests

`go test ./...` runs everywhere. The golden report in `testdata/mac-basic.golden.xml` comes from a synthetic Mac in `testdata/mac-basic.toml`; regenerate it with `go test ./internal/report -update` and review the diff. `hipreport record` writes the same kind of fixture from a real Mac. A recording holds that Mac's host name, MAC addresses and IP addresses, so scrub it before committing one. `--fixture FILE` replays one instead of reading the system.

`e2e/run.sh` runs a real openconnect with `hipreport` as its `--csd-wrapper` against [gp-fake-gateway](https://github.com/njvack/gp-fake-gateway) and checks the report the gateway received (Linux, root).

`scripts/parity.sh` compares `hipreport` with the old `hipreport.zsh` on a Mac, ignoring only the timestamp and Packet Filter. CI runs it on GitHub's macOS runners; `hipreport.zsh` stays until it also matches on a real work Mac.
