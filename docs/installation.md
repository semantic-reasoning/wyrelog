# Installation Guide

## Requirements

- A C17 compiler (GCC or Clang), `meson` >= 1.1.0, `ninja`, `pkg-config`,
  `patch`, `python3`
- Libraries: GLib/GIO 2.0, SQLite 3 (with `sqlite3_serialize` and
  `sqlite3_deserialize`), libsodium
- Optional: libsoup 3 (`-Denable_client`), tpm2-tss (`-Denable_tpm`)
- DuckDB is fetched automatically as a Meson subproject (prebuilt binary by
  default)

## 1. Install dependencies

Debian / Ubuntu:

```sh
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  meson ninja-build pkg-config patch python3 gcc g++ \
  libglib2.0-dev libsqlite3-dev libsoup-3.0-dev libsodium-dev libtss2-dev
```

macOS (Homebrew):

```sh
brew install meson ninja pkg-config glib sqlite libsoup libsodium gpatch
```

## 2. Get the source

```sh
git clone https://github.com/semantic-reasoning/wyrelog.git
cd wyrelog
```

## 3. Configure and build

The fact store, audit and fault-injection suites are disabled by default.
Enable them for a full build:

```sh
meson setup builddir \
  -Denable_fact_store=enabled \
  -Denable_audit=enabled \
  -Denable_fault_injection=enabled \
  -Dduckdb_source=prebuilt
meson compile -C builddir
```

| Option | Purpose |
| --- | --- |
| `enable_fact_store` | DuckDB-backed Datalog fact store |
| `enable_audit` | Audit subsystem |
| `duckdb_source` | `prebuilt` (default, download) or `subproject` (compile from source) |
| `enable_client` | Build the libsoup-based client |
| `enable_tpm` / `require_tpm` | TPM support, optional or mandatory |

See `meson.options` for the complete list.

## 4. Test

```sh
python3 tools/report-inactive-suites.py --strict builddir
meson test -C builddir
```

## 5. Install

```sh
sudo meson install -C builddir
```

This installs `wyrelogd`, `wyctl` and the access-control templates. For the
packaged Linux deployment (systemd units, service users, key provisioning),
follow the [Operator runbook](operator-runbook.md).

## Troubleshooting

- **Suite not registered:** the matching `enable_*` option is still
  `disabled`.
- **SQLite error:** SQLite must provide `sqlite3_serialize` and
  `sqlite3_deserialize`.
- **Reconfigure:** `meson setup --reconfigure builddir <options>`.
