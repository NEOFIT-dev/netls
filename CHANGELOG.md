# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `Filter::proto` and `Filter::state` now take `Proto` and `State` enums
  instead of strings.
- `sort_connections` now takes a `SortKey` enum instead of a string.
- `Connection::fd_usage` changed from `Option<(usize, usize)>` to
  `Option<FdUsage>` with named `open` and `soft_limit` fields.
- Modules `tui`, `tui_common`, `watch`, `output`, `services` are no longer
  part of the library API (moved into the binary crate).
- Modules `dns`, `docker`, `platform` are now `pub(crate)`.
- `Connection::local` and `Connection::remote` now carry raw addresses
  (e.g. `[::1]:80`). The CLI still prints `localhost:80` / `*:80` via
  `compact_addr` at render time.

### Added

- `FromStr` impls for `Proto`, `State`, `SortKey`.
- `ParseEnumError` returned by those `FromStr` impls.
- `docker_proxy_service` replaces `resolve_docker_name` and returns
  just the service name.
- `#[non_exhaustive]` on `Proto`, `State`, `Error`, `Summary`, `ConfigError`,
  `FdUsage`, `ParseEnumError`, `SortKey`.

### Removed

- `NO_PERMISSION`, `Connection::state_str`, `Connection::process_display`,
  `format_process_text` (CLI display helpers; now binary-only).

### Fixed

- Docker socket reads now have a 2s read/write timeout.
- `Connection::text_matches` now lowercases the query internally
  (previously required the caller to pre-lowercase or silently missed).

## [0.2.0] - 2026-04-19

### Added

**Configuration files** (`~/.config/netls/config.toml`, `NETLS_CONFIG`, or `--config PATH`):
- `[defaults]`: defaults for any long-form CLI flag
- `[profiles.<name>]`: named overlays activated with `--profile <name>`
- `[ports]`: port to service-name overrides

**New CLI flags:**
- `--config PATH`: load a specific file
- `--profile NAME`: activate a named profile
- `--init-config`: write a starter config (refuses to overwrite without `--force`)
- `--show-config`: print the resolved effective config with origin per field

**Quality of life:**
- `[ports]` non-empty auto-enables `--service-names`
- `NETLS_CONFIG` paths starting with `~` are expanded
- When `--profile NAME` is active, prints `applied: ... from <path>` to stderr

**Library API:**
- New module `netls::config` (`Config`, `Defaults`, `LoadedConfig`, `load`)
- New public constants `netls::VALID_{STATES,PROTOS,SORT,GROUP_BY}`

### Changed

- `--service-names` now reads `/etc/services` after the curated built-in map.
  Previously only ~28 hand-picked ports were annotated; thousands of IANA
  names are now resolved automatically. Built-in entries still win ties.

## [0.1.1] - 2026-04-18

### Fixed

- Build failure on `aarch64-unknown-linux-gnu`: replaced hard-coded `[i8; 256]`
  hostname buffer in `src/dns.rs` with `[libc::c_char; 256]`. `c_char` is `i8`
  on x86_64 but `u8` on aarch64, breaking the `getnameinfo` call signature on
  ARM64 Linux.

## [0.1.0] - 2026-04-18

Initial release.

### Added

- Cross-platform connection snapshot (Linux via `/proc/net/*`, macOS via `libproc`)
- Output formats: table (default), JSON (one object per line, `--pretty` available), CSV
- Watch mode (`--watch [N]`) with live diff highlighting new/closed connections
- Interactive TUI (`--tui`)
- Filters: `--port`, `--pid`, `--process`, `--state`, `--proto`, `--ipv4`/`--ipv6`, `--no-loopback`, `--listen`, `--all`
- Aggregation: `--summary` (with `--warn-timewait`), `--top N`, `--count`, `--sort`, `--group-by`
- Snapshot/diff: `--save FILE`, `--diff FILE`
- Port utilities: `--check-port`, `--kill PORT [--force]`, `--wait-for PORT [--timeout SECS]`
- Extra columns: `--queues`, `--service-names`, `--age`, `--tree`, `--systemd`, `--fd`, `--cmdline`, `--containers`, `--resolve-dns`, `--resolve-proxy`
- Library API for programmatic access (`netls::snapshot`, `Filter`, `Connection`)
