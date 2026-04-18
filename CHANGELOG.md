# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
