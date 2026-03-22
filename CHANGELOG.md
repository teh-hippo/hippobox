# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-22

### Added

- OCI image pulling from any registry (Docker Hub, GHCR, etc.) with anonymous token auth
- Fat manifest resolution for multi-platform images (linux/amd64)
- Streaming layer download with SHA256 verification
- Automatic image caching and layer deduplication
- Layer pruning on image update (removes orphaned layers)
- Full namespace isolation (mount, UTS, IPC, PID, network)
- Overlayfs-backed container filesystems with per-container writable layers
- Rootless mode with automatic user namespace setup via `unshare`
- Port forwarding via `pasta` (from the `passt` project)
- Volume mounts (bind mounts with read-only support)
- Environment variable overrides (`--env KEY=VALUE`)
- Seccomp BPF filtering for blocked syscalls
- Sensitive `/proc` path masking and read-only `/sys`
- `PR_SET_NO_NEW_PRIVS` enforcement
- PID 1 init handling with signal forwarding
- Automatic container cleanup on exit
- Stale container garbage collection on startup
- `LD_PRELOAD` rename shim for rootless EXDEV workaround
- `hippobox pull` command
- `hippobox run` command with auto-pull
- `hippobox images` command
- `hippobox clean` command

[0.1.0]: https://github.com/teh-hippo/hippobox/releases/tag/v0.1.0
