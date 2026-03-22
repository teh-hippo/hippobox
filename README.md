# hippobox

[![CI](https://github.com/teh-hippo/hippobox/actions/workflows/ci.yml/badge.svg)](https://github.com/teh-hippo/hippobox/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/hippobox.svg)](https://crates.io/crates/hippobox)
[![License](https://img.shields.io/crates/l/hippobox.svg)](LICENSE-MIT)

A lightweight Linux container manager written in Rust.
Pulls OCI images from any registry, sets up an isolated container using raw Linux primitives, and runs your command.
No runc, containerd, or other runtime wrappers involved.

> **Note:** hippobox is an experimental project built for learning and exploration.
> It is not intended for production use.
> If you need a production container runtime, use Docker, Podman, or a similar tool.

## Features

- Pull images from any OCI-compliant registry (Docker Hub, GHCR, etc.)
- Run containers with full namespace isolation (mount, UTS, IPC, PID, network)
- Rootless mode with automatic user namespace setup
- Overlayfs-backed container filesystems with per-container writable layers
- Port forwarding via `pasta` (from the `passt` project)
- Volume mounts (bind mounts, read-only support)
- Environment variable overrides
- Seccomp BPF filtering and `/proc` path masking
- Automatic image caching and layer deduplication
- Containers are always temporary and cleaned up on exit

The release binary is around 2 MB.

## Requirements

- Linux (x86_64). Tested under WSL2
- Kernel 5.11+ for rootless overlayfs support
- cgroup v2 for rootful mode
- `unshare` from util-linux for rootless bootstrap
- `pasta` from `passt` for port forwarding (`-p`)

hippobox is Linux-only.
It will not run on macOS or Windows outside of WSL.

## Usage

```bash
# Pull an image
hippobox pull docker.io/nginx:latest

# Run a container (auto-pulls if not cached)
hippobox run docker.io/nginx:latest

# Run with a custom command
hippobox run docker.io/nginx:latest /bin/sh -c "echo hello"

# Environment overrides
hippobox run --env POSTGRES_HOST_AUTH_METHOD=trust docker.io/postgres:16-alpine

# Volume mounts
hippobox run -v /host/data:/data:ro docker.io/alpine:latest ls /data

# Port forwarding
hippobox run -p 8080:80 docker.io/nginx:latest

# List cached images
hippobox images

# Clean all cached images and layers
hippobox clean
```

Images require an explicit registry prefix (`docker.io/`, `ghcr.io/`, etc).

If you run `hippobox` as a non-root user, it automatically switches to rootless mode.

## Building

hippobox does not provide pre-built binaries at this time.

```bash
cargo build --release
```

## Rootless Mode

Rootless mode is automatic.
If hippobox is not running as root, it bootstraps through a user namespace via `unshare`.

What changes in rootless mode:

- cgroups are skipped
- `/proc` is bind-mounted from the host so `/dev/stderr` and friends work
- `/sys` stays out of the container
- `/dev` device nodes are bind-mounted from a staging directory inside the rootfs
- Directory renames work via an `LD_PRELOAD` shim that handles EXDEV transparently

Host requirements for rootless:

- Linux user namespaces must be enabled
- `unshare` from util-linux must be installed
- `/etc/subuid` and `/etc/subgid` should provide a subordinate ID range for your user
- `newuidmap` and `newgidmap` from util-linux should be available

Limitations:

- Rootless containers cannot bind privileged ports unless the host allows it
- The rename shim covers dynamically-linked binaries only (statically-linked Go/Rust binaries with directory renames may still see EXDEV)
- Rootless mode is not a production isolation boundary

## Roadmap

- [ ] Pre-built release binaries for x86_64
- [ ] Multi-architecture builds (ARM64, etc.)
- [ ] Integration tests against release binaries in CI
- [ ] `hippobox ps` and `hippobox exec`
- [ ] Configurable resource limits (`--memory`, `--cpus`, `--pids`)
- [ ] Digest-based image refs (`image@sha256:...`)
- [ ] Auth for private registries
- [ ] Bridge networking with NAT
- [ ] zstd layer support

## Licence

Licensed under either of

- [Apache Licence, Version 2.0](LICENSE-APACHE)
- [MIT Licence](LICENSE-MIT)

at your option.
