# hippobox

Lightweight Linux container manager built in Rust. Uses raw Linux primitives — no runc, containerd, or other runtime wrappers.

## Requirements

- Linux kernel 5.2+ with cgroup v2
- Root privileges

## Usage

```bash
# Pull an image
hippobox pull docker.io/nginx:latest

# Run a container (auto-pulls if not cached)
hippobox run docker.io/nginx:latest

# Run with custom command
hippobox run docker.io/nginx:latest /bin/sh -c "echo hello"

# List cached images
hippobox images

# Clean all cached images and layers
hippobox clean
```

Images require an explicit registry prefix (`docker.io/`, `ghcr.io/`, etc).

Containers are always temporary — they're cleaned up on exit. No `--rm` flag needed.

## How it works

- **OCI registry client** — anonymous token auth, fat manifest resolution, streaming layer download with sha256 verification
- **overlayfs** — image layers stacked read-only, per-container writable upper layer
- **Linux namespaces** — mount, UTS, IPC isolation; host PID namespace for now
- **pivot_root** — full filesystem isolation with proper mount propagation
- **Re-exec handoff** — lightweight startup, signal forwarding, and wait handling
- **Security** — `PR_SET_NO_NEW_PRIVS`, sensitive `/proc` path masking, read-only `/sys`

## Building

```bash
cargo build --release
```

Release binary is ~2MB with the optimized profile.

## TODO

- [ ] `hippobox ps` — list running containers (daemon/background mode)
- [ ] `hippobox exec` — attach to running container
- [ ] PID namespace + PID 1 init handling
- [ ] `/etc/hosts` bind-mount
- [ ] Configurable resource limits (`--memory`, `--cpus`, `--pids`)
- [ ] Capability drops (Docker-standard allowlist)
- [ ] User field parsing (numeric uid, name → /etc/passwd lookup)
- [ ] Digest-based image refs (`image@sha256:...`)
- [ ] Auth for private registries (login/credentials)
- [ ] Bridge networking with NAT
- [ ] zstd layer support
- [ ] Rootless containers (user namespaces)
- [ ] seccomp profiles
