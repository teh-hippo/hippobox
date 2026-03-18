# hippobox

Lightweight Linux container manager built in Rust. Uses raw Linux primitives — no runc, containerd, or other runtime wrappers.

## Requirements

- Linux kernel 5.2+
- cgroup v2 for the rootful path
- Root privileges for the full feature set
- `unshare` from util-linux for rootless bootstrap

## Usage

```bash
# Pull an image
hippobox pull docker.io/nginx:latest

# Run a container (auto-pulls if not cached)
hippobox run docker.io/nginx:latest

# Run with custom command
hippobox run docker.io/nginx:latest /bin/sh -c "echo hello"

# Run with an environment override
hippobox run --env POSTGRES_HOST_AUTH_METHOD=trust docker.io/postgres:16-alpine

# List cached images
hippobox images

# Clean all cached images and layers
hippobox clean
```

Images require an explicit registry prefix (`docker.io/`, `ghcr.io/`, etc).

Containers are always temporary — they're cleaned up on exit. No `--rm` flag needed.

If you run `hippobox` as a non-root user, it automatically switches to rootless mode.

`--env KEY=VALUE` overrides image-provided environment variables for the container.

## How it works

- **OCI registry client** — anonymous token auth, fat manifest resolution, streaming layer download with sha256 verification
- **overlayfs** — image layers stacked read-only, per-container writable upper layer
- **Linux namespaces** — mount, UTS, IPC isolation; host PID namespace for now
- **pivot_root** — full filesystem isolation with proper mount propagation
- **Re-exec handoff** — lightweight startup, signal forwarding, and wait handling
- **Security** — `PR_SET_NO_NEW_PRIVS`, sensitive `/proc` path masking, read-only `/sys` on the rootful path

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
- [ ] Rootless privileged-port forwarding
- [ ] seccomp profiles

## Rootless mode

Rootless mode is automatic. If `hippobox` is not running as root, it bootstraps itself through a user namespace with `unshare --user --map-root-user --map-auto --mount --uts --ipc` and keeps the rest of the flow the same.

What changes in rootless mode:

- cgroups are skipped
- the container keeps host networking
- `/proc` is still mounted inside the user namespace so `/dev/stderr` and friends work
- `/sys` stays out of the container
- `/dev` device nodes are bind-mounted from a hidden staging directory inside the rootfs
- `/dev/pts` and `/dev/shm` still work

Host setup:

- Linux user namespaces must be enabled
- `unshare` from util-linux must be installed
- `/etc/subuid` and `/etc/subgid` should provide a subordinate ID range for your user
- `newuidmap` and `newgidmap` from util-linux should be available

Limitations:

- rootless containers cannot bind privileged ports like 80 unless the host allows it
- rootless mode is meant for lightweight commands, not a production isolation boundary
