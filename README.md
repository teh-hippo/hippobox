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

# Run Ubuntu
hippobox run docker.io/library/ubuntu:24.04 -- cat /etc/os-release

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
- **Linux namespaces** — mount, UTS, IPC, PID isolation with PID 1 init handling
- **pivot_root** — full filesystem isolation with proper mount propagation
- **Re-exec handoff** — lightweight startup, signal forwarding, and wait handling
- **Security** — seccomp BPF filter, `PR_SET_NO_NEW_PRIVS`, sensitive `/proc` path masking, read-only `/sys`
- **Rootless EXDEV fix** — LD_PRELOAD rename shim handles directory renames on unprivileged overlayfs

## Tested images

hippobox is regularly tested against these images:

- `busybox:latest` — minimal container, startup benchmarks
- `redis:alpine` — dynamically-linked server, binary load benchmarks
- `ubuntu:24.04` — full distro, dpkg/apt operations, directory renames

## Building

```bash
cargo build --release
```

Release binary is ~2MB with the optimized profile.

## Benchmarks

Run the benchmark suite (requires podman for comparison):

```bash
bench/run.sh
```

Compares hippobox vs podman (default) vs podman (optimised) across busybox,
redis, and ubuntu workloads. Includes a sustained-workload scenario (~40s per
run: 30,000 source files, 50MB data, grep/sed/tar/rename/sha256sum) to verify
zero container overhead beyond startup.

## TODO

- [ ] `hippobox ps` — list running containers (daemon/background mode)
- [ ] `hippobox exec` — attach to running container
- [ ] Configurable resource limits (`--memory`, `--cpus`, `--pids`)
- [ ] Capability drops (Docker-standard allowlist)
- [ ] User field parsing (numeric uid, name → /etc/passwd lookup)
- [ ] Digest-based image refs (`image@sha256:...`)
- [ ] Auth for private registries (login/credentials)
- [ ] Bridge networking with NAT
- [ ] zstd layer support
- [ ] Rootless privileged-port forwarding

## Rootless mode

Rootless mode is automatic. If `hippobox` is not running as root, it bootstraps itself through a user namespace with `unshare --user --map-root-user --map-auto --mount --uts --ipc` and keeps the rest of the flow the same.

What changes in rootless mode:

- cgroups are skipped
- the container keeps host networking
- `/proc` is still mounted inside the user namespace so `/dev/stderr` and friends work
- `/sys` stays out of the container
- `/dev` device nodes are bind-mounted from a hidden staging directory inside the rootfs
- `/dev/pts` and `/dev/shm` still work
- directory renames work via an LD_PRELOAD shim that handles EXDEV transparently

Host setup:

- Linux user namespaces must be enabled
- `unshare` from util-linux must be installed
- `/etc/subuid` and `/etc/subgid` should provide a subordinate ID range for your user
- `newuidmap` and `newgidmap` from util-linux should be available

Limitations:

- rootless containers cannot bind privileged ports like 80 unless the host allows it
- rootless mode is meant for lightweight commands, not a production isolation boundary
- the rename shim covers dynamically-linked binaries only (statically-linked Go/Rust binaries with directory renames may still see EXDEV)
