# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0](https://github.com/teh-hippo/hippobox/compare/hippobox-v0.1.1...hippobox-v0.2.0) (2026-03-24)


### Features

* add HOME and TERM environment defaults ([5dbcf45](https://github.com/teh-hippo/hippobox/commit/5dbcf45282337269875ef7be524a1fe7e3f511cb))
* add PID namespace isolation ([5ad2058](https://github.com/teh-hippo/hippobox/commit/5ad20587e3beb72606ed0b81709b9099726749d5))
* add port mapping (-p) and network modes (--network) ([7bf8a1a](https://github.com/teh-hippo/hippobox/commit/7bf8a1a4b26b46448d4339a1c2311634a6351eac))
* add volume mount support (-v) ([8cd38dd](https://github.com/teh-hippo/hippobox/commit/8cd38dda27d6bcc84470a370be9aa7235fafd543))
* bind-mount host /sys for rootless containers ([906cf6f](https://github.com/teh-hippo/hippobox/commit/906cf6fb6ef47a134d46874fb6be766fd8b25935))
* container runtime with namespaces, mounts, overlayfs, init shim ([7f82a12](https://github.com/teh-hippo/hippobox/commit/7f82a12f87e5b7e71686f0939152fe2e51d47448))
* image ref parser with registry/repo/tag resolution ([07089e3](https://github.com/teh-hippo/hippobox/commit/07089e315ce0a0a7e2d34f92a866fb7e729e347f))
* images list and clean commands ([212e9d6](https://github.com/teh-hippo/hippobox/commit/212e9d6276af0c037e5a895e68ac250cba946871))
* initial scaffold with CLI skeleton and storage dirs ([da69c5c](https://github.com/teh-hippo/hippobox/commit/da69c5c5a1a515cd3d66d3df54576eee2404ee51))
* LD_PRELOAD rename shim for EXDEV on rootless overlayfs ([9ffafee](https://github.com/teh-hippo/hippobox/commit/9ffafee77437c10dc6e815dcb15980498471ea4c))
* OCI registry client with auth, manifest resolution, layer download ([65c0b5a](https://github.com/teh-hippo/hippobox/commit/65c0b5a6b68f0a8528eb422776254d4b52b5d2bc))
* support official images in rootless mode ([4a67eee](https://github.com/teh-hippo/hippobox/commit/4a67eeedabbad8d2c28666073bc2ad91541c3124))


### Bug Fixes

* -p with explicit --network=host now shows clear error ([f3380b1](https://github.com/teh-hippo/hippobox/commit/f3380b1278c4abef45377a93ed49fad8687c9b5e))
* address review issues in rename shim ([9b3c08b](https://github.com/teh-hippo/hippobox/commit/9b3c08b9d6459481c60ff24dd70b911477f22c71))
* allow clone3 syscall for glibc threading compatibility ([f4c0261](https://github.com/teh-hippo/hippobox/commit/f4c0261bac467fdc0ee3aac0e93682dd2d8a71da))
* cargo fmt and add pre-commit hook ([3fc1e03](https://github.com/teh-hippo/hippobox/commit/3fc1e033d84c7770b12c1c33e05ca169540893e6))
* **ci:** scope CI to hippobox crate only ([e6c4138](https://github.com/teh-hippo/hippobox/commit/e6c4138fe9698d8c687e405b6aad537af3526fe4))
* **ci:** use rebase merge for release-please auto-merge ([2aadc17](https://github.com/teh-hippo/hippobox/commit/2aadc17e058a602336aa9e71fe0f1d2472f5ee70))
* file bind mounts creating directory instead of file placeholder ([bfb1d25](https://github.com/teh-hippo/hippobox/commit/bfb1d25c24f534e3bb7f2916ec58ac24a7ca779d))
* harden rename shim against TOCTOU and partial-delete ([c8a1906](https://github.com/teh-hippo/hippobox/commit/c8a19068520f8ad09b22a6925db2aa8546751bc7))
* move proc masking after PID namespace /proc mount ([7e1bdc5](https://github.com/teh-hippo/hippobox/commit/7e1bdc5f3bcaea0abbb0dc40ec9edb0b57c9b66c))
* pass container spec over pipe fd to preserve stdin ([1793122](https://github.com/teh-hippo/hippobox/commit/1793122bfaeb3a91fbf0618e89dfede2a6a75ca4))
* remove duplicate host-device cleanup ([21a0ec2](https://github.com/teh-hippo/hippobox/commit/21a0ec2219afd150166c387073a53be3a16be294))
* update tar and rustls-webpki to patch vulnerabilities ([08b06ac](https://github.com/teh-hippo/hippobox/commit/08b06acf4b830d9645492f569eeed6bfabe1dffd))


### Performance Improvements

* add volatile flag to overlayfs mount ([add7ee9](https://github.com/teh-hippo/hippobox/commit/add7ee980944f469cd8966981bc29cdfc21fa4ac))
* mount tmpfs on /tmp inside containers ([770befb](https://github.com/teh-hippo/hippobox/commit/770befb04fb22a6fbca390f522b42cbb133e372b))
* move host file copies to container_init (off pre-fork path) ([afee505](https://github.com/teh-hippo/hippobox/commit/afee505bac2f39fe71b2d1a9fa4b421a24a8277b))
* optimise container_init path and arg parsing ([ae496e4](https://github.com/teh-hippo/hippobox/commit/ae496e44773a02b355cd609afcf721a9fcd12499))
* reduce syscalls on container startup hot path ([a26842f](https://github.com/teh-hippo/hippobox/commit/a26842fe8a244f563346a8a23b8399e37564214a))
* remove opt-level=s, replace sha2 with ring's digest ([93e7752](https://github.com/teh-hippo/hippobox/commit/93e775268acb706c52e5e9e0cda53266828009b3))
* replace 50ms rootless poll with blocking waitpid ([786abae](https://github.com/teh-hippo/hippobox/commit/786abaed36e87705aa4d7b6f25deae4d698c9c57))
* resolve unshare path upfront, fix ioctl portability for musl ([61aed1a](https://github.com/teh-hippo/hippobox/commit/61aed1a16ebb1eb57a809b733b3ba06cdaac55bd))
* trim startup mount preflights ([31f075f](https://github.com/teh-hippo/hippobox/commit/31f075f5011ccb2b02ac807b4df4bde6c7390c12))
* tune release profile and buffer pipe I/O ([df7f0be](https://github.com/teh-hippo/hippobox/commit/df7f0be90e13942243cf4cb52806cb442d34dc5a))

## [0.1.1] - 2026-03-22

### Changed

- Release profile now uses default `opt-level` (3) for maximum runtime performance instead of `opt-level = "s"` (size-optimised)
- Replaced `sha2` crate with `ring::digest` for SHA256 hashing, reducing transitive dependencies from 86 to 77

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

[0.1.1]: https://github.com/teh-hippo/hippobox/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/teh-hippo/hippobox/releases/tag/v0.1.0
