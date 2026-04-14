# hippobox Development Guide

## Cross-platform development (WSL ↔ Windows)

When doing cross-platform Rust development from WSL, use a git worktree on the Dev Drive for Windows builds:

```bash
# Setup (one-time): create a worktree on the Dev Drive
git worktree add /mnt/d/hippobox-win -b windows-dev HEAD
git -C /mnt/d/hippobox-win config core.filemode false
```

```bash
# Build and test on Windows via pwsh.exe
pwsh.exe -Command "cd 'D:\hippobox-win'; cargo test -p hippobox"
pwsh.exe -Command "cd 'D:\hippobox-win'; cargo clippy -p hippobox -- -D warnings"
```

- The Dev Drive (ReFS) supports incremental compilation, which UNC paths (`\\wsl.localhost\...`) cannot
- Set `core.filemode false` in the worktree to prevent NTFS file-mode diff noise
- Edit files from WSL at `/mnt/d/hippobox-win/`, test from Windows via `pwsh.exe`
- Both platforms share git history through the worktree — commits on one are visible from the other
- Always run tests on both platforms before shipping cross-platform changes
- Cross-compilation from WSL (`--target x86_64-pc-windows-gnu`) validates compilation but cannot execute tests
