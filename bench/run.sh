#!/usr/bin/env bash
# hippobox benchmark suite — hippobox vs podman
# All tests run rootless (userland). Images must be pre-pulled.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HIPPOBOX="${SCRIPT_DIR}/../target/release/hippobox"
IMAGE_BUSYBOX="docker.io/library/busybox:latest"
IMAGE_REDIS="docker.io/library/redis:latest"
IMAGE_UBUNTU="docker.io/library/ubuntu:24.04"
WARMUP=3
ITERATIONS=15
SCENARIO_WARMUP=1
SCENARIO_ITERATIONS=5

# ── colours ──────────────────────────────────────────────────────────
bold()  { printf '\033[1m%s\033[0m' "$*"; }
green() { printf '\033[1;32m%s\033[0m' "$*"; }
red()   { printf '\033[1;31m%s\033[0m' "$*"; }
dim()   { printf '\033[2m%s\033[0m' "$*"; }

# ── helpers ──────────────────────────────────────────────────────────
time_ms() {
    local start end
    start=$(date +%s%N)
    "$@" >/dev/null 2>&1
    local rc=$?
    end=$(date +%s%N)
    if [ $rc -ne 0 ]; then echo "-1"; return; fi
    echo $(( (end - start) / 1000000 ))
}

find_port() {
    python3 -c "import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()"
}

stats() {
    local -n _times=$1
    local n=${#_times[@]}
    local sorted=($(printf '%s\n' "${_times[@]}" | sort -n))
    local sum=0
    for t in "${_times[@]}"; do sum=$((sum + t)); done
    _min=${sorted[0]}
    _med=${sorted[$((n / 2))]}
    _avg=$((sum / n))
    _p95=${sorted[$(( (n * 95 + 99) / 100 - 1 ))]}
    _max=${sorted[$((n - 1))]}
}

# Run a benchmark: label, warmup, iterations, command...
# Stores median in variable named ${label}_med
run_bench() {
    local label="$1"; shift
    local wu="$1"; shift
    local iters="$1"; shift

    # Warmup
    for ((i = 1; i <= wu; i++)); do
        if ! "$@" >/dev/null 2>&1; then
            printf "  %-22s %s\n" "$label" "$(red FAILED)"
            eval "${label}_med=-1"
            return 1
        fi
    done

    # Timed runs
    local times=()
    for ((i = 1; i <= iters; i++)); do
        local ms
        ms=$(time_ms "$@")
        if [ "$ms" = "-1" ]; then
            printf "  %-22s %s\n" "$label" "$(red FAILED)"
            eval "${label}_med=-1"
            return 1
        fi
        times+=("$ms")
    done

    stats times
    printf "  %-22s  %6d ms   %6d ms   %6d ms   %6d ms   %6d ms\n" \
        "$label" "$_min" "$_med" "$_avg" "$_p95" "$_max"
    eval "${label}_med=$_med"
}

# Sustained-workload scenario: 30k source files, 50MB data, grep/sed/tar/rename/sha256sum
# Exercises filesystem I/O, CPU, process spawning, directory renames (EXDEV shim)
SCENARIO_WORKLOAD='set -e
i=0; while [ $i -lt 50 ]; do
  j=0; while [ $j -lt 20 ]; do
    dir="/tmp/b/s/m${i}/p${j}"; mkdir -p "$dir"
    k=0; while [ $k -lt 30 ]; do
      printf "package m%d_p%d\nimport \"fmt\"\nfunc H%d%d%d(s string)string{\nfmt.Println(s)\n" "$i" "$j" "$i" "$j" "$k" > "$dir/f${k}.go"
      n=1; while [ $n -le 50 ]; do printf "// line %d in %d/%d/%d\n" "$n" "$i" "$j" "$k" >> "$dir/f${k}.go"; n=$((n+1)); done
      printf "return s\n}\n" >> "$dir/f${k}.go"; k=$((k+1))
    done; j=$((j+1))
  done; i=$((i+1))
done
mkdir -p /tmp/b/data
i=1; while [ $i -le 100 ]; do dd if=/dev/urandom bs=1024 count=500 of="/tmp/b/data/d${i}.bin" 2>/dev/null; i=$((i+1)); done
find /tmp/b/s -name "*.go" | wc -l
grep -rl "Println" /tmp/b/s | wc -l
find /tmp/b/s -name "*.go" -exec sed -i "s/Println/Printf/g" {} +
find /tmp/b/s -name "*.go" -exec sed -i "s/func H/func Process/g" {} +
find /tmp/b/s -name "*.go" -exec sed -i "s/package m/package mod/g" {} +
tar czf /tmp/b/a1.tar.gz -C /tmp/b s data
i=0; while [ $i -lt 50 ]; do mv "/tmp/b/s/m${i}" "/tmp/b/s/x${i}"; i=$((i+1)); done
find /tmp/b/s -type f -exec sha256sum {} + | wc -l
sha256sum /tmp/b/data/*.bin | awk "{print \$1}" | sort > /tmp/b/ck1.txt
mkdir -p /tmp/b/r; tar xzf /tmp/b/a1.tar.gz -C /tmp/b/r
sha256sum /tmp/b/r/data/*.bin | awk "{print \$1}" | sort > /tmp/b/ck2.txt
diff /tmp/b/ck1.txt /tmp/b/ck2.txt
tar czf /tmp/b/a2.tar.gz -C /tmp/b/r s data
find /tmp/b/s -name "*.go" -exec wc -l {} + | tail -1
find /tmp/b/r/s -name "*.go" -exec wc -l {} + | tail -1
rm -rf /tmp/b'

# Run scenario benchmark (seconds, fewer iterations since each run is ~40s)
run_scenario() {
    local label="$1"; shift
    local wu="$1"; shift
    local iters="$1"; shift

    # Warmup
    for ((i = 1; i <= wu; i++)); do
        if ! "$@" >/dev/null 2>&1; then
            printf "  %-22s %s\n" "$label" "$(red FAILED)"
            eval "${label}_med=-1"
            return 1
        fi
    done

    # Timed runs
    local times=()
    for ((i = 1; i <= iters; i++)); do
        local start end ms
        start=$(date +%s%N)
        if ! "$@" >/dev/null 2>&1; then
            printf "  %-22s %s\n" "$label" "$(red FAILED)"
            eval "${label}_med=-1"
            return 1
        fi
        end=$(date +%s%N)
        ms=$(( (end - start) / 1000000 ))
        times+=("$ms")
        printf "    run %d/%d: %d ms\n" "$i" "$iters" "$ms" >&2
    done

    stats times
    printf "  %-22s  %6d ms   %6d ms   %6d ms   %6d ms   %6d ms\n" \
        "$label" "$_min" "$_med" "$_avg" "$_p95" "$_max"
    eval "${label}_med=$_med"
}

# Redis PING benchmark — start server, wait for PING, measure total time
bench_redis_ping() {
    local runner="$1"; shift
    local label="$1"; shift
    local wu="$1"; shift
    local iters="$1"; shift

    if ! command -v redis-cli >/dev/null 2>&1; then
        printf "  %-22s %s\n" "$label" "$(dim 'skipped (no redis-cli)')"
        eval "${label}_med=-1"
        return 0
    fi

    # Warmup
    for ((i = 1; i <= wu; i++)); do
        local port
        port=$(find_port)
        if [ "$runner" = "hippobox" ]; then
            _bench_redis_ping_hippobox "$port" >/dev/null || true
        else
            _bench_redis_ping_podman "$port" >/dev/null || true
        fi
    done

    local times=()
    for ((i = 1; i <= iters; i++)); do
        local port ms
        port=$(find_port)
        if [ "$runner" = "hippobox" ]; then
            ms=$(_bench_redis_ping_hippobox "$port")
        else
            ms=$(_bench_redis_ping_podman "$port")
        fi
        if [ "$ms" = "-1" ]; then
            printf "  %-22s %s\n" "$label" "$(red FAILED)"
            eval "${label}_med=-1"
            return 1
        fi
        times+=("$ms")
    done

    stats times
    printf "  %-22s  %6d ms   %6d ms   %6d ms   %6d ms   %6d ms\n" \
        "$label" "$_min" "$_med" "$_avg" "$_p95" "$_max"
    eval "${label}_med=$_med"
}

_bench_redis_ping_hippobox() {
    local port=$1 start end
    start=$(date +%s%N)
    $HIPPOBOX run "$IMAGE_REDIS" redis-server --save "" --appendonly no \
        --daemonize no --port "$port" --bind 0.0.0.0 --loglevel warning \
        >/dev/null 2>&1 &
    local bg=$!
    local w=0
    while ! redis-cli -p "$port" PING >/dev/null 2>&1; do
        sleep 0.005; w=$((w+1))
        if [ $w -gt 2000 ]; then echo "-1"; return; fi
    done
    end=$(date +%s%N)
    redis-cli -p "$port" SHUTDOWN NOSAVE >/dev/null 2>&1 || true
    wait $bg 2>/dev/null || true
    echo $(( (end - start) / 1000000 ))
}

_bench_redis_ping_podman() {
    local port=$1 start end cid
    local -a cmd=(podman run -d --rm -p "${port}:${port}")
    start=$(date +%s%N)
    cid=$("${cmd[@]}" \
        "$IMAGE_REDIS" redis-server --save "" --appendonly no \
        --daemonize no --port "$port" --bind 0.0.0.0 --loglevel warning 2>/dev/null) || { echo "-1"; return; }
    local w=0
    while ! redis-cli -p "$port" PING >/dev/null 2>&1; do
        sleep 0.005; w=$((w+1))
        if [ $w -gt 2000 ]; then
            podman stop "$cid" >/dev/null 2>&1 || true
            echo "-1"; return
        fi
    done
    end=$(date +%s%N)
    redis-cli -p "$port" SHUTDOWN NOSAVE >/dev/null 2>&1 || true
    sleep 0.2
    echo $(( (end - start) / 1000000 ))
}

# ── preflight ────────────────────────────────────────────────────────
if [ ! -x "$HIPPOBOX" ]; then
    echo "error: hippobox binary not found at $HIPPOBOX"
    echo "  run: cargo build --release"
    exit 1
fi

echo ""
bold "╔════════════════════════════════════════════════════════════╗"
bold "║        hippobox benchmark suite (rootless/userland)       ║"
bold "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "  hippobox:          $HIPPOBOX"
echo "  podman:            $(command -v podman) ($(podman --version 2>/dev/null | head -1))"
echo "  warmup:            $WARMUP runs"
echo "  iterations:        $ITERATIONS timed runs"
echo ""

# ── Test 1: busybox true ─────────────────────────────────────────────
bold "── busybox: true (minimum viable container) ──"
echo ""
printf "  %-22s  %8s   %8s   %8s   %8s   %8s\n" "" "min" "median" "avg" "p95" "max"
printf "  %-22s  %8s   %8s   %8s   %8s   %8s\n" "" "───" "──────" "───" "───" "───"
run_bench "hippobox" $WARMUP $ITERATIONS $HIPPOBOX run "$IMAGE_BUSYBOX" true
run_bench "podman" $WARMUP $ITERATIONS podman run --rm "$IMAGE_BUSYBOX" true
echo ""

# ── Test 2: busybox echo hello ───────────────────────────────────────
bold "── busybox: echo hello ──"
echo ""
printf "  %-22s  %8s   %8s   %8s   %8s   %8s\n" "" "min" "median" "avg" "p95" "max"
printf "  %-22s  %8s   %8s   %8s   %8s   %8s\n" "" "───" "──────" "───" "───" "───"
run_bench "h_echo" $WARMUP $ITERATIONS $HIPPOBOX run "$IMAGE_BUSYBOX" echo hello
run_bench "p_echo" $WARMUP $ITERATIONS podman run --rm "$IMAGE_BUSYBOX" echo hello
echo ""

# ── Test 3: busybox sh computation ───────────────────────────────────
bold "── busybox: sh loop (small computation) ──"
echo ""
printf "  %-22s  %8s   %8s   %8s   %8s   %8s\n" "" "min" "median" "avg" "p95" "max"
printf "  %-22s  %8s   %8s   %8s   %8s   %8s\n" "" "───" "──────" "───" "───" "───"
run_bench "h_sh" $WARMUP $ITERATIONS $HIPPOBOX run "$IMAGE_BUSYBOX" sh -c 'i=0; while [ $i -lt 100 ]; do i=$((i+1)); done'
run_bench "p_sh" $WARMUP $ITERATIONS podman run --rm "$IMAGE_BUSYBOX" sh -c 'i=0; while [ $i -lt 100 ]; do i=$((i+1)); done'
echo ""

# ── Test 4: redis-server --version ───────────────────────────────────
bold "── redis: redis-server --version (binary load) ──"
echo ""
printf "  %-22s  %8s   %8s   %8s   %8s   %8s\n" "" "min" "median" "avg" "p95" "max"
printf "  %-22s  %8s   %8s   %8s   %8s   %8s\n" "" "───" "──────" "───" "───" "───"
run_bench "h_redis_ver" $WARMUP $ITERATIONS $HIPPOBOX run "$IMAGE_REDIS" redis-server --version
run_bench "p_redis_ver" $WARMUP $ITERATIONS podman run --rm "$IMAGE_REDIS" redis-server --version
echo ""

# ── Test 5: ubuntu cat /etc/os-release ──────────────────────────────
bold "── ubuntu: cat /etc/os-release (full distro load) ──"
echo ""
printf "  %-22s  %8s   %8s   %8s   %8s   %8s\n" "" "min" "median" "avg" "p95" "max"
printf "  %-22s  %8s   %8s   %8s   %8s   %8s\n" "" "───" "──────" "───" "───" "───"
run_bench "h_ubuntu_cat" $WARMUP $ITERATIONS $HIPPOBOX run "$IMAGE_UBUNTU" -- cat /etc/os-release
run_bench "p_ubuntu_cat" $WARMUP $ITERATIONS podman run --rm "$IMAGE_UBUNTU" cat /etc/os-release
echo ""

# ── Test 6: ubuntu directory rename ─────────────────────────────────
bold "── ubuntu: directory rename (EXDEV stress) ──"
echo ""
printf "  %-22s  %8s   %8s   %8s   %8s   %8s\n" "" "min" "median" "avg" "p95" "max"
printf "  %-22s  %8s   %8s   %8s   %8s   %8s\n" "" "───" "──────" "───" "───" "───"
run_bench "h_ubuntu_rename" $WARMUP $ITERATIONS $HIPPOBOX run "$IMAGE_UBUNTU" -- \
    sh -c 'mkdir -p /opt/a/b/c && echo x > /opt/a/b/c/f && mv /opt/a /opt/z && cat /opt/z/b/c/f'
run_bench "p_ubuntu_rename" $WARMUP $ITERATIONS podman run --rm "$IMAGE_UBUNTU" \
    sh -c 'mkdir -p /opt/a/b/c && echo x > /opt/a/b/c/f && mv /opt/a /opt/z && cat /opt/z/b/c/f'
echo ""

# ── Test 7: ubuntu dpkg --configure ─────────────────────────────────
bold "── ubuntu: dpkg --configure -a (package manager) ──"
echo ""
printf "  %-22s  %8s   %8s   %8s   %8s   %8s\n" "" "min" "median" "avg" "p95" "max"
printf "  %-22s  %8s   %8s   %8s   %8s   %8s\n" "" "───" "──────" "───" "───" "───"
run_bench "h_ubuntu_dpkg" $WARMUP $ITERATIONS $HIPPOBOX run "$IMAGE_UBUNTU" -- dpkg --configure -a
run_bench "p_ubuntu_dpkg" $WARMUP $ITERATIONS podman run --rm "$IMAGE_UBUNTU" dpkg --configure -a
echo ""

# ── Test 8: Redis PING (server startup-to-ready) ────────────────────
bold "── redis: PING (full server startup-to-ready) ──"
echo ""
printf "  %-22s  %8s   %8s   %8s   %8s   %8s\n" "" "min" "median" "avg" "p95" "max"
printf "  %-22s  %8s   %8s   %8s   %8s   %8s\n" "" "───" "──────" "───" "───" "───"
bench_redis_ping "hippobox"      "h_redis_ping"  $WARMUP $ITERATIONS || true
bench_redis_ping "podman"        "p_redis_ping"  $WARMUP $ITERATIONS || true
echo ""

# ── Test 9: Ubuntu sustained workload scenario ──────────────────────
bold "── ubuntu: sustained workload (~40s: 30k files, grep, sed, tar, rename, sha256) ──"
echo ""
printf "  %-22s  %8s   %8s   %8s   %8s   %8s\n" "" "min" "median" "avg" "p95" "max"
printf "  %-22s  %8s   %8s   %8s   %8s   %8s\n" "" "───" "──────" "───" "───" "───"
run_scenario "h_scenario" $SCENARIO_WARMUP $SCENARIO_ITERATIONS \
    $HIPPOBOX run "$IMAGE_UBUNTU" -- sh -c "$SCENARIO_WORKLOAD"
run_scenario "p_scenario" $SCENARIO_WARMUP $SCENARIO_ITERATIONS \
    podman run --rm "$IMAGE_UBUNTU" sh -c "$SCENARIO_WORKLOAD"
echo ""

# ── Summary ──────────────────────────────────────────────────────────
echo ""
bold "╔════════════════════════════════════════════════════════════════════════╗"
bold "║                          Summary (median ms)                         ║"
bold "╚════════════════════════════════════════════════════════════════════════╝"
echo ""
printf "  %-24s %10s %12s %10s\n" "Test" "hippobox" "podman" "h/p"
printf "  %-24s %10s %12s %10s\n" "────────────────────────" "──────────" "────────────" "──────────"

summary_row() {
    local name=$1 hvar=$2 pvar=$3
    local h=${!hvar:--1} p=${!pvar:--1}

    local r1="—"
    if [ "$h" -gt 0 ] && [ "$p" -gt 0 ]; then
        local pct=$((h * 100 / p))
        if [ "$pct" -lt 100 ]; then r1="$(green "${pct}%")"; else r1="$(red "${pct}%")"; fi
    fi

    local hs="—" ps="—"
    [ "$h"  -gt 0 ] && hs="${h} ms"
    [ "$p"  -gt 0 ] && ps="${p} ms"

    printf "  %-24s %10s %12s %10s\n" "$name" "$hs" "$ps" "$r1"
}

summary_row "true"              "hippobox_med"        "podman_med"
summary_row "echo"              "h_echo_med"          "p_echo_med"
summary_row "sh loop"           "h_sh_med"            "p_sh_med"
summary_row "redis --version"   "h_redis_ver_med"     "p_redis_ver_med"
summary_row "ubuntu cat"        "h_ubuntu_cat_med"    "p_ubuntu_cat_med"
summary_row "ubuntu dir-rename" "h_ubuntu_rename_med" "p_ubuntu_rename_med"
summary_row "ubuntu dpkg"       "h_ubuntu_dpkg_med"   "p_ubuntu_dpkg_med"
summary_row "redis PING"        "h_redis_ping_med"    "p_redis_ping_med"

# Scenario uses seconds for display
summary_row_s() {
    local name=$1 hvar=$2 pvar=$3
    local h=${!hvar:--1} p=${!pvar:--1}

    local r1="—"
    if [ "$h" -gt 0 ] && [ "$p" -gt 0 ]; then
        local pct=$((h * 100 / p))
        if [ "$pct" -le 105 ]; then r1="$(green "${pct}%")"; else r1="$(red "${pct}%")"; fi
    fi

    local hs="—" ps="—"
    if [ "$h" -gt 0 ]; then hs="$(( h / 1000 )).$(( h % 1000 / 100 ))s"; fi
    if [ "$p" -gt 0 ]; then ps="$(( p / 1000 )).$(( p % 1000 / 100 ))s"; fi

    printf "  %-24s %10s %12s %10s\n" "$name" "$hs" "$ps" "$r1"
}

summary_row_s "scenario (sustained)" "h_scenario_med"      "p_scenario_med"

echo ""
echo "  h/p = hippobox / podman — lower % = hippobox faster"
echo ""
