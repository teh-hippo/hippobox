#!/usr/bin/env bash
# hippobox benchmark suite — hippobox vs podman (default) vs podman (optimised)
# All tests run rootless (userland). Images must be pre-pulled.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HIPPOBOX="${SCRIPT_DIR}/../target/release/hippobox"
IMAGE_BUSYBOX="docker.io/library/busybox:latest"
IMAGE_REDIS="docker.io/library/redis:latest"
WARMUP=3
ITERATIONS=15

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
        elif [ "$runner" = "podman" ]; then
            _bench_redis_ping_podman "$port" "" >/dev/null || true
        else
            _bench_redis_ping_podman "$port" "optimised" >/dev/null || true
        fi
    done

    local times=()
    for ((i = 1; i <= iters; i++)); do
        local port ms
        port=$(find_port)
        if [ "$runner" = "hippobox" ]; then
            ms=$(_bench_redis_ping_hippobox "$port")
        elif [ "$runner" = "podman" ]; then
            ms=$(_bench_redis_ping_podman "$port" "")
        else
            ms=$(_bench_redis_ping_podman "$port" "optimised")
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
    local port=$1 mode=$2 start end cid
    local -a cmd=()
    if [ "$mode" = "optimised" ]; then
        cmd=(podman --events-backend=none run -d --rm --log-driver=none --cgroups=no-conmon --network=host)
    else
        cmd=(podman run -d --rm -p "${port}:${port}")
    fi
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
echo "  podman optimised:  --events-backend=none --log-driver=none"
echo "                     --cgroups=no-conmon --network=none/host"
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
run_bench "podman_opt" $WARMUP $ITERATIONS \
    podman --events-backend=none run --rm --log-driver=none --cgroups=no-conmon --network=none "$IMAGE_BUSYBOX" true
echo ""

# ── Test 2: busybox echo hello ───────────────────────────────────────
bold "── busybox: echo hello ──"
echo ""
printf "  %-22s  %8s   %8s   %8s   %8s   %8s\n" "" "min" "median" "avg" "p95" "max"
printf "  %-22s  %8s   %8s   %8s   %8s   %8s\n" "" "───" "──────" "───" "───" "───"
run_bench "h_echo" $WARMUP $ITERATIONS $HIPPOBOX run "$IMAGE_BUSYBOX" echo hello
run_bench "p_echo" $WARMUP $ITERATIONS podman run --rm "$IMAGE_BUSYBOX" echo hello
run_bench "po_echo" $WARMUP $ITERATIONS \
    podman --events-backend=none run --rm --log-driver=none --cgroups=no-conmon --network=none "$IMAGE_BUSYBOX" echo hello
echo ""

# ── Test 3: busybox sh computation ───────────────────────────────────
bold "── busybox: sh loop (small computation) ──"
echo ""
printf "  %-22s  %8s   %8s   %8s   %8s   %8s\n" "" "min" "median" "avg" "p95" "max"
printf "  %-22s  %8s   %8s   %8s   %8s   %8s\n" "" "───" "──────" "───" "───" "───"
run_bench "h_sh" $WARMUP $ITERATIONS $HIPPOBOX run "$IMAGE_BUSYBOX" sh -c 'i=0; while [ $i -lt 100 ]; do i=$((i+1)); done'
run_bench "p_sh" $WARMUP $ITERATIONS podman run --rm "$IMAGE_BUSYBOX" sh -c 'i=0; while [ $i -lt 100 ]; do i=$((i+1)); done'
run_bench "po_sh" $WARMUP $ITERATIONS \
    podman --events-backend=none run --rm --log-driver=none --cgroups=no-conmon --network=none "$IMAGE_BUSYBOX" sh -c 'i=0; while [ $i -lt 100 ]; do i=$((i+1)); done'
echo ""

# ── Test 4: redis-server --version ───────────────────────────────────
bold "── redis: redis-server --version (binary load) ──"
echo ""
printf "  %-22s  %8s   %8s   %8s   %8s   %8s\n" "" "min" "median" "avg" "p95" "max"
printf "  %-22s  %8s   %8s   %8s   %8s   %8s\n" "" "───" "──────" "───" "───" "───"
run_bench "h_redis_ver" $WARMUP $ITERATIONS $HIPPOBOX run "$IMAGE_REDIS" redis-server --version
run_bench "p_redis_ver" $WARMUP $ITERATIONS podman run --rm "$IMAGE_REDIS" redis-server --version
run_bench "po_redis_ver" $WARMUP $ITERATIONS \
    podman --events-backend=none run --rm --log-driver=none --cgroups=no-conmon --network=none "$IMAGE_REDIS" redis-server --version
echo ""

# ── Test 5: Redis PING (server startup-to-ready) ────────────────────
bold "── redis: PING (full server startup-to-ready) ──"
echo ""
printf "  %-22s  %8s   %8s   %8s   %8s   %8s\n" "" "min" "median" "avg" "p95" "max"
printf "  %-22s  %8s   %8s   %8s   %8s   %8s\n" "" "───" "──────" "───" "───" "───"
bench_redis_ping "hippobox"      "h_redis_ping"  $WARMUP $ITERATIONS
bench_redis_ping "podman"        "p_redis_ping"  $WARMUP $ITERATIONS
bench_redis_ping "podman_opt"    "po_redis_ping" $WARMUP $ITERATIONS
echo ""

# ── Summary ──────────────────────────────────────────────────────────
echo ""
bold "╔════════════════════════════════════════════════════════════════════════╗"
bold "║                          Summary (median ms)                         ║"
bold "╚════════════════════════════════════════════════════════════════════════╝"
echo ""
printf "  %-24s %10s %12s %12s %10s %10s\n" "Test" "hippobox" "podman" "podman opt" "h/p" "h/po"
printf "  %-24s %10s %12s %12s %10s %10s\n" "────────────────────────" "──────────" "────────────" "────────────" "──────────" "──────────"

summary_row() {
    local name=$1 hvar=$2 pvar=$3 povar=$4
    local h=${!hvar:--1} p=${!pvar:--1} po=${!povar:--1}

    local r1="—" r2="—"
    if [ "$h" -gt 0 ] && [ "$p" -gt 0 ]; then
        local pct=$((h * 100 / p))
        if [ "$pct" -lt 100 ]; then r1="$(green "${pct}%")"; else r1="$(red "${pct}%")"; fi
    fi
    if [ "$h" -gt 0 ] && [ "$po" -gt 0 ]; then
        local pct=$((h * 100 / po))
        if [ "$pct" -lt 100 ]; then r2="$(green "${pct}%")"; else r2="$(red "${pct}%")"; fi
    fi

    local hs="—" ps="—" pos="—"
    [ "$h"  -gt 0 ] && hs="${h} ms"
    [ "$p"  -gt 0 ] && ps="${p} ms"
    [ "$po" -gt 0 ] && pos="${po} ms"

    printf "  %-24s %10s %12s %12s %10s %10s\n" "$name" "$hs" "$ps" "$pos" "$r1" "$r2"
}

summary_row "true"              "hippobox_med"     "podman_med"       "podman_opt_med"
summary_row "echo"              "h_echo_med"       "p_echo_med"       "po_echo_med"
summary_row "sh loop"           "h_sh_med"         "p_sh_med"         "po_sh_med"
summary_row "redis --version"   "h_redis_ver_med"  "p_redis_ver_med"  "po_redis_ver_med"
summary_row "redis PING"        "h_redis_ping_med" "p_redis_ping_med" "po_redis_ping_med"

echo ""
echo "  h/p  = hippobox / podman (default)    — lower % = hippobox faster"
echo "  h/po = hippobox / podman (optimised)  — lower % = hippobox faster"
echo ""
