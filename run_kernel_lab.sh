#!/usr/bin/env bash
# Live Linux-kernel proof: Linux namespaces + actual nftables + actual TCP file transfer.
# All network changes are contained within disposable namespaces; no host firewall edits.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if (( EUID != 0 )); then
  echo 'Run in an Ubuntu VM as: sudo bash run_kernel_lab.sh' >&2; exit 1
fi
for command in ip nft python3 setpriv sha256sum; do
  command -v "$command" >/dev/null || { echo "Missing: $command (install iproute2 nftables python3 util-linux)" >&2; exit 1; }
done

TAG="${BASHPID}"
SRC="dds${TAG}"; GW="ddg${TAG}"; LAN="ddl${TAG}"
OUT="$(pwd)/lab-results/$(date +%Y%m%d-%H%M%S)-${TAG}"
mkdir -p "$OUT" "$OUT/staging"
chmod 755 "$OUT"
# Demo-only numeric identities. UID 21001 fetches; UID 21002 delivers.
chown 21001:21002 "$OUT/staging"
chmod 750 "$OUT/staging"
printf 'Data Diode Linux kernel proof\nSample source content only\n' > "$OUT/source.bin"
PIDS=()
cleanup() {
  set +e
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null; done
  for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null; done
  for ns in "$GW" "$SRC" "$LAN"; do ip netns del "$ns" 2>/dev/null; done
}
trap cleanup EXIT

run_gw() { ip netns exec "$GW" "$@"; }
gw_fetch() { run_gw setpriv --reuid 21001 --regid 21001 --clear-groups python3 "$(pwd)/lab_client.py" "$@"; }
gw_send() { run_gw setpriv --reuid 21002 --regid 21002 --clear-groups python3 "$(pwd)/lab_client.py" "$@"; }
link_up() { ip -n "$GW" -o link show dev "$1" | grep -Eq '<[^>]*\bUP\b'; }
assert_links() {
  local state0="$1" state1="$2"
  if link_up eth0; then got0=UP; else got0=DOWN; fi
  if link_up eth1; then got1=UP; else got1=DOWN; fi
  echo "Interfaces: eth0=$got0 eth1=$got1 (expected $state0/$state1)"
  [[ "$got0" == "$state0" && "$got1" == "$state1" ]] || { echo 'FAILED: interface state invariant' >&2; exit 1; }
}
close_all() {
  ip -n "$GW" link set dev eth0 down || true
  ip -n "$GW" link set dev eth1 down || true
  run_gw nft flush chain inet proof_fw phase_out || true
}
expect_blocked() {
  local role="$1" dest="$2" port="$3"
  echo "Expect BLOCK: role=$role target=$dest:$port"
  if [[ "$role" == fetch ]]; then
    if gw_fetch probe "$dest" "$port"; then echo 'FAIL: unauthorized connection succeeded' >&2; exit 1; fi
  else
    if gw_send probe "$dest" "$port"; then echo 'FAIL: unauthorized connection succeeded' >&2; exit 1; fi
  fi
  echo 'PASS: connection blocked'
}

printf '\n[1/8] Create three isolated Linux network stacks\n'
ip netns add "$SRC"; ip netns add "$GW"; ip netns add "$LAN"
ip link add "vs${TAG}" type veth peer name "vg0${TAG}"
ip link set "vs${TAG}" netns "$SRC"; ip link set "vg0${TAG}" netns "$GW"
ip link add "vl${TAG}" type veth peer name "vg1${TAG}"
ip link set "vl${TAG}" netns "$LAN"; ip link set "vg1${TAG}" netns "$GW"
ip -n "$SRC" link set "vs${TAG}" name source0
ip -n "$GW" link set "vg0${TAG}" name eth0
ip -n "$LAN" link set "vl${TAG}" name local0
ip -n "$GW" link set "vg1${TAG}" name eth1
ip -n "$SRC" address add 10.11.0.10/24 dev source0
ip -n "$GW" address add 10.11.0.20/24 dev eth0
ip -n "$LAN" address add 10.22.0.10/24 dev local0
ip -n "$GW" address add 10.22.0.1/24 dev eth1
for ns in "$SRC" "$GW" "$LAN"; do ip -n "$ns" link set lo up; done
ip -n "$SRC" link set source0 up
ip -n "$LAN" link set local0 up
close_rule="$(pwd)/base.nft"
run_gw nft -f "$close_rule"
close_all
assert_links DOWN DOWN

printf '\n[2/8] Start isolated test endpoints (443/22 are plain HTTP in this lab)\n'
for spec in "${SRC}:source:10.11.0.10:443:${OUT}/source.bin" \
            "${SRC}:source:10.11.0.10:80:${OUT}/source.bin" \
            "${LAN}:receiver:10.22.0.10:22:${OUT}/received.bin" \
            "${LAN}:receiver:10.22.0.10:80:${OUT}/blocked-receiver.bin"; do
  IFS=: read -r ns role host port filepath <<< "$spec"
  ip netns exec "$ns" python3 -u "$(pwd)/lab_endpoint.py" "$role" --host "$host" --port "$port" --file "$filepath" \
     > "$OUT/endpoint-${role}-${port}.log" 2>&1 &
  PIDS+=("$!")
done
sleep 0.35

printf '\n[3/8] Verify no IP forwarding and no default route\n'
[[ "$(run_gw sysctl -n net.ipv4.ip_forward)" == 0 ]] || { echo 'IP forwarding unexpectedly enabled'; exit 1; }
[[ -z "$(ip -n "$GW" -4 route show default)" ]] || { echo 'Unexpected default route'; exit 1; }
expect_blocked fetch 10.11.0.10 443

printf '\n[4/8] FETCH: eth0 UP, eth1 DOWN, only UID 21001 to source TCP 443\n'
run_gw nft add rule inet proof_fw phase_out oifname eth0 meta skuid 21001 ip daddr 10.11.0.10 tcp dport 443 ct state new accept
ip -n "$GW" link set eth0 up
assert_links UP DOWN
gw_fetch probe 10.11.0.10 443
expect_blocked send 10.11.0.10 443
expect_blocked fetch 10.11.0.10 80
gw_fetch fetch 10.11.0.10 443 --stage "$OUT/staging"

printf '\n[5/8] HOLD: both NICs down and all phase permissions gone\n'
close_all
assert_links DOWN DOWN
[[ -f "$OUT/staging/payload.bin" ]]
sha256sum "$OUT/staging/payload.bin"

printf '\n[6/8] DELIVER: eth0 DOWN, eth1 UP, only UID 21002 to receiver TCP 22\n'
run_gw nft add rule inet proof_fw phase_out oifname eth1 meta skuid 21002 ip daddr 10.22.0.10 tcp dport 22 ct state new accept
ip -n "$GW" link set eth1 up
assert_links DOWN UP
gw_send probe 10.22.0.10 22
expect_blocked fetch 10.22.0.10 22
expect_blocked send 10.22.0.10 80
gw_send deliver 10.22.0.10 22 --stage "$OUT/staging"

printf '\n[7/8] FINISH: firewall closed; real received-file hashes match\n'
close_all
assert_links DOWN DOWN
run_gw nft list chain inet proof_fw phase_out > "$OUT/final_phase_out.txt"
if grep -q 'tcp dport' "$OUT/final_phase_out.txt"; then echo 'FAIL: rules not removed'; exit 1; fi
cmp "$OUT/source.bin" "$OUT/received.bin"
sha256sum "$OUT/source.bin" "$OUT/received.bin" > "$OUT/hashes.txt"
cat "$OUT/hashes.txt"

echo '\n[8/8] Optional fault demonstration: detect both interfaces UP and close them'
ip -n "$GW" link set eth0 up
ip -n "$GW" link set eth1 up
if link_up eth0 && link_up eth1; then
  echo 'FAULT DETECTED (intentional): both links UP -> fail-closed'
  close_all
else
  echo 'FAIL: did not detect injected state' >&2; exit 1
fi
assert_links DOWN DOWN
printf '\nPASS: Live Linux-kernel isolation, UID/port firewall checks, staged file transfer and fail-close demo\n'
printf 'Evidence retained in: %s\n' "$OUT"
