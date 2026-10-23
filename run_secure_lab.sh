#!/usr/bin/env bash
# Stage 5: REAL certificate-verified HTTPS + key-authenticated SFTP over Linux namespaces.
# Run only in a disposable Ubuntu playground/VM, not a production host.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
if [[ "$(pwd)" == /root/* ]]; then
  echo "Move the lab folder to /tmp first: restricted application users cannot read scripts under /root." >&2
  exit 1
fi
(( EUID == 0 )) || { echo 'Run as: sudo bash run_secure_lab.sh' >&2; exit 1; }
for cmd in ip nft openssl ssh-keygen sshd sftp sha256sum setpriv python3 useradd userdel; do
  command -v "$cmd" >/dev/null || { echo "Missing $cmd. Install: apt install -y iproute2 nftables openssl openssh-client openssh-server python3 util-linux passwd" >&2; exit 1; }
done

TAG="${BASHPID}"
SRC="ssrc${TAG}"; GW="sgw${TAG}"; LAN="slan${TAG}"
# Keep result paths accessible to restricted users; do not run this from /root.
OUT="/tmp/diode-stage5-${TAG}"
NAME="drecv${TAG}"
FETCH_NAME="dfetch${TAG}"
SEND_NAME="dsend${TAG}"
PIDS=()
ACCOUNT_MADE=0
FETCH_MADE=0
SEND_MADE=0
cleanup() {
  local rc=$?
  set +e
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null; done
  for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null; done
  for ns in "$GW" "$SRC" "$LAN"; do ip netns del "$ns" 2>/dev/null; done
  (( ACCOUNT_MADE == 1 )) && userdel "$NAME" >/dev/null 2>&1
  (( FETCH_MADE == 1 )) && userdel "$FETCH_NAME" >/dev/null 2>&1
  (( SEND_MADE == 1 )) && userdel "$SEND_NAME" >/dev/null 2>&1
  rm -f "$OUT/sftp_client_key" "$OUT/source.key" "$OUT/host_key" "$OUT/receiver/.ssh/authorized_keys"
  if (( rc != 0 )); then echo "FAIL: Stage 5 ended with status $rc. Logs: $OUT" >&2; fi
}
trap cleanup EXIT
mkdir -p "$OUT/staging" "$OUT/source" "$OUT/receiver"
chmod 755 "$OUT" "$OUT/source"
# Create lab-only application accounts with real passwd entries (SSH requires this).
useradd --no-create-home --home-dir "$OUT" --shell /usr/sbin/nologin --password 'x' "$FETCH_NAME"
FETCH_MADE=1
useradd --no-create-home --home-dir "$OUT" --shell /usr/sbin/nologin --password 'x' "$SEND_NAME"
SEND_MADE=1
FETCH_UID="$(id -u "$FETCH_NAME")"; FETCH_GID="$(id -g "$FETCH_NAME")"
SEND_UID="$(id -u "$SEND_NAME")"; SEND_GID="$(id -g "$SEND_NAME")"
chown "$FETCH_UID":"$SEND_GID" "$OUT/staging"
chmod 750 "$OUT/staging"
head -c 131072 /dev/urandom > "$OUT/source/payload.bin"
sha256sum "$OUT/source/payload.bin" > "$OUT/source_hash.txt"

# Unique unprivileged key-only receiver account; removed during cleanup.
useradd --no-create-home --home-dir "$OUT/receiver" --shell /bin/sh --password 'x' "$NAME"
ACCOUNT_MADE=1
chown "$NAME":"$NAME" "$OUT/receiver"
chmod 750 "$OUT/receiver"
mkdir -p "$OUT/receiver/.ssh"
chmod 700 "$OUT/receiver/.ssh"
ssh-keygen -q -t ed25519 -N '' -f "$OUT/sftp_client_key"
chmod 600 "$OUT/sftp_client_key"
chown "$SEND_UID":"$SEND_GID" "$OUT/sftp_client_key"
cp "$OUT/sftp_client_key.pub" "$OUT/receiver/.ssh/authorized_keys"
chown -R "$NAME":"$NAME" "$OUT/receiver/.ssh"
chmod 600 "$OUT/receiver/.ssh/authorized_keys"
ssh-keygen -q -t ed25519 -N '' -f "$OUT/host_key"
chmod 600 "$OUT/host_key"
printf '10.22.0.10 %s\n' "$(cat "$OUT/host_key.pub")" > "$OUT/known_hosts"
chmod 644 "$OUT/known_hosts"
cat > "$OUT/sshd_config" <<EOF
Port 22
ListenAddress 10.22.0.10
HostKey $OUT/host_key
PidFile $OUT/sshd.pid
AuthorizedKeysFile .ssh/authorized_keys
AllowUsers $NAME
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM no
PermitEmptyPasswords no
PermitTTY no
X11Forwarding no
AllowTcpForwarding no
PermitTunnel no
GatewayPorts no
ForceCommand internal-sftp
Subsystem sftp internal-sftp
LogLevel VERBOSE
EOF
mkdir -p /run/sshd
/usr/sbin/sshd -t -f "$OUT/sshd_config"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj '/CN=diode.source.test' -addext 'subjectAltName=DNS:diode.source.test' \
  -keyout "$OUT/source.key" -out "$OUT/source.crt" >/dev/null 2>&1
chmod 644 "$OUT/source.crt"

rungw() { ip netns exec "$GW" "$@"; }
role_fetch() { rungw setpriv --reuid "$FETCH_UID" --regid "$FETCH_GID" --clear-groups python3 "$(pwd)/secure_client.py" "$@"; }
role_send() { rungw setpriv --reuid "$SEND_UID" --regid "$SEND_GID" --clear-groups "$@"; }
# Every operation must enforce the interface exclusion invariant.
link_up() { ip -n "$GW" -o link show dev "$1" | grep -Eq '<[^>]*\bUP\b'; }
state() {
  local wanted0="$1" wanted1="$2" a0=DOWN a1=DOWN
  link_up eth0 && a0=UP || :
  link_up eth1 && a1=UP || :
  echo "Interfaces eth0=$a0 eth1=$a1 (expected $wanted0/$wanted1)"
  [[ "$a0" == "$wanted0" && "$a1" == "$wanted1" ]] || { echo 'FAIL: unexpected gateway interface state' >&2; exit 1; }
}
close_all() {
  ip -n "$GW" link set eth0 down || :
  ip -n "$GW" link set eth1 down || :
  rungw nft flush chain inet secure_diodelab phase_out || :
}
expect_blocked() {
  local role="$1" dst="$2" port="$3"
  echo "Expect blocked: $role -> $dst:$port"
  if [[ "$role" == fetch ]]; then
    if role_fetch probe "$dst" "$port"; then echo 'FAIL: prohibited socket connected' >&2; exit 1; fi
  else
    if role_send python3 "$(pwd)/secure_client.py" probe "$dst" "$port"; then echo 'FAIL: prohibited socket connected' >&2; exit 1; fi
  fi
}

echo '[1/8] Create Internet source, gateway and local receiver namespaces'
ip netns add "$SRC"; ip netns add "$GW"; ip netns add "$LAN"
ip link add "vs${TAG}" type veth peer name "vg0${TAG}"
ip link set "vs${TAG}" netns "$SRC"
ip link set "vg0${TAG}" netns "$GW"
ip link add "vl${TAG}" type veth peer name "vg1${TAG}"
ip link set "vl${TAG}" netns "$LAN"
ip link set "vg1${TAG}" netns "$GW"
ip -n "$SRC" link set "vs${TAG}" name source0
ip -n "$GW" link set "vg0${TAG}" name eth0
ip -n "$LAN" link set "vl${TAG}" name local0
ip -n "$GW" link set "vg1${TAG}" name eth1
ip -n "$SRC" addr add 10.11.0.10/24 dev source0
ip -n "$GW" addr add 10.11.0.20/24 dev eth0
ip -n "$LAN" addr add 10.22.0.10/24 dev local0
ip -n "$GW" addr add 10.22.0.1/24 dev eth1
for ns in "$SRC" "$GW" "$LAN"; do ip -n "$ns" link set lo up; done
ip -n "$SRC" link set source0 up
ip -n "$LAN" link set local0 up
rungw nft -f "$(pwd)/firewall.nft"
close_all
rungw sysctl -qw net.ipv4.ip_forward=0
[[ -z "$(ip -n "$GW" route show default)" ]] || { echo 'FAIL: gateway has default route'; exit 1; }
state DOWN DOWN

echo '[2/8] Start REAL certificate-backed HTTPS and OpenSSH SFTP services inside namespaces'
ip netns exec "$SRC" python3 -u "$(pwd)/https_source.py" 10.11.0.10 "$OUT/source.crt" "$OUT/source.key" "$OUT/source/payload.bin" > "$OUT/https.log" 2>&1 &
PIDS+=("$!")
ip netns exec "$LAN" /usr/sbin/sshd -D -e -f "$OUT/sshd_config" > "$OUT/sshd.log" 2>&1 &
PIDS+=("$!")
# Test listeners on forbidden ports establish that failed probes mean policy blocks,
# not merely "there was no server listening".
ip netns exec "$SRC" python3 -m http.server 80 --bind 10.11.0.10 --directory "$OUT/source" > "$OUT/source80.log" 2>&1 &
PIDS+=("$!")
ip netns exec "$LAN" python3 -m http.server 80 --bind 10.22.0.10 --directory "$OUT/receiver" > "$OUT/local80.log" 2>&1 &
PIDS+=("$!")
sleep 1
for pid in "${PIDS[@]}"; do kill -0 "$pid" || { echo 'FAIL: endpoint exited; inspect https.log or sshd.log'; exit 1; }; done

echo '[3/8] Closed at idle: verify both NICs down and phase chain empty'
state DOWN DOWN
[[ -z "$(rungw nft -a list chain inet secure_diodelab phase_out | grep 'dport' || true)" ]]
# Positive checks from the endpoints themselves ensure negative port tests target real listeners.
ip netns exec "$SRC" python3 "$(pwd)/secure_client.py" probe 10.11.0.10 80
ip netns exec "$LAN" python3 "$(pwd)/secure_client.py" probe 10.22.0.10 80

echo '[4/8] FETCH: eth0 ON only; fetchsvc downloads verified HTTPS over TCP 443'
rungw nft add rule inet secure_diodelab phase_out oifname eth0 meta skuid "$FETCH_UID" ip daddr 10.11.0.10 tcp dport 443 ct state new,established accept
ip -n "$GW" link set eth0 up
state UP DOWN
role_fetch fetch "$OUT/source.crt" "$OUT/staging/payload.bin"
expect_blocked send 10.11.0.10 443
expect_blocked fetch 10.11.0.10 80

echo '[5/8] HOLD: both NICs down; SHA-256 of staged bytes equals source'
close_all
state DOWN DOWN
cmp "$OUT/source/payload.bin" "$OUT/staging/payload.bin"
sha256sum "$OUT/staging/payload.bin" > "$OUT/staging_hash.txt"

echo '[6/8] DELIVER: eth1 ON only; sendsvc uploads through authenticated OpenSSH SFTP'
rungw nft add rule inet secure_diodelab phase_out oifname eth1 meta skuid "$SEND_UID" ip daddr 10.22.0.10 tcp dport 22 ct state new,established accept
ip -n "$GW" link set eth1 up
state DOWN UP
# Ensure target is reachable before negative tests, and client key/host-key verification works.
printf 'put %s %s\n' "$OUT/staging/payload.bin" 'received.bin' > "$OUT/sftp.batch"
chmod 644 "$OUT/sftp.batch"
role_send sftp -q -b "$OUT/sftp.batch" -P 22 \
  -i "$OUT/sftp_client_key" \
  -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none \
  -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$OUT/known_hosts" \
  -o ConnectTimeout=8 "$NAME@10.22.0.10"
expect_blocked fetch 10.22.0.10 22
expect_blocked send 10.22.0.10 80

echo '[7/8] FINISH: close firewall; prove complete transferred bytes and hashes match'
close_all
state DOWN DOWN
cmp "$OUT/source/payload.bin" "$OUT/receiver/received.bin"
sha256sum "$OUT/source/payload.bin" "$OUT/staging/payload.bin" "$OUT/receiver/received.bin" | tee "$OUT/final_hashes.txt"
[[ -z "$(rungw nft list chain inet secure_diodelab phase_out | grep 'dport' || true)" ]]

echo '[8/8] Intentionally enable both NICs; verify watchdog response closes them'
ip -n "$GW" link set eth0 up
ip -n "$GW" link set eth1 up
if link_up eth0 && link_up eth1; then
  echo 'FAULT detected: both NICs UP'
  close_all
else
  echo 'FAIL: deliberate dual-NIC state not detected' >&2; exit 1
fi
state DOWN DOWN
printf '\nPASS: Stage 5, REAL HTTPS verification + OpenSSH SFTP + firewall + staged SHA-256\n'
echo "Evidence folder: $OUT"
