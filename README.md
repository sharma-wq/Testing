# Stage 5 – HTTPS + SFTP live kernel lab (pre-hardware)

This is a **test-only** lab for the Data Diode Gateway's fifth development stage. It builds on the Stage 4 namespace/nftables proof. It uses a **real certificate-validated HTTPS/TLS source** and an **actual OpenSSH SFTP receiver with key-based authentication**, separated by a Linux gateway namespace. It verifies 128 KiB of data, its SHA-256 digests, UID- and port-scoped `nftables` rules, interface switching and a deliberate both-NICs-UP fault.

**Not:** a Raspberry Pi production installer; a hardware-enforced data diode; a test of real removable 4 TB media, physical power interruption, real Internet sources, or deployed device services.

## Requirements

Disposable Ubuntu/Killercoda environment with root privileges, network namespaces and nftables support (you already successfully completed Stage 4 in such an environment). Internet is required only to install packages; the live file transfers remain inside private network namespaces. Execute only in a **throwaway test VM/playground**.

```bash
sudo apt update
sudo apt install -y iproute2 nftables python3 openssl openssh-client openssh-server util-linux passwd unzip
```

## Upload and run

Download the ZIP from ChatGPT, upload it into the existing GitHub `Testing` repository (or another file transfer mechanism into the online Ubuntu terminal). Then clone/pull the repo in Killercoda. Keep the test files outside `/root` so the restricted `fetchsvc`/`sendsvc` identities can read Python scripts:

```bash
# After transferring the ZIP to the online Ubuntu environment:
mkdir -p /tmp/stage5-files
unzip -o Data_Diode_Stage5_HTTPS_SFTP_Lab.zip -d /tmp/stage5-files
cd /tmp/stage5-files/Data_Diode_Stage5_HTTPS_SFTP_Lab
bash -n run_secure_lab.sh
python3 -m py_compile https_source.py secure_client.py
sudo bash run_secure_lab.sh
```

When the ZIP is under your clone, use `find ~/Testing -name 'Data_Diode_Stage5_HTTPS_SFTP_Lab.zip'` to identify its location; pass that absolute path to `unzip`. An earlier GitHub repo had a nested `Testing/Testing` directory, so do not assume the ZIP is in the first directory.

## Expected outputs

The script prints `[1/8]` to `[8/8]`. Look for:

```text
[4/8] FETCH ...
HTTPS VERIFIED: TLS + hostname + trusted certificate; bytes: 131072
[5/8] HOLD ...
[6/8] DELIVER ...
[7/8] FINISH ...
[8/8] ... both NICs UP -> closed
PASS: Stage 5, REAL HTTPS verification + OpenSSH SFTP + firewall + staged SHA-256
```

The script creates a temporary unprivileged SSH account for the receiver and removes it at exit. It also removes temporary private keys after the run, keeping public logs and hash evidence under `/tmp/diode-stage5-PID`. It does not change the host's physical network interfaces or host `nftables` firewall. The OpenSSH server binds only to `10.22.0.10:22` inside an isolated network namespace. If the account cannot be created in your playground, use a disposable Ubuntu VM with sufficient privileges.

## Design and proof boundaries

**What is actually tested:** TLS handshake, certificate trust, hostname verification, HTTPS response/body integrity; OpenSSH host-key pinning, SSH public-key authentication, SFTP upload; source/receiver file hash equality; disallowed UID and port blocks while their target services exist; both-interface shutdown between phases.

**What remains:** Tests against the actual Raspberry Pi Python controller, actual Pi NICs and USB disk, durable application policy after a crash/power loss, live network threat model, malicious-content screening, runtime protocol compatibility and security review. Software interface controls alone are **not a physical one-way data diode**.

If Stage 5 fails, copy the last 20 terminal lines plus `/tmp/diode-stage5-*/sshd.log` or `https.log`; do not share the private keys.
