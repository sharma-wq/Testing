# Data Diode Gateway — Real Linux Networking Proof (pre-hardware test)

**Objective:** Go beyond Windows Python mocks. Exercise **actual Linux kernel** network devices, nftables rule enforcement, sockets and transfer integrity before buying a Raspberry Pi.

## What it does

Creates **three isolated Linux network namespaces** inside an Ubuntu VM:

```
[Internet source namespace] --veth-- eth0 [Gateway namespace] eth1 --veth-- [Local receiver namespace]
  10.11.0.10:443                 10.11.0.20       10.22.0.1       10.22.0.10:22
```

- FETCH: `eth0 UP`, `eth1 DOWN`; only UID **21001** can connect to source **10.11.0.10:443**.
- HOLD: both DOWN; downloaded bytes remain in disk-backed staging directory.
- DELIVER: `eth0 DOWN`, `eth1 UP`; only UID **21002** can connect to receiver **10.22.0.10:22**.
- FINISH: both DOWN, no temporary firewall rules; matching received SHA-256.
- Negative checks: wrong UID, wrong port, no route, firewall-default-deny, deliberate both-links-UP fault + fail-close.

**Important:** This lab uses **plain HTTP on TCP ports 443 and 22 solely to test packet policy**. It does **NOT** test TLS/HTTPS, SSH/SFTP key authentication, the actual Raspberry Pi controller, a real USB disk, reboot handling, or physical hardware isolation. The protocol service/port names are deliberately not presented as HTTPS/SSH implementations. Real security deployment still requires those separate acceptance tests.

## Requirements

1. Windows computer with **an Ubuntu Server/Desktop VM** (VMware Workstation, VirtualBox, etc.). Use Ubuntu 24.04 LTS or equivalent.
2. Linux VM with `sudo` privileges. No extra virtual NICs are needed; namespaces provide the virtual test wiring.
3. Run **inside the Ubuntu VM terminal**, not directly in Windows PowerShell or Windows VS Code terminal.
4. Installer only runs **before** testing, to install packages. The lab itself creates no public listeners and does not modify the VM's main interface, routing or firewall.

## Setup on Ubuntu

Copy the extracted `Data_Diode_Real_Linux_Proof` folder to the Ubuntu VM, then:

```bash
cd ~/Data_Diode_Real_Linux_Proof
sudo apt update
sudo apt install -y iproute2 nftables python3 util-linux
bash -n run_kernel_lab.sh
python3 -m py_compile lab_client.py lab_endpoint.py
sudo bash run_kernel_lab.sh
```

Expected final lines:

```text
FAULT DETECTED (intentional): both links UP -> fail-closed
Interfaces: eth0=DOWN eth1=DOWN (expected DOWN/DOWN)
PASS: Live Linux-kernel isolation, UID/port firewall checks, staged file transfer and fail-close demo
Evidence retained in: .../lab-results/YYYYMMDD-HHMMSS-PID
```

Logs, source file, staged file, receiver file and SHA-256 evidence are retained under `lab-results/`. Network namespaces are deleted automatically on exit. `sudo` ownership may require `sudo` to read those artifacts.

## Evaluation / acceptance boundary

A passed lab supports feasibility of **store-and-forward software-controlled isolation** using the real Linux kernel. It **cannot** prove a security-grade data diode. The program can turn both virtual NICs UP (the injected fault demonstrates this), so an independent hardware mechanism is needed if physical one-way enforcement is required.

The Raspberry Pi-specific installer, startup services, real HTTPS/SFTP, USB storage, watchdog, rollback, threat model and power-loss behavior **remain unvalidated** by this lab. Do not infer those components passed because the lab passes.

Do **not** run this proof script on a production router or shared Linux host. Use a disposable Ubuntu VM. The test servers use elevated service context because they bind low-numbered test ports; they only bind IP addresses in disposable network namespaces.
