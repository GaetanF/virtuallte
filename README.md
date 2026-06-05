# VirtualLTE

VirtualLTE is a **userspace virtual 5G/LTE UE** (User Equipment). It speaks the
UERANSIM **RLS** protocol toward a gNB over UDP and presents itself to the host
operating system as a **USB CDC-MBIM modem** through the Linux **USB raw-gadget**
interface. From the host's point of view it behaves like a real cellular modem
(ModemManager, MikroTik RouterOS, etc.); from the network's point of view it is a
standard 5G UE.

It is built to attach to an Open5GS / UERANSIM lab and exercise the full call
flow without any physical radio.

## Features

- **5G NAS**: registration (SUCI, Authentication/Milenage, Security Mode), PDU
  session establishment, periodic/mobility updates, graceful de-registration.
- **User plane**: Ethernet/IP PDU data path over RLS, decoupled onto dedicated
  RX/TX threads so throughput and ping latency do not track the USB control loop.
- **USB CDC-MBIM frontend**: device caps, registration/packet-service state,
  connect, IP configuration and SMS service over the raw-gadget UDC.
- **SMS over IMS** (userspace, no extra network interface): a dedicated IMS PDU
  session, SIP `REGISTER` with AKA/MD5 digest, and SMS as SIP `MESSAGE`
  (`application/vnd.3gpp.sms`) carrying 3GPP RP-DATA. Both **mobile-originated**
  and **mobile-terminated** directions, including the RP-ACK.

## Requirements

- Linux with the **`raw_gadget`** kernel module (and a UDC such as the one
  provided by **`dummy_hcd`** for a fully virtual setup).
- A reachable gNB (UERANSIM-compatible RLS endpoint) and a 5G core (e.g. Open5GS).
- SMS over IMS additionally needs an IMS core: an `ims` DNN provisioned in the
  SMF with a **P-CSCF** address, and a reachable P-CSCF / IP-SM-GW.

## Building

```sh
make            # produces ./virtuallte
```

This is Linux-only (it includes `<linux/usb/raw_gadget.h>`).

## Debian package

```sh
dpkg-buildpackage -us -uc -b
sudo apt install ../virtuallte_*.deb
```

The package installs:

- `/usr/sbin/virtuallte` — the executable.
- `/lib/systemd/system/virtuallte@.service` — a systemd template, one unit per UE.
- `/usr/lib/modules-load.d/virtuallte.conf` — loads `raw_gadget` and `dummy_hcd` at boot.
- `/etc/modprobe.d/virtuallte.conf.example` — an **inert** CDC-driver blacklist (see below).
- `/etc/virtuallte/ue1.conf.example` — a sample configuration.

> ℹ️ **CDC-driver blacklist — shipped disabled.**
> `/etc/modprobe.d/virtuallte.conf.example` blacklists the host CDC drivers
> (`cdc_acm`, `cdc_mbim`, `cdc_wdm`, `cdc_ncm`, `cdc_ether`, `usbnet`). It is
> **not active** (modprobe.d only reads `*.conf`). Enable it only for the
> **USBIP → QEMU** export workflow, where the *local* host must not grab the
> virtual gadget:
> ```sh
> sudo cp /etc/modprobe.d/virtuallte.conf.example /etc/modprobe.d/virtuallte.conf
> sudo update-initramfs -u   # then reboot
> ```
> **Do not enable it on a host that needs its own local USB modems.**

## Running

### As a systemd service (recommended)

The service is a **template**: the instance name maps to a config file in
`/etc/virtuallte/`. For an instance `ue1`:

```sh
sudo cp /etc/virtuallte/ue1.conf.example /etc/virtuallte/ue1.conf
sudo editor /etc/virtuallte/ue1.conf            # set SIM, MCC/MNC, gNB address…
sudo systemctl enable --now virtuallte@ue1
journalctl -u virtuallte@ue1 -f
```

Run several UEs by creating more config files (`ue2.conf`, …) and enabling
`virtuallte@ue2`, etc.

### Manually

```sh
sudo modprobe raw_gadget dummy_hcd
sudo ./virtual-mbim --config /etc/virtuallte/ue1.conf
```

## Configuration

INI-style file. See `/etc/virtuallte/ue1.conf.example` for a complete sample.
Key sections:

| Section            | Purpose                                                        |
|--------------------|---------------------------------------------------------------|
| `[device]`         | IMEI and device identity strings.                             |
| `[sim]`            | IMSI, ICCID, Ki (`key`), `opc`, `amf`.                        |
| `[network]`        | `mcc`, `mnc`, `dnn`, operator name, `pdu_type`, `slice_sst`.  |
| `[ran]`            | `gnb_address`, `gnb_port` (RLS, default 4997).                |
| `[backend]`        | `mode=real`.                                                  |
| `[ims]`            | `enabled` — enable SMS over IMS.                              |
| `[sms]`            | `enabled`, `transport` (`ims`).                               |
| `[logging]`        | global `level`; `[logging.domains]` for per-domain levels.    |

Log domains include `mbim`, `ran`, `mm`, `sm`, `up`, `rrc`, `nas`, `ims`.

## SMS over IMS — network side

SMS over IMS only works if the network can deliver it. In Open5GS `smf.yaml`,
the `ims` DNN must advertise a P-CSCF, and that P-CSCF must be IP-reachable from
the UPF data network and able to route SIP `MESSAGE` to an IP-SM-GW / SMSC:

```yaml
  session:
    - subnet: 10.46.0.0/16
      gateway: 10.46.0.1
      dnn: ims
  p-cscf:
    - 10.46.0.10
```

## License

VirtualLTE is licensed under the **GNU Affero General Public License v3.0 or
later** (AGPL-3.0-or-later). See the [`LICENSE`](LICENSE) file for the full text.
