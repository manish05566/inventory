"""Inventory collection: CIM/WMI via one PowerShell call + installed software from the registry."""
import base64
import datetime as dt
import json
import os
import subprocess
from pathlib import Path

from common import AGENT_VERSION, CREATE_NO_WINDOW, as_list, clean, gb, is_admin
PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
function Q($cls, $ns = 'root\cimv2', $filter = $null) {
  try {
    if ($filter) { @(Get-CimInstance -ClassName $cls -Namespace $ns -Filter $filter -ErrorAction Stop) }
    else { @(Get-CimInstance -ClassName $cls -Namespace $ns -ErrorAction Stop) }
  } catch { @() }
}
function D($v) { if ($v) { try { ([datetime]$v).ToString('o') } catch { $null } } else { $null } }
function S($arr) { if ($arr) { (-join [char[]]($arr | Where-Object { $_ -ne 0 })).Trim() } else { $null } }
$r = [ordered]@{}
$r.cs = Q Win32_ComputerSystem | Select-Object -First 1 Name, DNSHostName, Domain, PartOfDomain, Manufacturer, Model, UserName, TotalPhysicalMemory, PCSystemType
$r.os = Q Win32_OperatingSystem | Select-Object -First 1 Caption, Version, BuildNumber, OSArchitecture, @{n='InstallDate';e={D $_.InstallDate}}, @{n='LastBootUpTime';e={D $_.LastBootUpTime}}
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$r.osrel = [ordered]@{ DisplayVersion = $cv.DisplayVersion; UBR = $cv.UBR }
$r.bios = Q Win32_BIOS | Select-Object -First 1 Manufacturer, SMBIOSBIOSVersion, SerialNumber, @{n='ReleaseDate';e={D $_.ReleaseDate}}
$r.csp = Q Win32_ComputerSystemProduct | Select-Object -First 1 UUID, IdentifyingNumber, Vendor, Name
$r.enc = Q Win32_SystemEnclosure | Select-Object -First 1 ChassisTypes, SerialNumber
$r.board = Q Win32_BaseBoard | Select-Object -First 1 Manufacturer, Product, SerialNumber
$r.cpu = @(Q Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed)
$r.mem = @(Q Win32_PhysicalMemory | Select-Object DeviceLocator, Capacity, Speed, Manufacturer, PartNumber)
$r.ldisk = @(Q Win32_LogicalDisk 'root\cimv2' 'DriveType=3' | Select-Object DeviceID, VolumeName, FileSystem, Size, FreeSpace)
$r.pdisk = @(Q MSFT_PhysicalDisk 'root\Microsoft\Windows\Storage' | Select-Object FriendlyName, SerialNumber, MediaType, BusType, Size)
if (-not $r.pdisk) { $r.pdisk = @(Q Win32_DiskDrive | Select-Object @{n='FriendlyName';e={$_.Model}}, SerialNumber, @{n='MediaType';e={$_.MediaType}}, @{n='BusType';e={$_.InterfaceType}}, Size) }
$r.nic = @(Q Win32_NetworkAdapterConfiguration 'root\cimv2' 'IPEnabled=TRUE' | Select-Object Description, MACAddress, IPAddress, IPSubnet, DefaultIPGateway, DNSServerSearchOrder, DHCPEnabled)
$r.gpu = @(Q Win32_VideoController | Select-Object Name, DriverVersion, AdapterRAM)
$r.mon = @(Q WmiMonitorID 'root\wmi' | ForEach-Object { [ordered]@{ Manufacturer = S $_.ManufacturerName; Model = S $_.UserFriendlyName; Serial = S $_.SerialNumberID } })
$r.av = @(Q AntiVirusProduct 'root\SecurityCenter2' | Select-Object displayName, productState)
$r.bl = @(Q Win32_EncryptableVolume 'root\cimv2\Security\MicrosoftVolumeEncryption' | Select-Object DriveLetter, ProtectionStatus)
$r.tpm = Q Win32_Tpm 'root\cimv2\Security\MicrosoftTpm' | Select-Object -First 1 IsEnabled_InitialValue, IsActivated_InitialValue, SpecVersion
$r.qfe = @(Q Win32_QuickFixEngineering | Select-Object HotFixID, Description, @{n='InstalledOn';e={ if ($_.InstalledOn) { try { ([datetime]$_.InstalledOn).ToString('yyyy-MM-dd') } catch { $null } } }})
$r | ConvertTo-Json -Depth 5 -Compress
"""

LAPTOP_CHASSIS = {8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32}
SERVER_CHASSIS = {17, 23, 28}
VM_HINTS = ("virtual", "vmware", "kvm", "qemu", "xen", "hvm domu", "innotek", "parallels", "bochs")


def run_powershell(script, timeout=180):
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    ps = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    out = subprocess.run([str(ps), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
                         capture_output=True, timeout=timeout, creationflags=CREATE_NO_WINDOW)
    text = out.stdout.decode("utf-8", errors="replace").strip().lstrip("\ufeff")
    start = text.find("{")
    if start < 0:
        raise RuntimeError("PowerShell collection returned no data: " + out.stderr.decode(errors="replace")[:500])
    return json.loads(text[start:])


def collect_software():
    import winreg
    seen, result = set(), []
    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_64KEY),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_32KEY),
    ]
    # Per-user installs for every loaded user profile (we run as SYSTEM).
    try:
        with winreg.OpenKey(winreg.HKEY_USERS, "") as hu:
            i = 0
            while True:
                try:
                    sid = winreg.EnumKey(hu, i)
                except OSError:
                    break
                i += 1
                if sid.startswith("S-1-5-21-") and not sid.endswith("_Classes"):
                    roots.append((winreg.HKEY_USERS, sid + r"\Software\Microsoft\Windows\CurrentVersion\Uninstall", 0))
    except OSError:
        pass
    if not is_admin():
        roots.append((winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", 0))

    def val(k, name):
        try:
            return winreg.QueryValueEx(k, name)[0]
        except OSError:
            return None

    for hive, path, flag in roots:
        try:
            root = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | flag)
        except OSError:
            continue
        with root:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(root, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(root, sub) as k:
                        name = clean(val(k, "DisplayName"))
                        if not name or val(k, "SystemComponent") == 1 or val(k, "ParentKeyName"):
                            continue
                        if str(val(k, "ReleaseType") or "") in ("Update", "Hotfix", "Security Update", "Service Pack"):
                            continue
                        version = clean(val(k, "DisplayVersion")) or ""
                        key = (name.lower(), version)
                        if key in seen:
                            continue
                        seen.add(key)
                        idate = clean(val(k, "InstallDate"))
                        if idate and len(idate) == 8 and idate.isdigit():
                            idate = f"{idate[:4]}-{idate[4:6]}-{idate[6:]}"
                        else:
                            idate = None
                        result.append({"name": name, "version": version, "publisher": clean(val(k, "Publisher")) or "",
                                       "install_date": idate})
                except OSError:
                    continue
    result.sort(key=lambda s: s["name"].lower())
    return result


AV_STATE = {0x10: "enabled", 0x11: "enabled", 0x00: "disabled", 0x01: "disabled"}
BL_STATUS = {0: "Off", 1: "On", 2: "Unknown"}
MEDIA = {3: "HDD", 4: "SSD", 5: "SCM"}


def collect():
    raw = run_powershell(PS_SCRIPT)
    cs, os_, bios, csp = raw.get("cs") or {}, raw.get("os") or {}, raw.get("bios") or {}, raw.get("csp") or {}
    enc, board, osrel = raw.get("enc") or {}, raw.get("board") or {}, raw.get("osrel") or {}
    cpus = as_list(raw.get("cpu"))
    chassis_types = set(as_list(enc.get("ChassisTypes")))
    model_str = f"{cs.get('Manufacturer') or ''} {cs.get('Model') or ''}".lower()
    if any(h in model_str for h in VM_HINTS):
        chassis = "vm"
    elif chassis_types & LAPTOP_CHASSIS or cs.get("PCSystemType") == 2:
        chassis = "laptop"
    elif chassis_types & SERVER_CHASSIS:
        chassis = "server"
    else:
        chassis = "desktop"
    serial = clean(bios.get("SerialNumber")) or clean(csp.get("IdentifyingNumber")) or clean(enc.get("SerialNumber"))
    user = clean(cs.get("UserName"))

    build = clean(os_.get("BuildNumber"))
    if build and osrel.get("UBR") is not None:
        build = f"{build}.{osrel['UBR']}"

    nics = []
    for n in as_list(raw.get("nic")):
        ips = as_list(n.get("IPAddress"))
        nics.append({
            "name": clean(n.get("Description")), "mac": clean(n.get("MACAddress")),
            "ip": [ip for ip in ips if ip], "subnet": as_list(n.get("IPSubnet")),
            "gateway": as_list(n.get("DefaultIPGateway")), "dns": as_list(n.get("DNSServerSearchOrder")),
            "dhcp": bool(n.get("DHCPEnabled")),
        })
    # Prefer the adapter with a default gateway as the primary.
    nics.sort(key=lambda n: (not n["gateway"], not any("." in i for i in n["ip"])))

    tpm = raw.get("tpm")
    return {
        "agent_version": AGENT_VERSION,
        "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "system": {
            "hostname": clean(cs.get("DNSHostName")) or clean(cs.get("Name")) or os.environ.get("COMPUTERNAME"),
            "domain": clean(cs.get("Domain")) if cs.get("PartOfDomain") else None,
            "manufacturer": clean(cs.get("Manufacturer")), "model": clean(cs.get("Model")),
            "serial": serial, "uuid": clean(csp.get("UUID")), "chassis": chassis, "logged_user": user,
            "ram_mb": int(int(cs.get("TotalPhysicalMemory") or 0) / 1024 / 1024) or None,
        },
        "os": {
            "name": clean(os_.get("Caption")), "version": clean(osrel.get("DisplayVersion")) or clean(os_.get("Version")),
            "build": build, "arch": clean(os_.get("OSArchitecture")),
            "install_date": os_.get("InstallDate"), "last_boot": os_.get("LastBootUpTime"),
        },
        "cpu": {
            "name": clean(cpus[0].get("Name")) if cpus else None, "sockets": len(cpus),
            "cores": sum(int(c.get("NumberOfCores") or 0) for c in cpus) or None,
            "logical": sum(int(c.get("NumberOfLogicalProcessors") or 0) for c in cpus) or None,
            "speed_mhz": cpus[0].get("MaxClockSpeed") if cpus else None,
        },
        "memory_modules": [{"slot": clean(m.get("DeviceLocator")), "capacity_mb": int(int(m.get("Capacity") or 0) / 1048576),
                            "speed": m.get("Speed"), "manufacturer": clean(m.get("Manufacturer")),
                            "part_number": clean(m.get("PartNumber"))} for m in as_list(raw.get("mem"))],
        "disks": [{"name": d.get("DeviceID"), "label": clean(d.get("VolumeName")), "fs": d.get("FileSystem"),
                   "size_gb": gb(d.get("Size")), "free_gb": gb(d.get("FreeSpace"))} for d in as_list(raw.get("ldisk"))],
        "physical_disks": [{"model": clean(d.get("FriendlyName")), "serial": clean(d.get("SerialNumber")),
                            "media": MEDIA.get(d.get("MediaType"), d.get("MediaType") if isinstance(d.get("MediaType"), str) else None),
                            "bus": d.get("BusType"), "size_gb": gb(d.get("Size"))} for d in as_list(raw.get("pdisk"))],
        "nics": nics,
        "gpus": [{"name": clean(g.get("Name")), "driver": g.get("DriverVersion"),
                  "ram_mb": int(int(g.get("AdapterRAM") or 0) / 1048576) or None} for g in as_list(raw.get("gpu"))],
        "monitors": [{"manufacturer": m.get("Manufacturer"), "model": m.get("Model"), "serial": m.get("Serial")}
                     for m in as_list(raw.get("mon"))],
        "bios": {"vendor": clean(bios.get("Manufacturer")), "version": clean(bios.get("SMBIOSBIOSVersion")),
                 "date": (bios.get("ReleaseDate") or "")[:10] or None},
        "motherboard": {"manufacturer": clean(board.get("Manufacturer")), "product": clean(board.get("Product")),
                        "serial": clean(board.get("SerialNumber"))},
        "antivirus": [{"name": a.get("displayName"),
                       "state": AV_STATE.get((int(a.get("productState") or 0) >> 8) & 0xFF, "unknown")}
                      for a in as_list(raw.get("av"))],
        "encryption": [{"drive": e.get("DriveLetter"), "status": BL_STATUS.get(e.get("ProtectionStatus"), "Unknown")}
                       for e in as_list(raw.get("bl")) if e.get("DriveLetter")],
        "tpm": {"enabled": tpm.get("IsEnabled_InitialValue"), "activated": tpm.get("IsActivated_InitialValue"),
                "spec": tpm.get("SpecVersion")} if tpm else None,
        "updates": [{"id": u.get("HotFixID"), "description": u.get("Description"), "installed_on": u.get("InstalledOn")}
                    for u in as_list(raw.get("qfe")) if u.get("HotFixID")],
        "software": collect_software(),
    }


