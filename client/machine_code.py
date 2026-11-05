"""机器码采集（规范附录 A / 附录 K）。

强路径（禁止 MD5 / wmic）：
    路径 1：SHA256("{CPU ProcessorId}-{BaseBoard SerialNumber}") → 64 位大写十六进制
    路径 2：SHA256("{ComputerSystemProduct UUID}-{BaseBoard SerialNumber}")
弱路径（仅应急，不得写入强路径缓存）：
    路径 3：系统固定卷序列号 → 8 位大写十六进制
    路径 4：MAC（uuid.getnode）→ SHA256
Linux（附录 K）：/etc/machine-id（或 /var/lib/dbus/machine-id）+ DMI product_uuid/board_serial。
强路径结果必须经 DPAPI（Windows）/0600 文件（Linux）缓存，采集偶发失败时回退缓存，
硬件疑似变更时继续用缓存并告警，禁止自动改绑。
"""

import hashlib
import platform
import subprocess
import sys
from pathlib import Path

INVALID_SET = {
    "", "TO BE FILLED BY O.E.M.", "TO BE FILLED BY OEM", "NONE", "UNKNOWN",
    "DEFAULT STRING", "SYSTEM SERIAL NUMBER", "0", "N/A", "NOT SPECIFIED",
}


def normalize_hw(value):
    s = str(value or "").strip().strip("﻿").strip()
    if not s:
        return ""
    u = s.upper()
    return "" if u in INVALID_SET else u


def _upper_hex_sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest().upper()


def _powershell_cim(class_name, property_name):
    """Windows 采集：PowerShell CIM（规范禁止 wmic / MD5）。"""
    command = (
        f"Get-CimInstance {class_name} | "
        f"Select-Object -First 1 -ExpandProperty {property_name}"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return (result.stdout or "").strip() if result.returncode == 0 else ""


def _probe_path12_windows():
    a = normalize_hw(_powershell_cim("Win32_Processor", "ProcessorId"))
    b = normalize_hw(_powershell_cim("Win32_BaseBoard", "SerialNumber"))
    if a and b:
        return _upper_hex_sha256(f"{a}-{b}"), 1
    a = normalize_hw(_powershell_cim("Win32_ComputerSystemProduct", "UUID"))
    b = normalize_hw(_powershell_cim("Win32_BaseBoard", "SerialNumber"))
    if a and b:
        return _upper_hex_sha256(f"{a}-{b}"), 2
    return None, 0


def _probe_path34_windows():
    try:
        import ctypes
        serial = ctypes.c_uint()
        if ctypes.windll.kernel32.GetVolumeInformationW("C:\\", None, 0, ctypes.byref(serial), None, None, None, 0):
            return format(serial.value & 0xFFFFFFFF, "08X"), 3
    except Exception:
        pass
    return _probe_path4_mac()


def _probe_path4_mac():
    import uuid
    mac = uuid.getnode()
    if mac:
        return _upper_hex_sha256(str(mac)), 4
    return None, 0


def _read_first_existing(paths):
    for path in paths:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        value = normalize_hw(text.splitlines()[0] if text else "")
        if value:
            return value
    return ""


def _probe_linux():
    """附录 K：machine-id + DMI 组合，输出与 Windows 同构的 64 位大写十六进制。"""
    machine_id = _read_first_existing(["/etc/machine-id", "/var/lib/dbus/machine-id"])
    dmi = normalize_hw(_read_first_existing([
        "/sys/class/dmi/id/product_uuid", "/sys/class/dmi/id/board_serial",
    ]))
    if machine_id and dmi:
        return _upper_hex_sha256(f"{machine_id}-{dmi}"), 1
    if machine_id:
        return _upper_hex_sha256(machine_id), 2
    return _probe_path4_mac()


def probe_machine_code():
    """返回 (code, path)；无法采集返回 (None, 0)。path 编号见附录 A。"""
    if sys.platform == "win32":
        code, path = _probe_path12_windows()
        if code:
            return code, path
        return _probe_path34_windows()
    if platform.system() == "Linux":
        return _probe_linux()
    return _probe_path4_mac()


def collect_machine_code(cache=None):
    """附录 A get_machine_code()：带缓存回退的机器码采集。

    cache 需实现 load() -> dict|None、save(code, path)、report_mismatch(cached, live)，
    见 client.state.LocalCache。省略 cache 时只做一次性采集。
    """
    live, path = probe_machine_code()
    if cache is None:
        if not live:
            raise RuntimeError("无法采集机器码")
        return live, path, "live"
    cached = cache.load()
    if live:
        if not cached:
            cache.save(live, path)
            return live, path, "live"
        if live == cached.get("code"):
            return live, path, "cache-agree"
        # 硬件疑似变更：继续用缓存并告警，不自动改绑
        cache.report_mismatch(cached, {"code": live, "path": path})
        return cached["code"], cached.get("path", 0), "cache-mismatch"
    if cached:
        return cached["code"], cached.get("path", 0), "cache-fallback"
    raise RuntimeError("无法采集机器码")
