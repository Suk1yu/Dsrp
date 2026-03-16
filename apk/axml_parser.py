"""
apk/axml_parser.py

Pure-Python Android Binary XML (AXML) parser.
Parses AndroidManifest.xml from real APK files without aapt/androguard.

Android Binary XML format:
  File header  → magic 0x00080003
  String pool  → all strings used in XML
  XML events   → START_NAMESPACE, START_ELEMENT, ATTR, END_ELEMENT, ...

Output: dict with package_name, permissions, services, activities, etc.
No external dependencies — stdlib only.
"""

import struct
from dataclasses import dataclass, field
from typing import Optional


# ── Chunk types ───────────────────────────────────────────────────────────────
RES_NULL_TYPE              = 0x0000
RES_STRING_POOL_TYPE       = 0x0001
RES_TABLE_TYPE             = 0x0002
RES_XML_TYPE               = 0x0003
RES_XML_START_NAMESPACE    = 0x0100
RES_XML_END_NAMESPACE      = 0x0101
RES_XML_START_ELEMENT      = 0x0102
RES_XML_END_ELEMENT        = 0x0103
RES_XML_CDATA              = 0x0104
RES_XML_RESOURCE_MAP       = 0x0180
RES_TABLE_PACKAGE_TYPE     = 0x0200
RES_TABLE_TYPE_TYPE        = 0x0201
RES_TABLE_CONFIG_TYPE      = 0x0202

# Attribute value types
TYPE_NULL      = 0x00
TYPE_REFERENCE = 0x01
TYPE_STRING    = 0x03
TYPE_INT_DEC   = 0x10
TYPE_INT_HEX   = 0x11
TYPE_INT_BOOL  = 0x12

ANDROID_NS = "http://schemas.android.com/apk/res/android"


@dataclass
class ManifestData:
    package_name: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: int = 0
    target_sdk: int = 0
    permissions: list = field(default_factory=list)
    activities: list = field(default_factory=list)
    services: list = field(default_factory=list)
    receivers: list = field(default_factory=list)
    providers: list = field(default_factory=list)
    features: list = field(default_factory=list)
    debuggable: bool = False
    allow_backup: bool = True
    uses_cleartext: bool = False
    parse_error: str = ""

    def to_dict(self) -> dict:
        return {
            "package_name": self.package_name,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "permissions": self.permissions,
            "activities": self.activities,
            "services": self.services,
            "receivers": self.receivers,
            "providers": self.providers,
            "debuggable": self.debuggable,
            "allow_backup": self.allow_backup,
            "uses_cleartext": self.uses_cleartext,
        }


class AXMLParser:
    """
    Parses Android Binary XML format (AXML).
    Call parse(data: bytes) → ManifestData.
    """

    def __init__(self):
        self._strings: list[str] = []
        self._ns_map: dict[str, str] = {}

    def parse(self, data: bytes) -> ManifestData:
        manifest = ManifestData()
        if len(data) < 8:
            manifest.parse_error = "File too small"
            return manifest

        # Validate magic
        magic = struct.unpack_from("<H", data, 0)[0]
        if magic != RES_XML_TYPE:
            manifest.parse_error = f"Not AXML (magic=0x{magic:04x})"
            return manifest

        pos = 8  # skip file header (type + size)
        element_stack: list[str] = []

        while pos < len(data) - 8:
            try:
                chunk_type = struct.unpack_from("<H", data, pos)[0]
                chunk_size = struct.unpack_from("<I", data, pos + 4)[0]

                if chunk_size < 8 or pos + chunk_size > len(data):
                    break

                if chunk_type == RES_STRING_POOL_TYPE:
                    self._strings = self._parse_string_pool(data, pos)

                elif chunk_type == RES_XML_START_NAMESPACE:
                    prefix_idx = struct.unpack_from("<i", data, pos + 12)[0]
                    uri_idx    = struct.unpack_from("<i", data, pos + 16)[0]
                    if 0 <= uri_idx < len(self._strings):
                        uri = self._strings[uri_idx]
                        if 0 <= prefix_idx < len(self._strings):
                            self._ns_map[self._strings[prefix_idx]] = uri

                elif chunk_type == RES_XML_START_ELEMENT:
                    name_idx  = struct.unpack_from("<i", data, pos + 20)[0]
                    attr_off  = struct.unpack_from("<H", data, pos + 28)[0]
                    attr_count= struct.unpack_from("<H", data, pos + 30)[0]

                    elem_name = self._str(name_idx)
                    element_stack.append(elem_name)

                    attrs = self._parse_attrs(
                        data, pos + 8 + attr_off, attr_count)

                    self._handle_element(manifest, elem_name, attrs)

                elif chunk_type == RES_XML_END_ELEMENT:
                    if element_stack:
                        element_stack.pop()

                pos += chunk_size

            except (struct.error, IndexError):
                break

        return manifest

    # ── String pool ───────────────────────────────────────────────────────────

    def _parse_string_pool(self, data: bytes, pool_start: int) -> list[str]:
        strings = []
        try:
            # pool header: type(2) headerSize(2) chunkSize(4) stringCount(4)
            #              styleCount(4) flags(4) stringsStart(4) stylesStart(4)
            header_size  = struct.unpack_from("<H", data, pool_start + 2)[0]
            string_count = struct.unpack_from("<I", data, pool_start + 8)[0]
            flags        = struct.unpack_from("<I", data, pool_start + 16)[0]
            strings_start= struct.unpack_from("<I", data, pool_start + 20)[0]
            is_utf8      = bool(flags & (1 << 8))

            offsets_start = pool_start + header_size
            data_start    = pool_start + strings_start

            for i in range(string_count):
                try:
                    offset = struct.unpack_from("<I", data, offsets_start + i * 4)[0]
                    spos   = data_start + offset
                    s = self._read_string(data, spos, is_utf8)
                    strings.append(s)
                except Exception:
                    strings.append("")
        except Exception:
            pass
        return strings

    def _read_string(self, data: bytes, pos: int, is_utf8: bool) -> str:
        try:
            if is_utf8:
                # UTF-8: u8len, u8len_again, chars, 0x00
                char_len = data[pos] & 0x7F
                if data[pos] & 0x80:
                    char_len = ((char_len & 0x7F) << 8) | data[pos + 1]
                    pos += 1
                pos += 1
                byte_len = data[pos] & 0x7F
                if data[pos] & 0x80:
                    byte_len = ((byte_len & 0x7F) << 8) | data[pos + 1]
                    pos += 1
                pos += 1
                return data[pos: pos + byte_len].decode("utf-8", errors="replace")
            else:
                # UTF-16-LE
                length = struct.unpack_from("<H", data, pos)[0]
                if length & 0x8000:
                    length = ((length & 0x7FFF) << 16) | \
                             struct.unpack_from("<H", data, pos + 2)[0]
                    pos += 2
                pos += 2
                raw = data[pos: pos + length * 2]
                return raw.decode("utf-16-le", errors="replace")
        except Exception:
            return ""

    # ── Attribute parsing ─────────────────────────────────────────────────────

    def _parse_attrs(self, data: bytes, start: int,
                     count: int) -> dict[str, str]:
        """
        Each attribute is 20 bytes:
        ns(4) name(4) rawVal(4) valueSize(2) res0(1) dataType(1) data(4)
        """
        attrs: dict[str, str] = {}
        for i in range(count):
            base = start + i * 20
            if base + 20 > len(data):
                break
            try:
                name_idx  = struct.unpack_from("<i", data, base + 4)[0]
                data_type = data[base + 15]
                raw_data  = struct.unpack_from("<i", data, base + 16)[0]
                raw_val   = struct.unpack_from("<i", data, base + 8)[0]

                name = self._str(name_idx)

                if data_type == TYPE_STRING:
                    value = self._str(raw_val)
                elif data_type == TYPE_INT_BOOL:
                    value = str(bool(raw_data))
                elif data_type in (TYPE_INT_DEC, TYPE_INT_HEX):
                    value = str(raw_data)
                elif data_type == TYPE_REFERENCE:
                    # Could resolve, but for our purposes string repr is enough
                    value = f"@0x{raw_data:08x}"
                else:
                    value = self._str(raw_val) if raw_val >= 0 else str(raw_data)

                if name:
                    attrs[name] = value
            except Exception:
                pass
        return attrs

    # ── Element handler ───────────────────────────────────────────────────────

    def _handle_element(self, manifest: ManifestData,
                         elem: str, attrs: dict[str, str]):
        name = attrs.get("name", "")

        if elem == "manifest":
            manifest.package_name = attrs.get("package", "")
            manifest.version_name = attrs.get("versionName", "")
            vc = attrs.get("versionCode", "0")
            try:
                manifest.version_code = str(int(vc, 0) if vc.startswith("0x") else int(vc))
            except Exception:
                manifest.version_code = vc

        elif elem == "uses-sdk":
            for k in ("minSdkVersion", "minsdkversion"):
                v = attrs.get(k, "")
                if v:
                    try:
                        manifest.min_sdk = int(v, 0) if v.startswith("0x") else int(v)
                    except Exception:
                        pass
            for k in ("targetSdkVersion", "targetsdkversion"):
                v = attrs.get(k, "")
                if v:
                    try:
                        manifest.target_sdk = int(v, 0) if v.startswith("0x") else int(v)
                    except Exception:
                        pass

        elif elem == "uses-permission":
            if name and name not in manifest.permissions:
                manifest.permissions.append(name)

        elif elem == "activity":
            if name and name not in manifest.activities:
                manifest.activities.append(name)

        elif elem == "service":
            if name and name not in manifest.services:
                manifest.services.append(name)

        elif elem == "receiver":
            if name and name not in manifest.receivers:
                manifest.receivers.append(name)

        elif elem == "provider":
            if name and name not in manifest.providers:
                manifest.providers.append(name)

        elif elem == "uses-feature":
            feat = attrs.get("name", "")
            if feat:
                manifest.features.append(feat)

        elif elem == "application":
            debug = attrs.get("debuggable", "false")
            manifest.debuggable = debug.lower() in ("true", "1")
            backup = attrs.get("allowBackup", "true")
            manifest.allow_backup = backup.lower() in ("true", "1")
            ct = attrs.get("usesCleartextTraffic", "false")
            manifest.uses_cleartext = ct.lower() in ("true", "1")

    def _str(self, idx: int) -> str:
        if 0 <= idx < len(self._strings):
            return self._strings[idx]
        return ""


# ── Convenience function ──────────────────────────────────────────────────────

def parse_manifest_bytes(data: bytes) -> ManifestData:
    """Parse raw AndroidManifest.xml bytes (binary or text)."""
    # Detect if binary XML
    if len(data) >= 2 and data[0] == 0x03 and data[1] == 0x00:
        return AXMLParser().parse(data)

    # Fallback: text XML (test APKs, decompiled APKs)
    import re
    m = ManifestData()
    text = data.decode("utf-8", errors="replace")

    pkg = re.search(r'package\s*=\s*["\']([^"\']+)["\']', text)
    if pkg:
        m.package_name = pkg.group(1)

    vn = re.search(r'versionName\s*=\s*["\']([^"\']+)["\']', text)
    if vn:
        m.version_name = vn.group(1)

    for perm in re.findall(r'android\.permission\.[\w.]+', text):
        if perm not in m.permissions:
            m.permissions.append(perm)

    return m