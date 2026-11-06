"""Read app identity and signing material from APK/APKS files without executing them."""
from __future__ import annotations
from dataclasses import dataclass, field
import io
from pathlib import Path
import re
import struct
import xml.etree.ElementTree as ET
import zipfile
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

PACKAGE = 'com.bugull.socket.myts'
MAX_ARCHIVE = 256 * 1024 * 1024
MAX_MEMBER = 80 * 1024 * 1024


class AppArchiveError(ValueError):
    """Archive metadata or signing material cannot be read safely."""


@dataclass(frozen=True)
class AppMaterial:
    package: str
    version: str
    key: object = field(repr=False)


def manifest_identity(data):
    """Read manifest versionName/package from plain or Android binary XML."""
    if data.lstrip().startswith(b'<'):
        root = ET.fromstring(data)
        return root.get('package', ''), root.get('{http://schemas.android.com/apk/res/android}versionName', '')
    def u16(offset):
        return struct.unpack_from('<H', data, offset)[0]
    def u32(offset):
        return struct.unpack_from('<I', data, offset)[0]
    def length8(offset):
        first = data[offset]
        if first & 0x80:
            return ((first & 0x7f) << 8) | data[offset + 1], offset + 2
        return first, offset + 1
    def length16(offset):
        first = u16(offset)
        if first & 0x8000:
            return ((first & 0x7fff) << 16) | u16(offset + 2), offset + 4
        return first, offset + 2
    if len(data) < 8 or u16(0) != 3 or u32(4) > len(data):
        raise AppArchiveError('AndroidManifest.xml is not valid Android XML')
    strings = []
    offset = u16(2)
    while offset + 8 <= len(data):
        kind, header, size = struct.unpack_from('<HHI', data, offset)
        if header < 8 or size < header or offset + size > len(data):
            raise AppArchiveError('Android manifest has an invalid chunk')
        if kind == 1:
            count, _, flags, start, _ = struct.unpack_from('<IIIII', data, offset + 8)
            if count > 100000 or header + count * 4 > size:
                raise AppArchiveError('Android manifest has an invalid string pool')
            strings = []
            for index in range(count):
                position = offset + start + u32(offset + header + 4 * index)
                if flags & 0x100:
                    _, position = length8(position)
                    length, position = length8(position)
                    strings.append(data[position:position + length].decode('utf-8'))
                else:
                    length, position = length16(position)
                    strings.append(data[position:position + length * 2].decode('utf-16le'))
        elif kind == 0x102 and strings:
            extension = offset + header
            name = u32(extension + 4)
            if name >= len(strings):
                raise AppArchiveError('Android manifest has an invalid element name')
            if strings[name] == 'manifest':
                start, stride, count = struct.unpack_from('<HHH', data, extension + 8)
                if stride < 20 or extension + start + count * stride > offset + size:
                    raise AppArchiveError('Android manifest has invalid attributes')
                values = {}
                for index in range(count):
                    attribute = extension + start + index * stride
                    name_index, raw = u32(attribute + 4), u32(attribute + 8)
                    data_type, typed = data[attribute + 15], u32(attribute + 16)
                    if name_index >= len(strings):
                        raise AppArchiveError('Android manifest has an invalid attribute name')
                    if raw < len(strings):
                        value = strings[raw]
                    elif data_type == 3 and typed < len(strings):
                        value = strings[typed]
                    else:
                        value = ''
                    values[strings[name_index]] = value
                return values.get('package', ''), values.get('versionName', '')
        offset += size
    raise AppArchiveError('Android manifest identity was not found')


def load_app_material(path):
    """Resolve the APK manifest and RSA key from the same base application."""
    path = Path(str(path).strip()).expanduser()
    if not path.is_file():
        raise FileNotFoundError('App archive must exist on the Home Assistant filesystem')
    if path.stat().st_size > MAX_ARCHIVE:
        raise AppArchiveError('App archive exceeds the 256 MiB limit')
    wrong_package = False
    matched = False
    def inspect(archive, depth=0):
        nonlocal wrong_package, matched
        names = archive.namelist()
        if 'AndroidManifest.xml' in names:
            info = archive.getinfo('AndroidManifest.xml')
            if info.file_size > 4 * 1024 * 1024:
                raise AppArchiveError('Android manifest is too large')
            package, version = manifest_identity(archive.read(info))
            if package != PACKAGE:
                wrong_package = True
                return None
            matched = True
            # Resource-only splits do not carry the signing implementation.
            dex_files = [item for item in archive.infolist() if re.fullmatch(r'classes\d*\.dex', item.filename)]
            if dex_files and not version:
                raise AppArchiveError('The app manifest does not contain a readable versionName')
            for item in dex_files:
                if item.file_size > MAX_MEMBER:
                    raise AppArchiveError('App DEX exceeds the 80 MiB limit')
                for candidate in re.findall(rb'30[0-9a-fA-F]{1200,10000}', archive.read(item)):
                    try:
                        key = serialization.load_der_private_key(bytes.fromhex(candidate.decode()), None)
                        if isinstance(key, rsa.RSAPrivateKey) and key.key_size >= 2048:
                            return AppMaterial(package, version, key)
                    except (ValueError, TypeError, UnsupportedAlgorithm):
                        continue
            return None
        if depth >= 1:
            raise AppArchiveError('Unsupported nested app archive')
        members = sorted(archive.infolist(), key=lambda item: (not item.filename.endswith('base.apk'), item.filename))
        for item in members:
            if not item.filename.endswith('.apk'):
                continue
            if item.file_size > MAX_MEMBER:
                raise AppArchiveError('Nested APK exceeds the 80 MiB limit')
            with zipfile.ZipFile(io.BytesIO(archive.read(item))) as nested:
                result = inspect(nested, depth + 1)
                if result:
                    return result
        return None
    try:
        with zipfile.ZipFile(path) as archive:
            result = inspect(archive)
    except (zipfile.BadZipFile, UnicodeError, struct.error, IndexError, ET.ParseError) as err:
        raise AppArchiveError('App archive or Android manifest is corrupt or unsupported') from err
    if result:
        return result
    if wrong_package and not matched:
        raise AppArchiveError('This archive is not the myTS Android application')
    raise AppArchiveError('No compatible RSA signing implementation was found in the myTS app')
