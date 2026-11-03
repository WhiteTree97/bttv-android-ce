"""Dual-ARM APK policy: native ZIP offsets and ELF load alignment are separate."""
from pathlib import Path
import struct
import zipfile

ZIPALIGN_BUILD_TOOLS = '35.0.0'
NATIVE_ZIP_ALIGNMENT = 16384
SUPPORTED_ABIS = ('arm64-v8a', 'armeabi-v7a')


def zipalign_tool(sdk):
    # Never fall back to the 30.0.3 -p behavior or select an unpinned latest SDK.
    return Path(sdk) / 'build-tools' / ZIPALIGN_BUILD_TOOLS / 'zipalign'


def elf_alignment(data, abi):
    """Inspect PT_LOAD headers without executing/disassembling native code."""
    if abi not in SUPPORTED_ABIS:
        raise ValueError('Unexpected native ABI')
    expected = (2, 183) if abi == 'arm64-v8a' else (1, 40)
    if (len(data) < 64 or data[:4] != b'\x7fELF' or data[5] != 1
            or (data[4], struct.unpack_from('<H', data, 18)[0]) != expected):
        raise ValueError('Native architecture mismatch')
    if struct.unpack_from('<H', data, 16)[0] != 3:
        raise ValueError('Native ELF load alignment failure')
    is64 = data[4] == 2
    if is64:
        offset = struct.unpack_from('<Q', data, 32)[0]
        size, count = struct.unpack_from('<HH', data, 54)
        layout, expected_size = '<IIQQQQQQ', 56
    else:
        offset = struct.unpack_from('<I', data, 28)[0]
        size, count = struct.unpack_from('<HH', data, 42)
        layout, expected_size = '<IIIIIIII', 32
    if size != expected_size or not count or offset < (64 if is64 else 52) or offset + size * count > len(data):
        raise ValueError('Native ELF load alignment failure')
    required = 16384 if is64 else 4096
    loads = []
    for index in range(count):
        header = struct.unpack_from(layout, data, offset + size * index)
        if header[0] != 1:
            continue
        if is64:
            position, address, file_size, memory_size, align = header[2], header[3], header[5], header[6], header[7]
        else:
            position, address, file_size, memory_size, align = header[1], header[2], header[4], header[5], header[7]
        if (align < required or align & (align - 1) or (position - address) % align
                or file_size > memory_size or position + file_size > len(data)):
            raise ValueError('Native ELF load alignment failure')
        loads.append(align)
    if not loads:
        raise ValueError('Native ELF load alignment failure')
    return min(loads)


def check_native_entry(entry, raw, data):
    parts = entry.filename.split('/')
    if len(parts) != 3 or parts[0] != 'lib' or parts[1] not in SUPPORTED_ABIS:
        raise ValueError('Unexpected native ABI')
    raw.seek(entry.header_offset)
    header = raw.read(30)
    if len(header) != 30 or header[:4] != b'PK\x03\x04':
        raise ValueError('Native compression/alignment failure: ' + entry.filename)
    name_size, extra_size = struct.unpack_from('<HH', header, 26)
    offset = entry.header_offset + 30 + name_size + extra_size
    if entry.compress_type != zipfile.ZIP_STORED or offset % NATIVE_ZIP_ALIGNMENT:
        raise ValueError('Native compression/alignment failure: ' + entry.filename)
    return parts[1], elf_alignment(data, parts[1])
