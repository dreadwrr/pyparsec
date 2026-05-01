import ctypes
import os
# 05/01/2026 mft parsec wrapper for parsing ntfs MFT
# by Colby Saigeon

TICKS_BTWN_1601_1970 = 11644473600000000
TICKS_BTWN_1601_1970_NS = 11644473600000000000
MAX_NAME = 1024


class FileEntry(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("frn",                   ctypes.c_uint64),
        ("parent_frn",            ctypes.c_uint64),
        ("record_number",         ctypes.c_uint32),
        ("sequence_num",          ctypes.c_uint16),
        ("record_offset",         ctypes.c_uint64),
        ("name",                  ctypes.c_char_p),
        ("name_len",              ctypes.c_uint16),
        ("size",                  ctypes.c_uint64),
        ("dir_path",              ctypes.c_char_p),
        ("dir_path_ready",        ctypes.c_uint8),
        ("in_use",                ctypes.c_uint8),
        ("is_dir",                ctypes.c_uint8),
        ("has_ads",               ctypes.c_uint8),
        ("hard_link_count",       ctypes.c_uint16),
        ("link_index",            ctypes.c_uint16),
        ("link_count",            ctypes.c_uint16),
        ("file_attribs",          ctypes.c_uint32),
        ("usn",                   ctypes.c_uint64),
        ("creation_time",         ctypes.c_uint64),
        ("modification_time",     ctypes.c_uint64),
        ("mft_modification_time", ctypes.c_uint64),
        ("access_time",           ctypes.c_uint64),
    ]


def ntfs_to_us(value):
    """ us epoch """
    try:
        return (int(value) // 10) - TICKS_BTWN_1601_1970
    except (ValueError, TypeError):
        return None


def ntfs_to_ns(value):
    try:
        return (int(value) * 100) - TICKS_BTWN_1601_1970_NS
    except (ValueError, TypeError):
        return None


def frn_to_entry(frn):
    record_num = frn & 0xFFFFFFFFFFFF
    sequence_num = (frn >> 48) & 0xFFFF
    return record_num, sequence_num


def entry_to_frn(record_num, sequence_num):
    return (sequence_num << 48) | record_num


def output_parserlib(target: str, ns=False, ticks=False):
    """ timestamps in us epoch default, ns epoch or the ntfs 100ns ticks
        returns a dict of dirs and list of files in tuples """

    if ns and ticks:
        print("both ns and ticks options set, defaulting to ns")

    lib = ctypes.CDLL(os.path.join(os.path.dirname(__file__), "parserlib.dll"))

    lib.ScanVolume.restype = ctypes.POINTER(FileEntry)
    lib.ScanVolume.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32)]
    lib.free_entries.argtypes = []
    lib.free_entries.restype = None

    count = ctypes.c_uint32(0)
    entries = lib.ScanVolume(target.encode(), ctypes.byref(count))  # parse mft

    if not entries:
        raise RuntimeError("ScanVolume failed")

    dirs, files = build_tup(entries, count, ns, ticks)

    lib.free_entries()  # free mem

    return dirs, files


def build_tup(entries, count, ns=False, ticks=False):

    dirs = {}
    files = []

    for i in range(count.value):

        e = entries[i]
        name = e.name.decode("utf-8", errors="replace") if e.name else None
        if not name:
            continue

        frn = e.frn
        parent_frn = e.parent_frn
        path = e.dir_path.decode("utf-8", errors="replace") if e.dir_path else ""

        is_dir = e.is_dir
        in_use = e.in_use

        if is_dir:
            if not in_use:
                continue
            dirs[frn] = {
                "parent": parent_frn,
                "name": name,
                "path": path
            }

        else:

            recno = e.record_number
            sequence_num = e.sequence_num
            size = e.size
            hardlinks = e.hard_link_count
            has_ads = bool(e.has_ads)
            attrs = e.file_attribs
            mod_time = e.modification_time
            creation_time = e.creation_time
            mft_mod = e.mft_modification_time
            access_time = e.access_time
            ParentEntryNumber, ParentSequenceNumber = frn_to_entry(parent_frn)

            if ns:
                mod_time = ntfs_to_ns(mod_time)
                creation_time = ntfs_to_ns(creation_time)
                mft_mod = ntfs_to_ns(mft_mod)
                access_time = ntfs_to_ns(access_time)

            elif not ticks:
                mod_time = ntfs_to_us(mod_time)
                creation_time = ntfs_to_us(creation_time)
                mft_mod = ntfs_to_us(mft_mod)
                access_time = ntfs_to_us(access_time)

            files.append((recno, sequence_num, in_use, ParentEntryNumber, ParentSequenceNumber, path, name, size, hardlinks, has_ads, attrs, creation_time, mod_time, mft_mod, access_time))

    return dirs, files
