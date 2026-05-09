import os
# 05/09/2026 mft parsec wrapper for parsing ntfs MFT
# by Colby Saigeon

TICKS_BTWN_1601_1970 = 11644473600000000
TICKS_BTWN_1601_1970_NS = 11644473600000000000


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
