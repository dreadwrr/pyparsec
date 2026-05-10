A Python extension for parsing the MFT on Windows 10 / Windows 11.
Returns a list of tuples for all active entries on the volume.
Requires administrator privileges.

## Install
pip install mftparser

## Parameters
- `drive` — drive letter e.g. `"C:"` (default `"C:"`)
- `only_active` — if `False`,  return all entries (default `True`)
- `microseconds` — if `True`, return timestamps as epoch microseconds (default `False`, returns ntfs ticks)
- `cutoff` — takes timestamp format `"2026-05-10T07:33:12"` or `"2026-05-10 07:33:12"` in system time. return entries only from that time onward

# Functions
mftparser.ScanVolume("C:", only_active=True, microseconds=False) <br><br>

## ntfs ticks to epoch microseconds
mftparser.ntfs_to_us(ts)

## ntfs ticks to epoch nanoseconds
mftparser.ntfs_to_ns(ts)

## file reference number to record number and sequence
recno, seq = mftparser.frn_to_entry(frn)

## record number and sequence to a file reference number
frn = mftparser.entry_to_frn(recno, seq)
