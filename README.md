![alt text](https://raw.githubusercontent.com/dreadwrr/pyparsec/main/wlv.png)

pypi https://pypi.org/project/mftparser/1.0.0/

A Python extension for parsing the MFT on Windows 10 / Windows 11.
Returns a list of tuples for all active entries on the volume.
Requires administrator privileges.

open to requests or contributors and other use cases. with the initial version things are looking good

## Install
pip install mftparser

## Parameters
- `drive` — drive letter e.g. `"C:"` (default `"C:"`)
- `only_active` — if `False`,  return all entries (default `True`)
- `microseconds` — if `True`, return timestamps as epoch microseconds (default `False`, returns NTFS ticks)
- `cutoff` — takes timestamp format `"2026-05-10T07:33:12"` or `"2026-05-10 07:33:12"` in system time. return entries only from that time onward

# Functions
## mftparser.ScanVolume("C:", only_active=True, microseconds=False) <br><br>
 
## mftparser.ntfs_to_us(ts)
> ntfs ticks to epoch microseconds

## mftparser.ntfs_to_ns(ts)
> ntfs ticks to epoch nanoseconds

## recno, seq = mftparser.frn_to_entry(frn)
> file reference number to record number and sequence

## frn = mftparser.entry_to_frn(recno, seq)
> record number and sequence to a file reference number
