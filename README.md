![alt text](https://raw.githubusercontent.com/dreadwrr/pyparsec/main/wlv.png)

listed on pypi https://pypi.org/project/mftparser/1.6.0/

A Python extension for parsing the MFT on Windows 10 / Windows 11. Returns a list of tuples for all active entries on the volume. This can be used to find new or modified files efficiently as its not necessary to walk the file system.
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
## results = mftparser.ScanVolume("C:", only_active=True, microseconds=False) <br><br>
> returns tuple with 18 fields per entry

recno, sequence_num, parent_recno, parent_sequence, in_use, path, name, size, hardlinks, is_dir, is_hardlink, has_ads, file_attribs, mod_time, creation_time, mft_mod, access_time, usn = results

or

( <br>
    recno, sequence_num, parent_recno, parent_sequence, <br>
    in_use, path, name, size, hardlinks, <br>
    is_dir, is_hardlink, has_ads, file_attribs, <br>
    mod_time, creation_time, mft_mod, access_time, usn <br>
) = results

## mftparser.ntfs_to_us(ts)
> ntfs ticks to epoch microseconds

## mftparser.ntfs_to_ns(ts)
> ntfs ticks to epoch nanoseconds

## recno, seq = mftparser.frn_to_entry(frn)
> file reference number to record number and sequence

## frn = mftparser.entry_to_frn(recno, seq)
> record number and sequence to a file reference number

# Example
print(len(results))
for entry in results:
    if is_dir:
        continue
    ...    
