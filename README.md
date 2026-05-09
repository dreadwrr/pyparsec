![Alt text](https://raw.githubusercontent.com/dreadwrr/pyparsec/main/VD0ZvNd.png)

# mftparser
A Python extension for parsing the MFT on Windows 10 / Windows 11. <br>
Returns a list of tuples for all active records <br>
if listing all entries check that entry is not None as list is then sparse <br>
Requires administrator privileges <br>

## Install
pip install mftparser

## Parameters
- `drive` — drive letter in format `"C:"` (default `"C:"`)
- `only_active` — if `False`,  return all entries (default `True`)
- `microseconds` — if `True`, return timestamps in epoch microseconds (default `False`, NTFS ticks)

## Usage
```python
import mftparser

results = mftparser.ScanVolume("C:")
for entry in results:
    record_number, seq, in_use, parent_recno, parent_seq, path, name, size, hard_links, is_dir, has_ads, attribs, mod_time, create_time, mft_mod, access_time = entry
    print(path, name)
```

## Functions
mftparser.ScanVolume("C:", only_active=True, microseconds=False) <br><br>
note if only_active is False check that entry is not None as it is sparse

# NTFS ticks to epoch microseconds
mftparser.ntfs_to_us(ts)

# NTFS ticks to epoch nanoseconds
mftparser.ntfs_to_ns(ts)

# file reference number to record number and sequence
recno, seq = mftparser.frn_to_entry(frn)

# record number and sequence to file reference number
frn = mftparser.entry_to_frn(recno, seq)
