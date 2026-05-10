05/10/20206 <br><br>

Note originally made using ctypes and .dll. but moved to python c api so have to finish testing before releasing <br>

Purpose and initial concept was for file searching use. so accesses by volume if needing to read a mft dump there are other apis
available https://github.com/omerbenamram/mft. or use the CLI version of mft parser.

Can be expanded to include FILENAME timestamps but SI is used which is more reliable. Open to any suggestions to improve or support
use cases

Will list compile steps for the .pyd <br><br>

# mftparser
A Python extension for parsing the MFT on Windows 10 / Windows 11. <br>
Returns a list of tuples for all active records <br>
Requires administrator privileges <br>

## Install
pip install mftparser

## Parameters
- `drive` — drive letter e.g. `"C:"` (default `"C:"`)
- `only_active` — if `False`,  if set to False return all entries (default `True`, only in use entries)
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

# NTFS ticks to epoch microseconds
mftparser.ntfs_to_us(ts)

# NTFS ticks to epoch nanoseconds
mftparser.ntfs_to_ns(ts)

# file reference number to record number and sequence
recno, seq = mftparser.frn_to_entry(frn)

# record number and sequence to file reference number
frn = mftparser.entry_to_frn(recno, seq)
