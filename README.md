# mftparser
A Python extension for parsing the MFT on Windows 10 / Windows 11. <br>
Returns a list of tuples for all entries on the volume. <br>
Requires administrator privileges. <br>

## Install
pip install mftparser

## Usage
```python
import mftparser

results = mftparser.ScanVolume("C:")
for entry in results:
    if entry is None:
        continue
    record_number, seq, in_use, parent_recno, parent_seq, path, name, size, hard_links, is_dir, has_ads, attribs, mod_time, create_time, mft_mod, access_time = entry
    print(path, name)
```

## Utilities

# convert NTFS ticks to epoch microseconds
mftparser.ntfs_to_us(ts)

# convert NTFS ticks to epoch nanoseconds
mftparser.ntfs_to_ns(ts)

# convert a file reference number to record number and sequence
recno, seq = mftparser.frn_to_entry(frn)

# convert record number and sequence to a file reference number
frn = mftparser.entry_to_frn(recno, seq)
