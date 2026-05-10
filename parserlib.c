#define Py_LIMITED_API 0x03090000
#include <Python.h>
#include "parsec.h"
#include <stdio.h>

static void clean_up(HANDLE h, unsigned char *buf) {
    free_processed(buf);
    if (h != INVALID_HANDLE_VALUE)
        CloseHandle(h);
}

static PyObject *ScanVolume(PyObject * self, PyObject * args, PyObject *kwargs) {

    static char *kwlist[] = {"drive", "only_active", "microseconds", "cutoff", NULL};
    const char *error_msg = NULL;
    char error_buf[128];

    char drive_buf[3];
    char arg_buf[64];
    char *t;

    char volume[16];  // set target drive ie C: S: E:
    
    const char *drive = NULL;
    int in_use_arg = 1;  // default kwarg value true
    int epoch_us_arg = 0;  // default kwarg value false
    const char *cutoff_arg = NULL;

    bool deleted = false;
    bool epoch_us = false;
    uint64_t cutoff_time = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|spps", kwlist, &drive, &in_use_arg, &epoch_us_arg, &cutoff_arg)) {
        PyErr_SetString(PyExc_RuntimeError, "failed to parse args");
        return NULL;
    }
    if (!drive) {
        drive = "C:";
        
    } else {

        if (!isalpha((unsigned char) drive[0]) || strlen(drive) < 2 || drive[1] != ':') {
            PyErr_Format(PyExc_RuntimeError, "invalid drive: %s", drive);
            return NULL;
        }

        drive_buf[0] = drive[0];
        drive_buf[1] = ':';
        drive_buf[2] = '\0';

        drive = drive_buf;
    }

    // deleted is false (default). show only in use. saves time later iterating in python. has no effect on parsing speed
    if (!in_use_arg)
        deleted = true;  // user passed false show all

    // any pre-filters

    // default is ntfs ticks
    if (epoch_us_arg)
        epoch_us = true;

    if (cutoff_arg) {
        strncpy(arg_buf, cutoff_arg, sizeof(arg_buf) - 1);
        arg_buf[sizeof(arg_buf) - 1] = '\0';
        t = strchr( arg_buf, 'T');
        if (t) {
            *t = ' ';
        }
        cutoff_time = ParseDatetimeToNtfs(arg_buf);
        if (cutoff_time == 0) {
            PyErr_SetString(PyExc_ValueError, "Invalid datetime format 2026-03-19T10:13:18 or \"2026-03-19 10:13:18\" \n");
            return NULL;
        }
    }
    // end any pre-filters

    snprintf(volume, sizeof(volume), "\\\\.\\%s", drive);
    HANDLE h;
    
    unsigned char *buf = NULL;

    FILE_RECORD_HEADER *hrec;

    h = CreateFileA(
        volume,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            error_msg = "Access denied. Run as administrator.\n";
        } else if (err == ERROR_NOT_READY) {
            error_msg = "Drive not ready.\n";
        } else if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
            snprintf(error_buf, sizeof(error_buf), "Invalid drive %s\n", volume);
            error_msg = error_buf;
        } else {
            snprintf(error_buf, sizeof(error_buf), "Failed to open %s (error %lu)\n", volume, (unsigned long)err);
            error_msg = error_buf;
        }
        clean_up(h, buf);
        PyErr_SetString(PyExc_RuntimeError, error_msg);
        return NULL;
    }

    BootSector bootsector;
    Read(h, &bootsector, 0, sizeof(bootsector));
   
    /* verify drive */
    if (bootsector.bootSignature != 0xAA55) {
        clean_up(h, buf);
        PyErr_SetString(PyExc_RuntimeError, "Invalid boot sector signature\n");
        return NULL;
    }
    if (memcmp(bootsector.name, "NTFS    ", 8) != 0) {
        clean_up(h, buf);
        PyErr_SetString(PyExc_RuntimeError, "Not an NTFS volume\n");
        return NULL;
    }

    uint32_t record_size = GetFileRecordSize(&bootsector);
    uint64_t bytesPerCluster = (uint64_t)bootsector.bytesPerSector * bootsector.sectorsPerCluster;
    uint64_t mftOffset = bootsector.mftStart * bytesPerCluster;

    buf = malloc(record_size);
    if (!buf) {
        clean_up(h, buf);
        PyErr_SetString(PyExc_RuntimeError, "malloc failed\n");
        return NULL;
    }

    // record 0
    Read(h, buf, mftOffset, record_size);

    hrec = (FILE_RECORD_HEADER *)buf;

    if (!apply_usa(buf, bootsector.bytesPerSector)) {
        clean_up(h, buf);
        PyErr_SetString(PyExc_RuntimeError, "USA fixup failed\n");
        return NULL;
    }

    if (memcmp(hrec->signature, "FILE", 4) != 0) {
        clean_up(h, buf);
        PyErr_SetString(PyExc_RuntimeError, "Invalid MFT record signature (expected FILE)\n");
        return NULL;
    } // } else {
        // success
    // }
    
    uint64_t record_count = ParseAttributes(h, buf, record_size, hrec, bytesPerCluster, bootsector.bytesPerSector, deleted, false);
    if (!record_count) {
        error_msg = "no record count failed to parse.\n";
    }

    CloseHandle(h);
    if (error_msg) {
        free_processed(buf);
        PyErr_SetString(PyExc_RuntimeError, error_msg);
        return NULL;
    }

    /* check extension records for over flows ie name missing <-- this ensures all dirs can be built */
    for (uint32_t i = 0; i < ext_count; i++) {
        uint32_t b = ext[i].base_recno;
        // see if its missing
        if (entries[b].in_use && (entries[b].name == NULL || entries[b].name[0] == '\0') && entries[b].frn == ext[i].frn) {
            // write its name windows posix or windows&dos 
            free(entries[b].name);
            entries[b].name = _strdup(ext[i].name);
            entries[b].name_len = ext[i].name_len;
            entries[b].parent_frn = ext[i].parent_frn;
        }
    }

    // tack on hardlinks to end of entries
    EnsureEntryCapacity(entry_capacity + link_count);
    for (uint32_t i = 0; i < link_count; i++) {
        uint32_t recno = links[i].recno;
        FileEntry *dst = &entries[entry_count++];
        *dst = entries[recno];
        dst->parent_frn = links[i].parent_frn;
        dst->name       = _strdup(links[i].name);
        dst->name_len   = links[i].name_len;
        max_count++;
    }

    // free some memory
    if (links) {
        for (uint32_t i = 0; i < link_count; i++) {
            free(links[i].name);
        }
        free(links);
        links = NULL;
        link_count = 0;
        link_capacity = 0;
    }

    // finally make list

    char path[MAX_PATH];
    uint64_t parent_recno = 0;
    uint16_t parent_seq = 0;
    uint64_t mod_time = 0;
    uint64_t c_time = 0;
    uint64_t mft_mod = 0;
    uint64_t a_time = 0;

    PyObject *result = NULL;
    
    // result = PyList_New(max_count + 1);  // if prealloc
    result = PyList_New(0);
    if (!result) {
        PyErr_SetString(PyExc_RuntimeError, "failed at start of converting results");
        return NULL;
    }

    for (uint32_t i = 0; i < max_count + 1; i++) {

        FileEntry *e = &entries[i];

        // if (!e->name) {  // if prealloc
            // PyList_SetItem(result, i, Py_NewRef(Py_None));
            // continue;
        // }
        if (!e->name)
            continue;

        if (!deleted && !e->in_use)
            continue;

        if (cutoff_time > 0 && e->modification_time < cutoff_time && e->creation_time < cutoff_time)
            continue;
 
        // PyObject *tuple = PyTuple_New(16);  // if prealloc
        // if (!tuple) {
            // Py_DECREF(result);
            // free_processed(buf);
            // PyErr_SetString(PyExc_RuntimeError, "failed while converting results");
            // return NULL;
        // }
        PyObject *tuple = PyTuple_New(16);
        if (!tuple) {
            Py_DECREF(result);
            PyErr_SetString(PyExc_RuntimeError, "failed while converting results");
            return NULL;
        }

        BuildPath(i, entries[i].name, entries[i].name_len, path, sizeof(path));

        parent_recno = e->parent_frn & FRN_RECORD_MASK;
        parent_seq = (uint16_t)(e->parent_frn >> 48);

        PyTuple_SetItem(tuple, 0,
            PyLong_FromUnsignedLong(e->record_number));
        PyTuple_SetItem(tuple, 1,
            PyLong_FromUnsignedLong(e->sequence_num));
        PyTuple_SetItem(tuple, 2,
            PyLong_FromUnsignedLongLong(parent_recno));
        PyTuple_SetItem(tuple, 3,
            PyLong_FromUnsignedLong(parent_seq));
        PyTuple_SetItem(tuple, 4,
            PyBool_FromLong(e->in_use ? 1 : 0));
        PyTuple_SetItem(tuple, 5,
            PyUnicode_FromString(e->dir_path ? e->dir_path : ""));
        PyTuple_SetItem(tuple, 6,
            PyUnicode_FromString(e->name ? e->name : ""));
        PyTuple_SetItem(tuple, 7,
            PyLong_FromUnsignedLongLong(e->size));
        PyTuple_SetItem(tuple, 8,
            PyLong_FromUnsignedLong(e->hard_link_count));
        PyTuple_SetItem(tuple, 9,
            PyBool_FromLong(e->is_dir ? 1 : 0));
        PyTuple_SetItem(tuple, 10,
            PyBool_FromLong(e->has_ads ? 1 : 0));
        PyTuple_SetItem(tuple, 11,
            PyLong_FromUnsignedLong(e->file_attribs));

        mod_time = epoch_us ? ntfs_to_epoch_us(e->modification_time) : e->modification_time;
        c_time   = epoch_us ? ntfs_to_epoch_us(e->creation_time) : e->creation_time;
        mft_mod  = epoch_us ? ntfs_to_epoch_us(e->mft_modification_time) : e->mft_modification_time;
        a_time   = epoch_us ? ntfs_to_epoch_us(e->access_time) : e->access_time;

        PyTuple_SetItem(tuple, 12, PyLong_FromUnsignedLongLong(mod_time));
        PyTuple_SetItem(tuple, 13, PyLong_FromUnsignedLongLong(c_time));
        PyTuple_SetItem(tuple, 14, PyLong_FromUnsignedLongLong(mft_mod));
        PyTuple_SetItem(tuple, 15, PyLong_FromUnsignedLongLong(a_time));

        // PyList_SetItem(result, i, tuple);  // if prealloc
        if (PyList_Append(result, tuple) < 0) {
            Py_DECREF(tuple);
            Py_DECREF(result);
            free_processed(buf);
            PyErr_SetString(PyExc_RuntimeError, "failed to convert results");
            return NULL;
        }

        Py_DECREF(tuple);  // comment out if prealloc
    }

    free_processed(buf);

    return result;
}

static PyMethodDef module_methods[] = {
    {"ScanVolume", (PyCFunction)ScanVolume, METH_VARARGS | METH_KEYWORDS,
    "parse the MFT and return a list of tuples."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef mftparser = {
    PyModuleDef_HEAD_INIT,
    "mftparser",
    NULL,
    -1,
    module_methods
};

PyMODINIT_FUNC
PyInit_mftparser(void) {
    return PyModule_Create(&mftparser);
}
