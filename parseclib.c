#define Py_LIMITED_API 0x03090000
#include <Python.h>
#include "parsec.h"
#include <stdio.h>

static void clean_up(HANDLE h, unsigned char *buf) {
    free_processed(buf);
    if (h != INVALID_HANDLE_VALUE)
        CloseHandle(h);
}

static PyObject *make_tuple(FileEntry *e, const char *name, uint64_t parent_frn, const char *path, bool is_hardlink,
                            uint64_t mod_time, uint64_t c_time, uint64_t mft_mod, uint64_t a_time) {

    // PyObject *tuple = PyTuple_New(16);  // if prealloc
    // if (!tuple) {
        // Py_DECREF(result);
        // free_processed(buf);
        // PyErr_SetString(PyExc_RuntimeError, "failed while converting results");
        // return NULL;
    // }
    PyObject *tuple = PyTuple_New(18);
    if (!tuple)
        return NULL;

    uint64_t parent_recno = parent_frn & FRN_RECORD_MASK;
    uint16_t parent_seq = (uint16_t)(parent_frn >> 48);

    PyTuple_SetItem(tuple, 0, PyLong_FromUnsignedLong(e->record_number));
    PyTuple_SetItem(tuple, 1, PyLong_FromUnsignedLong(e->sequence_num));
    PyTuple_SetItem(tuple, 2, PyLong_FromUnsignedLongLong(parent_recno));
    PyTuple_SetItem(tuple, 3, PyLong_FromUnsignedLong(parent_seq));
    PyTuple_SetItem(tuple, 4, PyBool_FromLong(e->in_use ? 1 : 0));
    PyTuple_SetItem(tuple, 5, PyUnicode_FromString(path ? path : ""));  // e->dir_path
    PyTuple_SetItem(tuple, 6, PyUnicode_FromString(name ? name : ""));
    PyTuple_SetItem(tuple, 7, PyLong_FromUnsignedLongLong(e->size));
    PyTuple_SetItem(tuple, 8, PyLong_FromUnsignedLong(e->hard_link_count));
    PyTuple_SetItem(tuple, 9, PyBool_FromLong(e->is_dir ? 1 : 0));
    PyTuple_SetItem(tuple, 10, PyBool_FromLong(is_hardlink ? 1 : 0));
    PyTuple_SetItem(tuple, 11, PyBool_FromLong(e->has_ads ? 1 : 0));
    PyTuple_SetItem(tuple, 12, PyLong_FromUnsignedLong(e->file_attribs));
    PyTuple_SetItem(tuple, 13, PyLong_FromUnsignedLongLong(mod_time));
    PyTuple_SetItem(tuple, 14, PyLong_FromUnsignedLongLong(c_time));
    PyTuple_SetItem(tuple, 15, PyLong_FromUnsignedLongLong(mft_mod));
    PyTuple_SetItem(tuple, 16, PyLong_FromUnsignedLongLong(a_time));
    PyTuple_SetItem(tuple, 17, PyLong_FromUnsignedLongLong(e->usn));

    return tuple;
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
        if (!get_drive(drive, drive_buf)) {
            PyErr_Format(PyExc_RuntimeError, "invalid drive: %s", drive);
            return NULL;           
        }

        // if (!isalpha((unsigned char) drive[0]) || strlen(drive) < 2 || drive[1] != ':') {
            // PyErr_Format(PyExc_RuntimeError, "invalid drive: %s", drive);
            // return NULL;
        // }

        // drive_buf[0] = drive[0];
        // drive_buf[1] = ':';
        // drive_buf[2] = '\0';

        drive = drive_buf;
    }

    // default is show in use only. saves time later iterating in python but has no effect on parsing speed
    if (!in_use_arg)
        deleted = true;  // user passed false show all

    // any pre-filters

    // default ntfs ticks
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
        PyErr_SetString(PyExc_OSError, error_msg);
        return NULL;
    }

    BootSector bootsector;
    int res;

    res = Read(h, &bootsector, 0, sizeof(bootsector));
    if (res != ERR_OK) {
        clean_up(h, buf);
        PyErr_SetString(PyExc_RuntimeError, error_string(res));
        return NULL;
    }
    
    /* verify drive */
    if (bootsector.bootSignature != 0xAA55) {
        clean_up(h, buf);
        PyErr_SetString(PyExc_RuntimeError, "Invalid boot sector signature");
        return NULL;
    }
    if (memcmp(bootsector.name, "NTFS    ", 8) != 0) {
        clean_up(h, buf);
        PyErr_SetString(PyExc_RuntimeError, "Not an NTFS volume");
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
    res = Read(h, buf, mftOffset, record_size);
    if (res != ERR_OK) {
        clean_up(h, buf);

        PyErr_SetString(PyExc_RuntimeError, error_string(res));
        return NULL;
    }
    
    hrec = (FILE_RECORD_HEADER *)buf;

    if (!apply_usa(buf, bootsector.bytesPerSector)) {
        clean_up(h, buf);
        PyErr_SetString(PyExc_RuntimeError, "USA fixup failed\n");
        return NULL;
    }

    if (memcmp(hrec->signature, "FILE", 4) != 0) {
        clean_up(h, buf);
        PyErr_SetString(PyExc_RuntimeError, "Invalid MFT record signature (expected FILE)");
        return NULL;
    } // } else {
        // success
    // }
    
    res = ParseAttributes(MODE_PARSE, h, NULL, buf, record_size, hrec, bytesPerCluster, bootsector.bytesPerSector, NULL, deleted, false);
    
    if (res != ERR_OK) {
        clean_up(h, buf);

        PyErr_SetString(PyExc_RuntimeError, error_string(res));
        return NULL;
    }

    // are there results to process?
    if (!entry_count) {
        clean_up(h, buf);
        PyErr_SetString(PyExc_RuntimeError, "no records returned failed to parse");  // PyErr_Format(PyExc_RuntimeError, "%s", msg);
        
        return NULL;
    }

    CloseHandle(h);
    h = INVALID_HANDLE_VALUE;

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

    // make list

    char path[MAX_PTH];
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
 
        mod_time = epoch_us ? ntfs_to_epoch_us(e->modification_time) : e->modification_time;
        c_time   = epoch_us ? ntfs_to_epoch_us(e->creation_time) : e->creation_time;
        mft_mod  = epoch_us ? ntfs_to_epoch_us(e->mft_modification_time) : e->mft_modification_time;
        a_time   = epoch_us ? ntfs_to_epoch_us(e->access_time) : e->access_time;
    
        BuildPath(i, e->name, e->name_len, path, sizeof(path));

        PyObject *tuple = make_tuple(e, e->name, e->parent_frn, path, false, mod_time, c_time, mft_mod, a_time);
        if (!tuple) {
            Py_DECREF(result);
            free_processed(buf);
            PyErr_SetString(PyExc_RuntimeError, "failed while converting results");
            return NULL;
        }
        // PyList_SetItem(result, i, tuple);  // if prealloc
        if (PyList_Append(result, tuple) < 0) {
            Py_DECREF(tuple);
            Py_DECREF(result);
            free_processed(buf);
            PyErr_SetString(PyExc_RuntimeError, "failed to convert results");
            return NULL;
        }       
        Py_DECREF(tuple);  // comment out if prealloc

        
        for (uint16_t j = 0; j < e->link_count; j++) {
            
            LinkEntry *lnk = &links[e->link_index + j];
 
            BuildPath(lnk->recno, lnk->name, lnk->name_len, path, sizeof(path));

            tuple = make_tuple(e, lnk->name, lnk->parent_frn, path, true, mod_time, c_time, mft_mod, a_time);
            
            if (!tuple) {
                Py_DECREF(result);
                free_processed(buf);
                PyErr_SetString(PyExc_RuntimeError, "failed while converting results links");
                return NULL;
            }

            if (PyList_Append(result, tuple) < 0) {
                Py_DECREF(tuple);
                Py_DECREF(result);
                free_processed(buf);
                PyErr_SetString(PyExc_RuntimeError, "failed to convert result link");
                return NULL;
            }       
            Py_DECREF(tuple);
        }
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
