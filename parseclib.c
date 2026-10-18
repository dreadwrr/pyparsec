#define Py_LIMITED_API 0x03090000
#include <Python.h>
#include "parsec.h"
#include <direct.h>
#include <stdio.h>
#include <time.h>

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

// added for refactor when adding CreateCsv and DumpMft functions CreateCsv and DumpMft. Taken originally from ScanVolume
static int ValidateMft(const char *volume, HANDLE *h, unsigned char **buf, FILE_RECORD_HEADER **hrec, uint32_t *record_size,
                       uint64_t *bytesPerCluster, uint16_t *bytesPerSector, BootSector *bootsector, bool input) {
    
    const char *error_msg = NULL;
    char error_buf[128];

    *h = CreateFileA(
        volume,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (*h == INVALID_HANDLE_VALUE) {
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

        PyErr_SetString(PyExc_OSError, error_msg);
        return 1;
    }

    uint64_t mftOffset = 0;

    int res;

    // set some values if the input is a drive ie the bootsector
    if (!input) {
        res = Read(*h, bootsector, 0, sizeof(*bootsector));
        if (res != ERR_OK) {
            PyErr_SetString(PyExc_RuntimeError, error_string(res));
            return 1;
        }
        
        /* verify drive */
        if (bootsector->bootSignature != 0xAA55) {
            PyErr_SetString(PyExc_RuntimeError, "Invalid boot sector signature");
            return 1;
        }
        if (memcmp(bootsector->name, "NTFS    ", 8) != 0) {
            PyErr_SetString(PyExc_RuntimeError, "Not an NTFS volume");
            return 1;
        }

        *record_size = GetFileRecordSize(bootsector);  
        *bytesPerSector = bootsector->bytesPerSector;
        *bytesPerCluster = (uint64_t)bootsector->bytesPerSector * bootsector->sectorsPerCluster;
        mftOffset = bootsector->mftStart * (*bytesPerCluster);
    }

    *buf = malloc(*record_size);
    if (!*buf) {
        PyErr_SetString(PyExc_RuntimeError, "malloc failed\n");
        return 1;
    }

    // record 0
    res = Read(*h, *buf, mftOffset, *record_size);
    if (res != ERR_OK) {
        PyErr_SetString(PyExc_RuntimeError, error_string(res));
        return 1;
    }
    
    *hrec = (FILE_RECORD_HEADER *)*buf;

    if (!apply_usa(*buf, *bytesPerSector)) {
        PyErr_SetString(PyExc_RuntimeError, "USA fixup failed\n");
        return 1;
    }

    if (memcmp((*hrec)->signature, "FILE", 4) != 0) {
        PyErr_SetString(PyExc_RuntimeError, "Invalid MFT record signature (expected FILE)");
        return 1;
    }
    
    return 0;
}

static PyObject *ScanVolume(PyObject * self, PyObject * args, PyObject *kwargs) {

    static char *kwlist[] = {"drive", "only_active", "microseconds", "cutoff", NULL};

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
        // PyErr_SetString(PyExc_RuntimeError, "failed to parse args");
        return NULL;
    }

    // this can go in validatemft
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
    BootSector bootsector;

    uint32_t record_size = 1024;
    uint16_t bytesPerSector = 0;
    uint64_t bytesPerCluster = 0;

    int res = ValidateMft(volume, &h, &buf, &hrec, &record_size, &bytesPerCluster, &bytesPerSector, &bootsector, false);

    if (res != ERR_OK) {
        clean_up(h, buf);
        return NULL;
    }
    Py_BEGIN_ALLOW_THREADS
    res = ParseAttributes(MODE_PARSE, h, NULL, buf, record_size, hrec, bytesPerCluster, bytesPerSector, NULL, deleted, false);
    Py_END_ALLOW_THREADS
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

        if (ext[i].size && entries[b].need_size && entries[b].frn == ext[i].frn) {
            entries[b].size = ext[i].size;
            entries[b].need_size = 0;
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

// read mft from drive or mft dump from input. Then it output to csv.
// other parsers dont filter anything out of the csv for lookuping parents ect. This function
// is similar to ScanVolume with differences like having filters only_active ect removed as
// well as other functionality. This along with DumpMft were added after ScanVolume.
static PyObject *CreateCsv(PyObject * self, PyObject * args, PyObject *kwargs) {

    static char *kwlist[] = {"input", "output", "record_size", "bytes_per_sector", NULL};  // "only_active", "microseconds, "cutoff" omitted but can be put in
    const char *error_msg = NULL;
    char error_buf[128];

    char drive_buf[3];

    char volume[16];

    // HANDLE o;
    FILE * o;

    const char *input = NULL;
    const char *output = NULL;  // save or dump mode

    uint32_t record_size;
    uint16_t bytesPerSector;
    unsigned int dump_record_size = 1024;
    unsigned int bytes_per_sector = 512;

    bool is_dump = false;
    bool deleted = true;  // show all records
    bool csv = true;  // output csv which is the alternative output fmt

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|sII", kwlist, &input, &output, &dump_record_size, &bytes_per_sector)) {
        return NULL;
    }
    
    size_t str_len = strlen(input);

    // it is a drive
    if (str_len > 1 && str_len <= 3 &&
        isalpha((unsigned char) input[0]) &&
        input[1] == ':') {
        if (!get_drive(input, drive_buf)) {
            PyErr_Format(PyExc_RuntimeError, "invalid drive: %s", input);
            return NULL;
        }
        input = drive_buf;
        snprintf(volume, sizeof(volume), "\\\\.\\%s", input);
    //  it is a file
    } else {
        is_dump = true;
        
        record_size = (uint32_t)dump_record_size;
        bytesPerSector = (uint16_t)bytes_per_sector;

        if(!is_file(input)) {
            PyErr_Format(PyExc_RuntimeError, "target input not a file: %s", input);
            return NULL;
        }
    }

    char cwd[MAX_PATH];
    char default_output[MAX_PATH];

    if (!output) {
        // use default csv filename
        
        if (_getcwd(cwd, sizeof(cwd)) == NULL) {
            PyErr_SetString(PyExc_OSError, "Failed to get current working directory");
            return NULL;
        }

        char filename[32];
        time_t now = time(NULL);
        struct tm t;

        if (localtime_s(&t, &now) != 0) {
            PyErr_SetString(PyExc_RuntimeError, "Failed to get local time");
            return NULL;
        }

        if (strftime(filename, sizeof(filename), "%Y%m%d%H%M%S_mft.csv", &t) == 0) {
            PyErr_SetString(PyExc_RuntimeError, "Failed to format filename");
            return NULL;
        }

        int len = snprintf(default_output, sizeof(default_output), "%s\\%s", cwd, filename);
        
        if (len < 0 || (size_t)len >= sizeof(default_output)) {
            PyErr_SetString(PyExc_ValueError, "Output path is too long");
            return NULL;
        }

        output = default_output;

    }

    // if the input is a file the default filename might  be the same as the input 
    if (is_dump && _stricmp(input, output) == 0) {
        PyErr_Format(PyExc_RuntimeError, "input: %s cannot be the same as output %s", input, output);
        return NULL;
    }

    // check that the output cant somehow be a drive MFT ie \\\\.\\X:
    if (strlen(output) >= 2 &&
        output[0] == '\\' &&
        output[1] == '\\') {
        PyErr_SetString(PyExc_ValueError, "Output cannot be a device path");
        return NULL;
    }
    // exit if output is in volume $MFT format ie X:\\$MFT
    if (strlen(output) == 7 &&
        output[2] == '\\' &&
        output[7] == '\0' &&
        _stricmp(output + 3, "$MFT") == 0) {
        PyErr_Format(PyExc_ValueError, "volume mft: %s cannot be used for input", output);
        return 1;
    }

    // o = CreateFileA(
        // output,
        // GENERIC_WRITE,
        // FILE_SHARE_READ | FILE_SHARE_WRITE,
        // NULL,
        // CREATE_ALWAYS,
        // FILE_ATTRIBUTE_NORMAL,
        // NULL
    // );
    // if (o == INVALID_HANDLE_VALUE) {

        // snprintf(error_buf, sizeof(error_buf), "Failed to create output file: %s\n", output);
        // error_msg = error_buf;
        // PyErr_SetString(PyExc_OSError, error_msg);
        // return NULL;
    // }
    o = fopen(output, "w");
    if (o == NULL) {
        PyErr_SetFromErrnoWithFilename(PyExc_OSError, output);
        return NULL;
    }

    HANDLE h;
    
    unsigned char *buf = NULL;

    FILE_RECORD_HEADER *hrec;
    BootSector bootsector;

    // uint32_t record_size = 1024;
    // uint16_t bytesPerSector = 512;
    uint64_t bytesPerCluster = 0;
    
    const char *target = is_dump ? input : volume;

    int res = ValidateMft(target, &h, &buf, &hrec, &record_size, &bytesPerCluster, &bytesPerSector, &bootsector, is_dump);

    if (res != ERR_OK) {

        clean_up(h, buf);
        // CloseHandle(o);
        fclose(o);
        return NULL;
    }

    // uint64_t record_count = 0; // diagnostics for stdout
    // res = ParseAttributes(MODE_PARSE, h, NULL, buf, record_size, hrec, bytesPerCluster, bootsector.bytesPerSector, &record_count, deleted, has_target); template

    Py_BEGIN_ALLOW_THREADS
    // drive
    if (!is_dump) {
        res = ParseAttributes(MODE_PARSE, h, NULL, buf, record_size, hrec, bytesPerCluster, bytesPerSector, NULL, false, false);
    // file
    } else {
        res = ParseAttributes(MODE_READ, h, NULL, buf, record_size, hrec, 0, bytesPerSector, NULL, false, false);  // &record_count
    }
    Py_END_ALLOW_THREADS
    if (res != ERR_OK) {
        clean_up(h, buf);
        // CloseHandle(o);
        fclose(o);
        PyErr_SetString(PyExc_RuntimeError, error_string(res));
        return NULL;
    }

    // are there results to process?
    if (!entry_count) {
        clean_up(h, buf);
        // CloseHandle(o);
        fclose(o);
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

        if (ext[i].size && entries[b].need_size && entries[b].frn == ext[i].frn) {
            entries[b].size = ext[i].size;
            entries[b].need_size = 0;
        }
    }

    const char *output_path = output;
    char path[MAX_PTH];

    /* print mft entries for run to csv */
    PrintRuns(o, entries, path, sizeof(path), csv, deleted);

    free_processed(buf);
    // CloseHandle(o);
    fclose(o);
    return PyUnicode_FromString(output_path);
}

// write - mft dump
static PyObject *DumpMft(PyObject * self, PyObject * args, PyObject *kwargs)
{

    static char *kwlist[] = {"drive", "output", NULL};
    const char *error_msg = NULL;
    char error_buf[128];

    char drive_buf[3];

    char volume[16];

    HANDLE o;
    const char *drive = NULL;
    const char *output = NULL;  // save or dump mode

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|ss", kwlist, &drive, &output)) {
        return NULL;
    }

    if (!drive) {
        drive = "C:";
        
    } else {
        if (!get_drive(drive, drive_buf)) {
            PyErr_Format(PyExc_RuntimeError, "invalid drive: %s", drive);
            return NULL;
        }

        drive = drive_buf;
    }

    // Py_BEGIN_ALLOW_THREADS
    // Py_END_ALLOW_THREADS
    if (!output) {
        // in pwd use default filename
        output = "mft.raw";
        // if not having a default filename filename quit
        // PyErr_SetString(PyExc_ValueError, "No output filename provided.\n");
        // PyErr_Format(PyExc_RuntimeError, "invalid drive: %s", drive);
        // return NULL;
    }

    // check that the output cant somehow be a drive MFT ie \\\\.\\X:
    if (strlen(output) >= 2 &&
        output[0] == '\\' &&
        output[1] == '\\') {
        PyErr_SetString(PyExc_ValueError, "Output cannot be a device path");
        return NULL;
    }

    // exit if output is in volume $MFT format ie X:\\$MFT
    if (strlen(output) == 7 &&
        output[2] == '\\' &&
        output[7] == '\0' &&
        _stricmp(output + 3, "$MFT") == 0) {
        PyErr_Format(PyExc_ValueError, "volume mft: %s cannot be used for output", output);
        return NULL;
    }

    o = CreateFileA(
        output,
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (o == INVALID_HANDLE_VALUE) {

        snprintf(error_buf, sizeof(error_buf), "Failed to create output file: %s\n", output);
        error_msg = error_buf;
        PyErr_SetString(PyExc_OSError, error_msg);
        return NULL;
    }

    snprintf(volume, sizeof(volume), "\\\\.\\%s", drive);

    HANDLE h;

    unsigned char *buf = NULL;
        
    FILE_RECORD_HEADER *hrec;
    BootSector bootsector;

    uint32_t record_size = 1024;
    uint16_t bytesPerSector = 0;
    uint64_t bytesPerCluster = 0;

    int res = ValidateMft(volume, &h, &buf, &hrec, &record_size, &bytesPerCluster, &bytesPerSector, &bootsector, false);

    if (res != ERR_OK) {
        clean_up(h, buf);
        CloseHandle(o);
        return NULL;
    }
    Py_BEGIN_ALLOW_THREADS
    res = ParseAttributes(MODE_WRITE, h, o, buf, record_size, hrec, bytesPerCluster, bootsector.bytesPerSector, NULL, false, false);
    Py_END_ALLOW_THREADS
    const char *output_path = output;
    char path[MAX_PTH];

    if (strcmp(output, "mft.raw") == 0) {
        DWORD len = GetFinalPathNameByHandleA(
            o,
            path,
            MAX_PATH,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS
        );

        if (len > 0 && len < MAX_PATH) {
            output_path = path;  // the default filepath in present working directory of calling process
        }
    }

    free_processed(buf);
    CloseHandle(o);
    CloseHandle(h);

    if (res == PARSE_FAIL) {
        PyErr_SetString(PyExc_RuntimeError, "failed while converting results links");
        return NULL;
    }

    return PyUnicode_FromString(output_path);
}

static PyMethodDef module_methods[] = {
    {"ScanVolume", (PyCFunction)ScanVolume, METH_VARARGS | METH_KEYWORDS,
    "parse the MFT and return a list of tuples."},
    {"CreateCsv", (PyCFunction)CreateCsv, METH_VARARGS | METH_KEYWORDS,
    "create csv from saved MFT."},
    {"DumpMft", (PyCFunction)DumpMft, METH_VARARGS | METH_KEYWORDS,
    "dump the MFT for drive."},
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
