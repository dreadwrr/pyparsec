#include "parser.h"
#include <stdio.h>

__declspec(dllexport) void free_entries(void) {
    free_processed(NULL);
}

__declspec(dllexport) FileEntry* ScanVolume(const char *drive, uint32_t *count) {

    char volume[16];  // set target drive ie C: S: E:

    if (!drive || strlen(drive) < 2 || drive[1] != ':') {
        *count = 0;
        return NULL;
    }

    snprintf(volume, sizeof(volume), "\\\\.\\%s", drive);
    
    HANDLE h;
    
    unsigned char *buf = NULL;
    bool has_target = false;
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
            fprintf(stderr, "Access denied. Run as administrator.\n");
        } else if (err == ERROR_NOT_READY) {
            fprintf(stderr, "Drive not ready.\n");
        } else if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
            fprintf(stderr, "Invalid drive %s\n", volume); 
        } else {
            fprintf(stderr, "Failed to open %s (error %lu)\n", volume, err);
        }

        goto cleanup;
    }

    BootSector bootsector;
    Read(h, &bootsector, 0, sizeof(bootsector));
   
    /* verify drive */
    if (bootsector.bootSignature != 0xAA55) {
        fprintf(stderr, "Invalid boot sector signature\n");
        goto cleanup;
    }
    if (memcmp(bootsector.name, "NTFS    ", 8) != 0) {
        fprintf(stderr, "Not an NTFS volume\n");
        goto cleanup;
    }

    uint32_t record_size = GetFileRecordSize(&bootsector);
    
    uint64_t bytesPerCluster = (uint64_t)bootsector.bytesPerSector * bootsector.sectorsPerCluster;

    uint64_t mftOffset = bootsector.mftStart * bytesPerCluster;

    buf = malloc(record_size);
    if (!buf) {
        fprintf(stderr, "malloc failed\n");
        goto cleanup;
    }

    // record 0
    Read(h, buf, mftOffset, record_size);  

    hrec = (FILE_RECORD_HEADER *)buf;

    if (!apply_usa(buf, bootsector.bytesPerSector)) {
        fprintf(stderr, "USA fixup failed\n");
        goto cleanup;
    }

    if (memcmp(hrec->signature, "FILE", 4) != 0) {
        fprintf(stderr, "Invalid MFT record signature (expected FILE)\n");
        goto cleanup;
    } // } else {
        // success
    // }

    uint64_t record_count = ParseAttributes(h, buf, record_size, hrec, bytesPerCluster, bootsector.bytesPerSector, has_target);
    if (!record_count) {
        goto cleanup;
    }

    /* check extension records for over flows ie name missing <-- this ensures all dirs can be built */
    for (int i = 0; i < ext_count; i++) {
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

    char path[MAX_PATH];

    // tack on hardlinks to the end of entries
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

    // now free some memory
    if (links) {
        for (uint32_t i = 0; i < link_count; i++) {
            free(links[i].name);
        }
        free(links);
        links = NULL;
        link_count = 0;
        link_capacity = 0;
    }

    for (uint32_t i = 0; i < max_count + 1; i++) {
        // if (!entries[i].in_use)
            // continue;
        if (!entries[i].name)
            continue;
        BuildPath(i, entries[i].name, entries[i].name_len, path, sizeof(path));
    }
    
    free(buf);
    CloseHandle(h);
    *count = max_count + 1;
    return entries;

    cleanup:
        free_processed(buf);

        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
        }
        *count = 0;
        return NULL;
}
