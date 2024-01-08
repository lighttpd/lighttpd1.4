/*
 * sys-dirent.h - <sys/dirent.h> wrapper (selected functions; not complete)
 *
 * Copyright(c) 2021 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#ifndef INCLUDED_SYS_DIRENT_H
#define INCLUDED_SYS_DIRENT_H
#include "first.h"

#include <sys/types.h>
#ifndef _WIN32
#include <dirent.h>
#endif


#ifdef _WIN32

#include <windows.h>
#include <direct.h>
#include <errno.h>
#include <stdlib.h>
#include <stringapiset.h>

/*#include <stdlib.h>*/ /* _MAX_PATH */
/* Windows C Runtime supports path lengths up to 32768 characters in length (_MAX_PATH)
 * https://docs.microsoft.com/en-us/cpp/c-runtime-library/path-field-limits?view=msvc-160
 *
 * Impose a shorter limit (4k) since using stack below (char path[PATH_MAX+1])
 */
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifndef DT_UNKNOWN
#define DT_UNKNOWN 0
#endif
#ifndef DT_FIFO
#define DT_FIFO 1
#endif
#ifndef DT_CHR
#define DT_CHR 2
#endif
#ifndef DT_DIR
#define DT_DIR 4
#endif
#ifndef DT_BLK
#define DT_BLK 6
#endif
#ifndef DT_REG
#define DT_REG 8
#endif
#ifndef DT_LNK
#define DT_LNK 10
#endif
#ifndef DT_SOCK
#define DT_SOCK 12
#endif
#ifndef DT_WHT
#define DT_WHT 14
#endif
#ifndef _DIRENT_HAVE_D_NAMLEN
#define _DIRENT_HAVE_D_NAMLEN 1
#endif
#ifndef _DIRENT_HAVE_D_TYPE
#define _DIRENT_HAVE_D_TYPE 1
#endif
#ifndef DTTOIF
#define DTTOIF(d_type) (((mode_t)(d_type)) << 12)
#endif
/* minimal implementation to walk directory */
struct dirent {
    char *d_name;
    uint8_t d_type;
    uint16_t d_namlen;
};
struct DIR {
    int first;
    int last_error;
    HANDLE hFind;
    struct dirent de;
    WIN32_FIND_DATAW ffd;
    char fnUTF8[260*4+1]; /* <stdio.h> FILENAME_MAX 260 */
};
typedef struct DIR DIR;

static inline int
closedir (DIR * const dirp);
static inline int
closedir (DIR * const dirp)
{
    if (!dirp) {
        errno = EBADF;
        return -1;
    }
    FindClose(dirp->hFind);
    free(dirp);
    return 0;
}

static inline DIR *
opendir (const char *name);
static inline DIR *
opendir (const char *name)
{
    WCHAR wbuf[4096];
    int wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name, -1,
                                   wbuf, (sizeof(wbuf)/sizeof(*wbuf))-2);
    if (wlen < 2) return NULL;
    --wlen;
    if (wbuf[wlen-1] != '/' && wbuf[wlen-1] != '\\') wbuf[wlen++] = '\\';
    wbuf[wlen]   = '*';
    wbuf[wlen+1] = '\0';
    DIR * const dirp = calloc(1, sizeof(DIR));
    if (NULL == dirp) return NULL;
    dirp->first = 1;
    dirp->hFind = FindFirstFileExW(wbuf, FindExInfoBasic, &dirp->ffd,
                                   FindExSearchNameMatch, NULL,
                                   FIND_FIRST_EX_LARGE_FETCH);
    if (INVALID_HANDLE_VALUE == dirp->hFind) {
        if (GetLastError() != ERROR_FILE_NOT_FOUND) {
            free(dirp);
            return NULL;
        }
        dirp->last_error = ERROR_NO_MORE_FILES;
    } /* else dirp->last_error = 0 */
    return dirp;
}

static inline struct dirent *
readdir (DIR * const dirp);
static inline struct dirent *
readdir (DIR * const dirp)
{
    struct dirent * const de = &dirp->de;
    WIN32_FIND_DATAW * const ffd = &dirp->ffd;

    do {
        if (!dirp->first) {
            if (0 == FindNextFileW(dirp->hFind, ffd))
                dirp->last_error = GetLastError();
        }
        else
            dirp->first = 0;

        if (dirp->last_error)
            return NULL;

        const int dsz =
          WideCharToMultiByte(CP_UTF8, 0, ffd->cFileName, -1,
                              dirp->fnUTF8, sizeof(dirp->fnUTF8), NULL, NULL);
        if (dsz > 0 && dsz <= UINT16_MAX) { /*(dsz includes '\0' here)*/
            de->d_namlen = (uint16_t)(dsz-1);
            de->d_name = dirp->fnUTF8;
            if ((ffd->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
                 == FILE_ATTRIBUTE_REPARSE_POINT)
                de->d_type = DT_LNK;
                /* XXX: incomplete; need to check for IO_REPARSE_TAG_SYMLINK */
            else if ((ffd->dwFileAttributes & FILE_ATTRIBUTE_DEVICE)
                     == FILE_ATTRIBUTE_DEVICE)
                de->d_type = DT_CHR;
            else if ((ffd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                     == FILE_ATTRIBUTE_DIRECTORY)
                de->d_type = DT_DIR;
            else
                de->d_type = DT_REG;
        }
        else /*(ignore excessively long names)*/
            de->d_namlen = 0;

    } while (0 == de->d_namlen);

    return de;
}

#endif /* _WIN32 */


#ifndef _D_EXACT_NAMLEN
#ifdef _DIRENT_HAVE_D_NAMLEN
#define _D_EXACT_NAMLEN(d) ((d)->d_namlen)
#else
#define _D_EXACT_NAMLEN(d) (strlen ((d)->d_name))
#endif
#endif


#endif
