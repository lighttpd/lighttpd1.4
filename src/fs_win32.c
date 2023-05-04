/*
 * fs_win32 - filesystem _WIN32 API wrapper
 *
 * Copyright(c) 2023 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"

#ifdef _WIN32

#include "fs_win32.h"

/* MS filesystem API does not support UTF-8?  WTH?  write our own; not hard */

#include <sys/types.h>
#include <sys/stat.h>
#include <direct.h>
#include <io.h>

#include <windows.h> /*(otherwise get No Target Architecture error)*/
#include <stringapiset.h>
#include <errno.h>

int fs_win32_openUTF8 (const char *path, int oflag, int pmode)
{
    WCHAR wbuf[4096];
    int wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1,
                                   wbuf, sizeof(wbuf)/sizeof(*wbuf));
    return wlen > 0 ? _wopen(wbuf, oflag, pmode) : -1;
}

int fs_win32_mkdirUTF8 (const char *path, mode_t mode)
{
    UNUSED(mode);
    WCHAR wbuf[4096];
    int wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1,
                                   wbuf, sizeof(wbuf)/sizeof(*wbuf));
    return wlen > 0 ? _wmkdir(wbuf) : -1;
}

int fs_win32_stati64UTF8 (const char *path, struct fs_win32_stati64UTF8 *st)
{
    WCHAR wbuf[4096];
    size_t len = strlen(path);
    if (0 == len) {
        errno = EINVAL;
        return -1;
    }
    /* omit trailing '/' (if present) or else _WIN32 stat() fails */
    int final_slash = (path[len-1] == '/' || path[len-1] == '\\');
    int wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                   path, len - final_slash,
                                   wbuf, (sizeof(wbuf)/sizeof(*wbuf))-1);
    if (wlen <= 0) /* 0 indicates error; < 0 should not happen */
        return -1;
    wbuf[wlen] = 0;
    if (-1 == _wstati64(wbuf, (struct _stati64 *)st))
        return -1;
    /* must check since stat() w/o trailing '/' above */
    if (final_slash && (st->st_mode & _S_IFMT) == _S_IFREG) { /* S_ISREG() */
        errno = ENOTDIR;
        return -1;
    }
    return 0;
}

#endif /* _WIN32 */
