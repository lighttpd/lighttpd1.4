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
#include <winioctl.h>
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
    /* do not omit trailing '/' for slash root ("/") or drive root ("C:/") */
    /* This is not exhaustive, because Windows path handling is exhausting.
     * Not handled: \??\UNC\<server\share>\ \GLOBAL??\UNC\<server\share>\
     *              \??\C:\ \\<share>\C$\ \\.\Volume{...}\ ... and more ...
     * => If the result is _WIN32 stat() fail, then that is "failing closed" */
    int final_slash = (path[len-1] == '/' || path[len-1] == '\\')
                   && len > 1                          /* slash root ("/")   */
                   && (len != 3 || path[1] != ':')     /* drive root ("C:/") */
                   && (len != 7 /* drive root w/ local device path specifier */
                       || (path[0] != '/' && path[0] != '\\')     /* //?/C:/ */
                       || (path[1] != '/' && path[1] != '\\')     /* //./C:/ */
                       || (path[2] != '?' && path[2] != '.')
                       || (path[3] != '/' && path[3] != '\\')
                       ||  path[5] != ':');
    int wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                   path, len - final_slash,
                                   wbuf, (sizeof(wbuf)/sizeof(*wbuf))-1);
    if (wlen <= 0) /* 0 indicates error; < 0 should not happen */
        return -1;
    wbuf[wlen] = 0;
    if (-1 == _wstati64(wbuf, (struct _stati64 *)st))
        return -1;
    /* must check since stat() w/o trailing '/' above */
    if (final_slash && (st->st_mode & _S_IFMT) != _S_IFDIR) { /* S_ISDIR() */
        errno = ENOTDIR;
        return -1;
    }
    return 0;
}

// Custom reparse data buffer structure to avoid dependency on WDK/winnt.h differences
typedef struct {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG  Flags;
            WCHAR  PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR  PathBuffer[1];
        } MountPointReparseBuffer;
    } u;
} fs_win32_reparse_data_buffer_t;

int fs_win32_readlinkUTF8 (const char *path, char *result, size_t rsz)
{
    WCHAR wbuf[4096];
    int wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1,
                                   wbuf, sizeof(wbuf)/sizeof(*wbuf));
    if (0 == wlen) {
        errno = (GetLastError() == ERROR_INSUFFICIENT_BUFFER) ? ENOSPC : EINVAL;
        return -1;
    }

    HANDLE h = CreateFileW(wbuf, 0, 0, 0, OPEN_EXISTING,
                           FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, 0);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        errno = (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) ? ENOENT : EINVAL;
        return -1;
    }

    union {
        fs_win32_reparse_data_buffer_t rdb;
        BYTE dummy[16384]; /* MAXIMUM_REPARSE_DATA_BUFFER_SIZE */
    } u;
    DWORD bytes_returned = 0;
    if (!DeviceIoControl(h, FSCTL_GET_REPARSE_POINT, NULL, 0, &u.rdb, sizeof(u.dummy), &bytes_returned, NULL)) {
        CloseHandle(h);
        errno = EINVAL;
        return -1;
    }
    CloseHandle(h);

    const WCHAR *target_path = NULL;
    int target_len = 0;

    /* Windows SDK definitions if not present */
    #ifndef IO_REPARSE_TAG_SYMLINK
    #define IO_REPARSE_TAG_SYMLINK 0xA000000C
    #endif
    #ifndef IO_REPARSE_TAG_MOUNT_POINT
    #define IO_REPARSE_TAG_MOUNT_POINT 0xA0000003
    #endif

    if (u.rdb.ReparseTag == IO_REPARSE_TAG_SYMLINK) {
        int printOffset = u.rdb.u.SymbolicLinkReparseBuffer.PrintNameOffset / sizeof(WCHAR);
        int printLen = u.rdb.u.SymbolicLinkReparseBuffer.PrintNameLength / sizeof(WCHAR);
        int subOffset = u.rdb.u.SymbolicLinkReparseBuffer.SubstituteNameOffset / sizeof(WCHAR);
        int subLen = u.rdb.u.SymbolicLinkReparseBuffer.SubstituteNameLength / sizeof(WCHAR);

        if (printLen > 0) {
            target_path = &u.rdb.u.SymbolicLinkReparseBuffer.PathBuffer[printOffset];
            target_len = printLen;
        } else if (subLen > 0) {
            target_path = &u.rdb.u.SymbolicLinkReparseBuffer.PathBuffer[subOffset];
            target_len = subLen;
            if (target_len >= 4 && target_path[0] == L'\\' && target_path[1] == L'?' && target_path[2] == L'?' && target_path[3] == L'\\') {
                target_path += 4;
                target_len -= 4;
            }
        }
    } else if (u.rdb.ReparseTag == IO_REPARSE_TAG_MOUNT_POINT) {
        int printOffset = u.rdb.u.MountPointReparseBuffer.PrintNameOffset / sizeof(WCHAR);
        int printLen = u.rdb.u.MountPointReparseBuffer.PrintNameLength / sizeof(WCHAR);
        int subOffset = u.rdb.u.MountPointReparseBuffer.SubstituteNameOffset / sizeof(WCHAR);
        int subLen = u.rdb.u.MountPointReparseBuffer.SubstituteNameLength / sizeof(WCHAR);

        if (printLen > 0) {
            target_path = &u.rdb.u.MountPointReparseBuffer.PathBuffer[printOffset];
            target_len = printLen;
        } else if (subLen > 0) {
            target_path = &u.rdb.u.MountPointReparseBuffer.PathBuffer[subOffset];
            target_len = subLen;
            if (target_len >= 4 && target_path[0] == L'\\' && target_path[1] == L'?' && target_path[2] == L'?' && target_path[3] == L'\\') {
                target_path += 4;
                target_len -= 4;
            }
        }
    } else {
        errno = EINVAL;
        return -1;
    }

    if (target_path == NULL || target_len <= 0) {
        errno = EINVAL;
        return -1;
    }

    if (rsz == 0) {
        errno = ENOSPC;
        return -1;
    }

    int mlen = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, target_path, target_len, result, rsz - 1, NULL, NULL);
    if (mlen <= 0) {
        errno = (GetLastError() == ERROR_INSUFFICIENT_BUFFER) ? ENOSPC : EINVAL;
        return -1;
    }
    result[mlen] = '\0';

    for (int i = 0; i < mlen; i++) {
        if (result[i] == '\\') {
            result[i] = '/';
        }
    }
    return mlen;
}

#endif /* _WIN32 */
