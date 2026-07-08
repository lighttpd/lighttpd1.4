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
#include <io.h>

#include <windows.h> /*(otherwise get No Target Architecture error)*/
#include <stringapiset.h>
#include <errno.h>

#include "sys-stat.h" /*(for _S_IFLNK; include after <...> headers)*/

#ifndef IO_REPARSE_TAG_SYMLINK
#define IO_REPARSE_TAG_SYMLINK          0xA000000C
#endif
#ifndef IO_REPARSE_TAG_LX_SYMLINK
#define IO_REPARSE_TAG_LX_SYMLINK       0xA000001D
#endif

#define IsReparseTagSymlink(tag) \
    ((tag) == IO_REPARSE_TAG_SYMLINK || \
     (tag) == IO_REPARSE_TAG_LX_SYMLINK)

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
                           FILE_FLAG_BACKUP_SEMANTICS, 0);
    DWORD rd = (h != INVALID_HANDLE_VALUE) /*(reuse wbuf for result)*/
      ? GetFinalPathNameByHandleW(h, wbuf, sizeof(wbuf)/sizeof(*wbuf),
                                  FILE_NAME_NORMALIZED | VOLUME_NAME_NT)
      : 0;
    CloseHandle(h);
    if (0 == rd) {
        errno = (GetLastError() == ERROR_PATH_NOT_FOUND) ? ENOENT : EINVAL;
        return -1;
    }
    if (rd >= sizeof(wbuf)/sizeof(*wbuf) || 0 == rsz) {
        errno = ENOSPC;
        return -1;
    }
    int mlen =
     #if 0 /*(???: should we strip "\\?\" from result?)*/
      (StrCmpNW(wbuf, L"\\\\?\\", 4) == 0)
      ? WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                            wbuf+4, rd-4, result, rsz-1, NULL, NULL);
      :
     #endif
        WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                            wbuf, rd, result, rsz-1, NULL, NULL);
    if (0 == mlen) {
        errno = (GetLastError() == ERROR_INSUFFICIENT_BUFFER) ? ENOSPC : EINVAL;
        return -1;
    }
    /*(???: should we translate '\\' to '/' in result?)*/
    result[mlen] = '\0';
    return mlen;
}

int fs_win32_lstati64UTF8 (const char *path, struct fs_win32_stati64UTF8 *st)
{
    WCHAR wbuf[4096];
    size_t len = strlen(path);
    if (0 == len) {
        errno = EINVAL;
        return -1;
    }
    /* omit trailing '/' (if present) or else _WIN32 stat() fails */
    /* do not omit for drive root (e.g. "C:/") or single slash root (e.g. "/") */
    int final_slash = 0;
    if (len > 1 && (path[len-1] == '/' || path[len-1] == '\\')) {
        if (len != 3 || path[1] != ':') {
            final_slash = 1;
        }
    }
    int wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                   path, len - final_slash,
                                   wbuf, (sizeof(wbuf)/sizeof(*wbuf))-1);
    if (wlen <= 0)
        return -1;
    wbuf[wlen] = 0;

    DWORD attr = GetFileAttributesW(wbuf);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        return _wstati64(wbuf, (struct _stati64 *)st);
    }

    if (!(attr & FILE_ATTRIBUTE_REPARSE_POINT)) {
        int rc = _wstati64(wbuf, (struct _stati64 *)st);
        if (rc == 0 && final_slash && (st->st_mode & _S_IFMT) != _S_IFDIR) {
            errno = ENOTDIR;
            return -1;
        }
        return rc;
    }

    /* If a final slash was specified (e.g. "path/"), then it refers to a directory.
     * On POSIX/Linux, lstat("symlink/") is equivalent to stat("symlink/"), meaning
     * it follows the symlink and validates it is a directory. */
    if (final_slash) {
        int rc = _wstati64(wbuf, (struct _stati64 *)st);
        if (rc == 0 && (st->st_mode & _S_IFMT) != _S_IFDIR) {
            errno = ENOTDIR;
            return -1;
        }
        return rc;
    }

    HANDLE h = CreateFileW(wbuf, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        return _wstati64(wbuf, (struct _stati64 *)st);
    }

    FILE_ATTRIBUTE_TAG_INFO fati;
    if (!GetFileInformationByHandleEx(h, FileAttributeTagInfo, &fati, sizeof(fati))) {
        CloseHandle(h);
        return _wstati64(wbuf, (struct _stati64 *)st);
    }

    if (!IsReparseTagSymlink(fati.ReparseTag)) {
        CloseHandle(h);
        int rc = _wstati64(wbuf, (struct _stati64 *)st);
        if (rc == 0 && final_slash && (st->st_mode & _S_IFMT) != _S_IFDIR) {
            errno = ENOTDIR;
            return -1;
        }
        return rc;
    }

    BY_HANDLE_FILE_INFORMATION bhfi;
    if (!GetFileInformationByHandle(h, &bhfi)) {
        CloseHandle(h);
        return _wstati64(wbuf, (struct _stati64 *)st);
    }
    CloseHandle(h);

    memset(st, 0, sizeof(*st));
    st->st_dev = bhfi.dwVolumeSerialNumber;
    st->st_ino = (unsigned short)bhfi.nFileIndexLow;
    st->st_nlink = (short)bhfi.nNumberOfLinks;
    st->st_size = ((__int64)bhfi.nFileSizeHigh << 32) | bhfi.nFileSizeLow;
    st->st_rdev = bhfi.dwVolumeSerialNumber;

    ULARGE_INTEGER ull;
    ull.LowPart = bhfi.ftLastAccessTime.dwLowDateTime;
    ull.HighPart = bhfi.ftLastAccessTime.dwHighDateTime;
    st->st_atime = (__time64_t)((ull.QuadPart - 116444736000000000ULL) / 10000000ULL);

    ull.LowPart = bhfi.ftLastWriteTime.dwLowDateTime;
    ull.HighPart = bhfi.ftLastWriteTime.dwHighDateTime;
    st->st_mtime = (__time64_t)((ull.QuadPart - 116444736000000000ULL) / 10000000ULL);

    ull.LowPart = bhfi.ftCreationTime.dwLowDateTime;
    ull.HighPart = bhfi.ftCreationTime.dwHighDateTime;
    st->st_ctime = (__time64_t)((ull.QuadPart - 116444736000000000ULL) / 10000000ULL);

    st->st_mode = _S_IFLNK;
    if (!(bhfi.dwFileAttributes & FILE_ATTRIBUTE_READONLY)) {
        st->st_mode |= _S_IWRITE;
    }
    st->st_mode |= _S_IREAD;

    return 0;
}

#endif /* _WIN32 */
