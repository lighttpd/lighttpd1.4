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
    HANDLE h = CreateFileW(wbuf,0,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
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

#endif /* _WIN32 */
