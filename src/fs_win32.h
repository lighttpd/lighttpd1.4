/*
 * fs_win32 - filesystem _WIN32 API wrapper
 *
 * Copyright(c) 2023 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#ifndef INCLUDED_FS_WIN32_H
#define INCLUDED_FS_WIN32_H
#include "first.h"

#ifdef _WIN32

#include <sys/types.h>
#include <sys/stat.h>

/* MS filesystem API does not support UTF-8?  WTH?  write our own; not hard */

int fs_win32_openUTF8 (const char *path, int oflag, int pmode);

#include <direct.h>
#undef mkdir
#define mkdir(a,b)    fs_win32_mkdirUTF8((a),(b))
int fs_win32_mkdirUTF8 (const char *path, mode_t mode);

#undef stat
#undef fstat
#define stat          fs_win32_stati64UTF8
#define fstat(fd,st)  _fstati64((fd),(struct _stati64 *)(st))

/*('#define stat fs_win32_stati64UTF8' must handle 'struct stat' definitions)*/
struct fs_win32_stati64UTF8 {
#if 1 /*(?non-standard?) (appears to work)*/
    struct _stati64; /*(intentionally unnamed for transparent struct)*/
#else
/* /usr/x86_64-w64-mingw32/sys-root/mingw/include/_mingw_stat64.h */
  #ifdef __MINGW_EXTENSION
    _dev_t st_dev;
    _ino_t st_ino;
    unsigned short st_mode;
    short st_nlink;
    short st_uid;
    short st_gid;
    _dev_t st_rdev;
    __MINGW_EXTENSION __int64 st_size;
    __time64_t st_atime;
    __time64_t st_mtime;
    __time64_t st_ctime;
  #else
/* C:/Program Files (x86)/Windows Kits/10/Include/10.0.19041.0/ucrt/sys/stat.h*/
    _dev_t         st_dev;
    _ino_t         st_ino;
    unsigned short st_mode;
    short          st_nlink;
    short          st_uid;
    short          st_gid;
    _dev_t         st_rdev;
    __int64        st_size;
    __time64_t     st_atime;
    __time64_t     st_mtime;
    __time64_t     st_ctime;
  #endif
#endif
};

/* could be inline compat func here, but fairly large func */
int fs_win32_stati64UTF8 (const char *path, struct fs_win32_stati64UTF8 *st);

#endif /* _WIN32 */

#endif
