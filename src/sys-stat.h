/*
 * sys-stat.h - sys/stat.h wrapper
 *
 * Copyright(c) 2020 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#ifndef INCLUDED_SYS_STAT_H
#define INCLUDED_SYS_STAT_H
#include "first.h"

#include <sys/types.h>
#include <sys/stat.h>


#ifdef _WIN32

#ifndef S_IRWXU
#define S_IRWXU (_S_IREAD | _S_IWRITE | _S_IEXEC)
#endif
#ifndef S_IRUSR
#define S_IRUSR _S_IREAD
#endif
#ifndef S_IWUSR
#define S_IWUSR _S_IWRITE
#endif
#ifndef S_IXUSR
#define S_IXUSR _S_IEXEC
#endif

/* not available on _WIN32 */
#ifndef S_IRWXG
#define S_IRWXG 0
#endif
#ifndef S_IRGRP
#define S_IRGRP 0
#endif
#ifndef S_IWGRP
#define S_IWGRP 0
#endif
#ifndef S_IXGRP
#define S_IXGRP 0
#endif

/* not available on _WIN32 */
#ifndef S_IRWXO
#define S_IRWXO 0
#endif
#ifndef S_IROTH
#define S_IROTH 0
#endif
#ifndef S_IWOTH
#define S_IWOTH 0
#endif
#ifndef S_IXOTH
#define S_IXOTH 0
#endif

/* not available on _WIN32 */
#ifndef S_ISUID
#define S_ISUID 0
#endif
#ifndef S_ISGID
#define S_ISGID 0
#endif
#ifndef S_ISVTX
#define S_ISVTX 0
#endif

#ifndef S_IFMT
#define S_IFMT _S_IFMT
#endif
#ifndef S_IFBLK
#define S_IFBLK _S_IFBLK
#endif
#ifndef S_IFCHR
#define S_IFCHR _S_IFCHR
#endif
#ifndef S_IFDIR
#define S_IFDIR _S_IFDIR
#endif
#ifdef _S_IFIFO
#ifndef S_IFIFO
#define S_IFIFO _S_IFIFO
#endif
#endif
#ifndef S_IFREG
#define S_IFREG _S_IFREG
#endif
#ifdef _S_IFLNK
#ifndef S_IFLNK
#define S_IFLNK _S_IFLNK
#endif
#endif
#ifdef _S_IFSOCK
#ifndef S_IFSOCK
#define S_IFSOCK _S_IFSOCK
#endif
#endif

#ifndef __S_ISTYPE
#define __S_ISTYPE(mode,mask) (((mode) & _S_IFMT) == (mask))
#endif
#ifndef S_ISBLK
#define S_ISBLK(mode)  __S_ISTYPE((mode), _S_IFBLK)
#endif
#ifndef S_ISCHR
#define S_ISCHR(mode)  __S_ISTYPE((mode), _S_IFCHR)
#endif
#ifndef S_ISDIR
#define S_ISDIR(mode)  __S_ISTYPE((mode), _S_IFDIR)
#endif
#ifdef _S_IFIFO
#ifndef S_ISFIFO
#define S_ISFIFO(mode) __S_ISTYPE((mode), _S_IFIFO)
#endif
#endif
#ifdef _S_IFLNK
#ifndef S_ISLNK
#define S_ISLNK(mode)  __S_ISTYPE((mode), _S_IFLNK)
#endif
#endif
#ifndef S_ISREG
#define S_ISREG(mode)  __S_ISTYPE((mode), _S_IFREG)
#endif
#ifdef _S_IFSOCK
#ifndef S_ISSOCK
#define S_ISSOCK(mode) __S_ISTYPE((mode), _S_IFSOCK)
#endif
#endif

/* stat/fstat with 64-bit file length (struct stat, too) */
#undef stat
#undef fstat
#define stat  _stati64
#define fstat _fstati64

#if !defined(__MINGW32__) && !defined(__MINGW64__)
#include <direct.h>
#undef mkdir
#define mkdir(a,b) _mkdir(a)
#endif

#endif /* _WIN32 */

#ifdef _WIN32
/* local overrides to support UTF-8 path strings */
/* note: redefines stat, fstat, mkdir, ... */
#include "fs_win32.h"
#endif


#ifndef S_ISFIFO
#define S_ISFIFO(mode) 0
#endif
#ifndef S_ISLNK
#define S_ISLNK(mode) 0
#endif
#ifndef S_ISSOCK
#define S_ISSOCK(mode) 0
#endif

#ifndef HAVE_LSTAT
#define lstat(a,b) stat((a),(b))
#endif


#endif
