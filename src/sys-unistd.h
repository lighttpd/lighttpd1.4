/*
 * sys-unistd.h - unistd.h wrapper (selective; incomplete)
 *
 * Copyright(c) 2021 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#ifndef INCLUDED_SYS_UNISTD_H
#define INCLUDED_SYS_UNISTD_H
#include "first.h"


#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif


#ifdef _WIN32


#include <direct.h>

#undef chdir
#define chdir(path)                     _chdir(path)

#undef getcwd
#define getcwd(buf,sz)                  _getcwd((buf),(int)(sz))

#if 0 /* mkdir() is from <sys/stat.h> for mode; see local sys-stat.h */
#undef mkdir
#define mkdir(a,b)                      _mkdir(a)
#endif

#undef rmdir
#define rmdir(path)                     _rmdir(path)


#include <process.h>

#undef getpid
#define getpid()                        _getpid()


#include <io.h>

#undef close
#define close(fd)                       _close(fd)

/* _dup2() returns 0 on success, not newfd */
#undef dup2
#define dup2(oldfd,newfd) (0 == _dup2((oldfd),(newfd)) ? (newfd) : -1)

#undef ftruncate
#define ftruncate(fd, sz) (!(errno = _chsize_s((fd),(sz))) ? 0 : -1)

#undef lseek
#define lseek(fd,offset,origin) _lseeki64((fd), (__int64)(offset), (origin))

/* note: read() and write() are not for SOCKET (see winsock2.h) */
#undef read
#define read(fd,buffer,buffer_size) _read((fd),(buffer),(unsigned)(buffer_size))

/* note: read() and write() are not for SOCKET (see winsock2.h) */
#undef write
#define write(fd,buffer,count)      _write((fd),(buffer),(unsigned)(count))

#undef unlink
#define unlink(path)                    _unlink(path)

/*#include <stdio.h>*//*(defined in <stdio.h> in _WIN32 ucrt includes)*/
#ifndef SEEK_SET
#define SEEK_SET 0
#endif


#endif /* _WIN32 */


#ifndef STDIN_FILENO
#define STDIN_FILENO  0
#endif
#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif
#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif


#endif
