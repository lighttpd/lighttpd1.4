#ifndef LI_SYS_MMAP_H
#define LI_SYS_MMAP_H
#include "first.h"

#if defined(HAVE_SYS_MMAN_H)

#include <sys/mman.h>

#elif defined(_WIN32)

#include <Windows.h>
#include <HandleAPI.h>
#include <io.h>
#include <MemoryAPI.h>

#ifndef MAP_FAILED
#define MAP_FAILED ((void *)-1)
#endif
#ifndef MAP_PRIVATE
#define MAP_PRIVATE 0
#endif
#ifndef MAP_SHARED
#define MAP_SHARED 0
#endif
#ifndef PROT_READ
#define PROT_READ PAGE_READONLY
#endif
#ifndef PROT_WRITE
#define PROT_WRITE PAGE_READWRITE
#endif

#define HAVE_MMAP 1

#define munmap(addr, length) UnmapViewOfFile((LPCVOID)(addr))

static inline void *
mmap (void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    /* XXX: this limited implementation maps args only to read-only mmap */
    if (prot != PAGE_READONLY) /*(for PAGE_READONLY and FILE_MAP_READ)*/
        return MAP_FAILED;
    UNUSED(flags);

    HANDLE mh = CreateFileMapping((HANDLE) _get_osfhandle(fd),
                                  NULL, PAGE_READONLY,
                                 #ifdef _WIN64
                                  (sizeof(size_t) > 4) ? length >> 32 : 0,
                                 #else
                                  0,
                                 #endif
                                  length & 0xffffffff, NULL);
    if (NULL == mh)
        return MAP_FAILED;

    LPVOID p = MapViewOfFileEx(mh, FILE_MAP_READ,
                              #ifdef _WIN64
                               (sizeof(off_t) > 4) ? offset >> 32 : 0,
                              #else
                               0,
                              #endif
                               offset & 0xffffffff, length, addr);
    CloseHandle(mh);
    return (NULL != p) ? (void *)p : MAP_FAILED;
}

#else

# define MAP_SHARED 0
# define MAP_PRIVATE 0
# define PROT_READ 0
# define PROT_WRITE 0

# define mmap(a, b, c, d, e, f) (-1)
# define munmap(a, b) (-1)

#endif /* HAVE_SYS_MMAN_H */

/* NetBSD 1.3.x needs it; also make it available if mmap() is not present */
#if !defined(MAP_FAILED)
# define MAP_FAILED ((char*)-1)
#endif

#endif
