#include "first.h"

#include "stream.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>
#include <fcntl.h>

#include "sys-mmap.h"

#ifndef O_BINARY
# define O_BINARY 0
#endif

int stream_open(stream *f, buffer *fn) {

#ifdef HAVE_MMAP

	struct stat st;
	int fd;

	f->start = NULL;
	f->size = 0;

	if (-1 == (fd = open(fn->ptr, O_RDONLY | O_BINARY))) {
		return -1;
	}

	if (-1 == fstat(fd, &st)) {
		close(fd);
		return -1;
	}

	if (0 == st.st_size) {
		/* empty file doesn't need a mapping */
		close(fd);
		return 0;
	}

	f->start = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);

	close(fd);

	if (MAP_FAILED == f->start) {
		f->start = NULL;
		return -1;
	}

	f->size = st.st_size;
	return 0;

#elif defined __WIN32

	HANDLE *fh, *mh;
	void *p;
	LARGE_INTEGER fsize;

	f->start = NULL;
	f->size = 0;

	fh = CreateFile(fn->ptr,
			GENERIC_READ,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_READONLY,
			NULL);

	if (!fh) return -1;

	if (0 != GetFileSizeEx(fh, &fsize)) {
		CloseHandle(fh);
		return -1;
	}

	if (0 == fsize) {
		CloseHandle(fh);
		return 0;
	}

	mh = CreateFileMapping( fh,
			NULL,
			PAGE_READONLY,
			(sizeof(off_t) > 4) ? fsize >> 32 : 0,
			fsize & 0xffffffff,
			NULL);

	if (!mh) {
/*
		LPVOID lpMsgBuf;
		FormatMessage(
		        FORMAT_MESSAGE_ALLOCATE_BUFFER |
		        FORMAT_MESSAGE_FROM_SYSTEM,
		        NULL,
		        GetLastError(),
		        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		        (LPTSTR) &lpMsgBuf,
		        0, NULL );
*/
		CloseHandle(fh);
		return -1;
	}

	p = MapViewOfFile(mh,
			FILE_MAP_READ,
			0,
			0,
			0);
	CloseHandle(mh);
	CloseHandle(fh);

	f->start = p;
	f->size = (off_t)fsize;
	return 0;

#else
# error no mmap found
#endif

}

int stream_close(stream *f) {
#ifdef HAVE_MMAP
	if (f->start) munmap(f->start, f->size);
#elif defined(__WIN32)
	if (f->start) UnmapViewOfFile(f->start);
#endif

	f->start = NULL;
	f->size = 0;

	return 0;
}
