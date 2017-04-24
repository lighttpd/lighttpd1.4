#ifndef LI_SYS_STRINGS_H
#define LI_SYS_STRINGS_H
#include "first.h"

#if defined(HAVE_STRINGS_H)

#include <strings.h>

#else /* HAVE_STRINGS_H */

#ifdef _MSC_VER
#define strcasecmp(s1,s2)    _stricmp(s1,s2)
#define strncasecmp(s1,s2,n) _strnicmp(s1,s2,n)
#else
/* ??? */
#endif

#endif /* HAVE_STRINGS_H */

#endif
