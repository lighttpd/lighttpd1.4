#ifndef LI_BSC_COMPAT_H
#define LI_BSC_COMPAT_H
/* BiSheng C ownership/safety keywords. Under the BSC compiler (__bishengc
 * defined) these are real keywords driving the borrow checker. For every other
 * compiler (plain C) they must vanish so the annotated buffer.h still parses.
 *
 * _Nullable / _Nonnull are also neutralized: although Clang accepts them as
 * nullability keywords, GCC (the default compiler for the cmake/autotools
 * builds) does not, so leaving them live would break the ~69 plain-C includers
 * of buffer.h under GCC. Under BSC they stay live and feed the nullability
 * checker. */
#ifndef __bishengc
#define _Owned
#define _Borrow
#define _Safe
#define _Unsafe
#define _Mut
#define _Const
#define _Nullable
#define _Nonnull
#endif
#endif /* LI_BSC_COMPAT_H */
