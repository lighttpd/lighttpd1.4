#ifndef LI_BSC_COMPAT_H
#define LI_BSC_COMPAT_H
/* BiSheng C ownership/safety keywords. Under the BSC compiler (__bishengc
 * defined) these are real keywords. For every other compiler (plain C) they
 * must vanish so annotated headers still parse. Do NOT guard _Nullable /
 * _Nonnull here — those are real clang nullability keywords valid in plain C. */
#ifndef __bishengc
#define _Owned
#define _Borrow
#define _Safe
#define _Unsafe
#define _Mut
#define _Const
#endif
#endif /* LI_BSC_COMPAT_H */
