# Pilot: C → BiSheng C translation of `buffer.c` + `buffer.h`

**Date:** 2026-05-23
**Status:** Approved design — ready for implementation plan
**Scope:** Pilot (one subsystem). **Goal:** memory-safety hardening. **Toolchain:** user-provided BiSheng C clang.

## 1. Goal & scope

Translate lighttpd's central buffer type (`src/buffer.c` + `src/buffer.h`) to BiSheng C, adding
ownership/borrow annotations so the BSC borrow checker can catch use-after-free, double-free, and
leaks in this code. This is a **proof-of-concept** that establishes the foundational ownership
pattern the rest of the tree could later build on (the buffer is the natural first domino — it
depends on nothing and is included by 70 files).

**Hard constraint:** the other 69 files that `#include "buffer.h"` must keep building unchanged, and
none of the four build systems (autotools / meson / cmake / scons) may be modified. The pilot adds
BSC annotations to exactly two files plus one new compatibility header.

## 2. Toolchain (verified)

- **Compiler:** `~/bsc/llvm-project/install/bin/clang` — BiSheng C, clang 15.0.4, supports `-x bsc`.
- **libcbs include:** `/home/zly/bsc/llvm-project/install/include/libcbs` (contains `bishengc_safety.hbs`).
- **Runtime lib:** `/home/zly/bsc/llvm-project/install/lib/libstdcbs.a` (needed only when linking; not for `-fsyntax-only`).
- The stock system `clang` (Ubuntu 18.1.3) does **not** support `-x bsc`; only the BSC clang above does.

**Verify command** (borrow-check `buffer.c` in isolation, no link — exit 0 = clean):
```sh
~/bsc/llvm-project/install/bin/clang -x bsc \
  -I/home/zly/bsc/llvm-project/install/include/libcbs \
  -Wno-nullability-completeness -fsyntax-only src/buffer.c
```
**Link form** (only if building a runnable artifact): append
`-L/home/zly/bsc/llvm-project/install/lib -lstdcbs -o <out>`.

`-Wno-nullability-completeness` suppresses warnings originating inside `bishengc_safety.hbs` itself
(not our code). This command, and the link form, get recorded in `CLAUDE.md` under a
"BSC Project Compile Command" section so future sessions don't guess.

## 3. Migration mechanics — dual-build model (validated)

**Key fact, proven empirically:** `_Owned`, `_Borrow`, `_Safe`, `_Unsafe`, `_Mut`, `_Const` are BSC
*keywords*, not macros. An annotated `buffer.h` compiled in plain-C mode fails to parse
(`expected ')'`), which would break all 69 includers and stock-clang builds.

**Solution (tested working in all three modes):** a new header `src/bsc_compat.h` that neutralizes the
keywords when not under BSC. BSC predefines `__bishengc`; key off it:

```c
#ifndef __bishengc
#define _Owned
#define _Borrow
#define _Safe
#define _Unsafe
#define _Mut
#define _Const
#endif
```

`buffer.h` includes `bsc_compat.h` first. Effects:
- **Plain-C consumers** (BSC clang without `-x bsc`, and stock clang): annotations expand to nothing;
  `char *_Owned ptr` → `char *ptr`, `&_Mut x` → `&x`. Valid C. Verified exit 0 for both compilers.
- **BSC mode** (`-x bsc`): `__bishengc` is defined, the `#define`s are skipped, keywords are live and
  the borrow checker runs. Verified exit 0.

Do **not** macro-guard `_Nullable`/`_Nonnull` — those are real clang nullability keywords that work in
plain C already.

Note: BSC-only constructs that are *not* macro-expandable (`safe_malloc<T>`, `__take_from_raw`,
`__move_to_raw`, `nullptr`, template syntax) must appear **only in `buffer.c` bodies** compiled with
`-x bsc`, never in the shared `buffer.h` seen by plain-C consumers.

## 4. The buffer ownership model

`buffer` is **embedded by value in 41+ structs** (`request.h`: `authority`, `path`, `target`, …;
`array.h`: `key`, `value`; `stat_cache.h`, `base.h`, `fdlog.h`, …) and in by-value arrays
(`buffer bptr[128]`, `cache_user[2]`, `cache_path[2]`). Therefore `buffer` **must stay a plain
`struct`** — promoting it to an `_Owned struct` (with destructor + move semantics) would ripple
move-semantics and destructor obligations onto all 41 embedders and is explicitly out of scope.

Instead, the single heap-owning field becomes owned, which matches lighttpd's existing **manual**
lifetime management (`buffer_free` / `buffer_free_ptr`):

```c
typedef struct {
    char *_Owned _Nullable ptr;   /* _Nullable: the documented "empty" state has ptr == NULL */
    uint32_t used;                /* "used" includes a terminating 0 */
    uint32_t size;                /* size of allocated buffer at *ptr */
} buffer;
```

A plain struct with an `_Owned` field is move-semantic but gets **no auto-destructor** — the code must
release `ptr` manually on every path. That is exactly what `buffer_free`/`buffer_free_ptr` already do,
so the translation stays faithful to the original.

### Signature decisions

| Function (representative) | BSC signature | Rationale |
|---|---|---|
| `buffer_init(void)` | returns `buffer *_Owned` | callee `calloc`s heap struct; caller frees. `force_assert(b)` ⇒ non-null. |
| `buffer_free(b)` | `buffer *_Owned _Nullable b` | consumes the heap struct; frees `b->ptr` then `b`. Header says "b can be NULL". |
| `buffer_free_ptr(b)` | `buffer *_Borrow b` | frees only `b->ptr`, resets fields; struct lives on (embedded-buffer case). |
| `buffer_move(b, src)` | `buffer *_Borrow b, buffer *_Borrow src` | swaps contents; frees neither struct. |
| mutators: `buffer_copy_*`, `buffer_append_*`, `buffer_commit`, `buffer_extend`, `buffer_string_prepare_*`, `buffer_clear`, `buffer_reset` | `buffer *_Borrow b` | mutate contents; do not free the struct. |
| readers: `buffer_clen`, `buffer_is_equal`, `buffer_eq_*`, etc. | `const buffer *_Borrow b` | read-only ⇒ callable from `const` contexts. Apply the read-only-getter `const` discipline. |
| string inputs `s` / `src` / `format` | `const char *_Borrow` | borrowed, not consumed. |
| returned write cursors (`buffer_string_prepare_*`, `buffer_extend` return `char*`) | raw `char *` (interior pointer) | pointer into `b->ptr`; arithmetic cursor — Category C raw, documented. |

### Compiler-driven `_Unsafe` seams (write `_Safe` first; escape only where the checker rejects)

These are the spots expected to need minimal `_Unsafe`, but the **compiler is the source of truth** —
each `_Unsafe` must trace to a specific diagnostic and wrap only the offending statement(s):

1. **`buffer_realloc` / `buffer_alloc_replace`** — `b->ptr = realloc(b->ptr, sz)` is the realloc
   ownership dance: `__move_to_raw(b->ptr)` → `realloc` → null-check → `__take_from_raw`, with the
   failure path re-wrapping per C realloc semantics. (`b` itself is `_Borrow`.)
2. **`buffer_move`** — `tmp = *src; *src = *b; *b = tmp;` is a bit-copy swap of a move-semantic struct.
   Likely needs `_Unsafe` paired with `forget`, or a restructure into explicit field moves. Resolve
   per whatever the borrow checker reports.
3. **byte-encoding helpers** (`buffer_append_string_encoded*`, `buffer_append_uint_hex*`,
   `buffer_append_string_c_escaped`, `buffer_append_path_len`, etc.) — raw `b->ptr[i]` subscripting and
   any `printf`/`snprintf`-style variadic calls. Wrap the raw-subscript / variadic statements only.

## 5. Verification & success criteria

A. `buffer.c` borrow-checks **clean** — the verify command (§2) exits 0 with no errors.
B. The full project still **builds unchanged** as plain C: `meson setup build && ninja -C build`
   succeeds (proves the 69 includers and the build wiring are unaffected). Stock-clang parse of
   `buffer.h` also still succeeds.
C. **`test_buffer` passes** — behavioral parity via `meson test -C build test_buffer`
   (`src/t/test_buffer.c`, ~50 buffer calls). Behavioral parity is the contract; a translation that
   compiles but changes behavior has wrong annotations.
D. Translation contains real `_Owned` annotations (skill minimum bar — zero `_Owned` = incomplete),
   and every `_Unsafe` is minimal and traces to a specific compiler diagnostic.

## 6. Explicitly out of scope

- Promoting `buffer` to an `_Owned struct` (would ripple to 41 embedders).
- Modifying any of the 69 includers.
- Wiring the BSC compiler into the four build systems (the pilot verifies `buffer.c` standalone).
- Translating `array.c` / `chunk.c` — documented as the natural next phases (both depend on buffer).

## 7. Implementation phases (input to the writing-plans step)

1. **Scaffolding** — add `src/bsc_compat.h`; include it first in `buffer.h`; add the BSC compile/verify
   commands to `CLAUDE.md`. Confirm: project still builds (meson) and stock clang still parses
   `buffer.h`. No annotations yet.
2. **Annotate `buffer.h`** — apply the signature table from §4. Re-confirm dual-build green (plain-C
   parse of `buffer.h` under both compilers; project still builds).
3. **Translate `buffer.c` bodies** — `_Safe`-first, iterating against the §2 verify command. Add
   minimal `_Unsafe` only where the compiler demands; convert `&` → `&_Const`/`&_Mut`; convert
   `malloc`/`free` to `safe_malloc`/`safe_free` where applicable, raw `malloc`/`realloc`/`calloc`
   through `__take_from_raw`/`__move_to_raw` in `_Unsafe` where not.
4. **Verify & document** — success criteria A–D; write the ownership-decision summary
   (counts of `_Owned` / `_Borrow` / `_Unsafe`, and any escalations).

## 8. Risks & open questions

- **`buffer_move` swap** may not be expressible without `_Unsafe`+`forget`; acceptable, but if it
  forces a wide escape, reconsider expressing the swap as explicit per-field moves.
- **`force_assert`-based non-null guarantees** vs. BSC nullability tracking: `buffer_init`'s
  `force_assert(b)` lets us return non-null `_Owned`; confirm the checker accepts the post-assert
  narrowing or declare `_Nullable` and let callers check.
- **Interior-pointer returns** (`char*` write cursors) are intentionally raw; confirm call sites within
  `buffer.c` don't trip the checker when consuming them.
- If `buffer.c`'s transitive includes (`first.h`, `sys-time.h`, …) fail to parse under `-x bsc`,
  scaffolding (phase 1) surfaces it early; mitigate with targeted compat shims, not by abandoning
  `-x bsc`.
