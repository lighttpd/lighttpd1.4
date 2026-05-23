# buffer.c → BiSheng C Pilot — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Also load the `c-to-bsc`, `bsc-ownership`, `bsc-safe-zone`, and `bsc-compile` Skills before starting.

**Goal:** Translate lighttpd's central buffer type (`src/buffer.c` + `src/buffer.h`) to BiSheng C with ownership/borrow annotations so the BSC borrow checker hardens it against use-after-free / double-free / leaks — without touching the other 69 includers or any build system.

**Architecture:** Add a macro-guard shim (`src/bsc_compat.h`) so annotation keywords vanish for plain-C consumers but stay live under `-x bsc`. `buffer` stays a plain `struct` (it is embedded by value in 41+ structs) with its one heap field promoted to `char *_Owned _Nullable ptr`. Functions are translated `_Safe`-first; `_Unsafe` is added only where a specific compiler diagnostic demands it. Verification is per-file borrow-check under `-x bsc` plus the existing `test_buffer` unit test.

**Tech Stack:** BiSheng C clang 15.0.4 (`~/bsc/llvm-project/install/bin/clang`), libcbs (`bishengc_safety.hbs`, `libstdcbs.a`), cmake (to generate `config.h` and as the build-integrity check).

**Spec:** `docs/superpowers/specs/2026-05-23-buffer-c-to-bsc-pilot-design.md` (read it first).

---

## Conventions used in every translation task

**THE VERIFY COMMAND** (borrow-checks `buffer.c` in isolation; exit 0 = clean). Run it after every edit:
```sh
~/bsc/llvm-project/install/bin/clang -x bsc -DHAVE_CONFIG_H \
  -Ibuild-cmake/build -Isrc \
  -I/home/zly/bsc/llvm-project/install/include/libcbs \
  -Wno-nullability-completeness -fsyntax-only src/buffer.c
```

**Compiler-driven `_Unsafe` rule (non-negotiable):** write each function `_Safe` with a plain body first, run the verify command, and add `_Unsafe` ONLY for the exact statement a diagnostic rejects. Never pre-wrap. If a line compiles in `_Safe`, leave it `_Safe`. An `_Unsafe { ... }` block inside a `_Safe` function keeps the function `_Safe`.

**`.h`/`.c` signatures must match** — annotate the declaration in `buffer.h` and the definition in `buffer.c` together, or you get mismatch errors.

**Validated facts this plan relies on** (from spec §2–§3): un-annotated `buffer.c` compiles clean under `-x bsc`; functions without `_Safe`/`_Unsafe` are not safety-checked; but `_Owned` *ownership* errors fire even in non-`_Safe` functions (you cannot subscript, take the value of, or `free` an `_Owned` pointer raw anywhere). Therefore flipping the struct field to `_Owned` (Task 2) is an atomic change that touches every `b->ptr` site at once.

**Two recurring gotchas** (handle as they appear, don't pre-empt):
- `ptr` is `_Owned _Nullable`, so `&_Mut *b->ptr` / `&_Const *b->ptr` may raise a `deref-nullable` diagnostic. Most accesses are post-allocation (guarded by the existing `used`/`size`/`force_assert` checks) where `ptr` is non-NULL — let the checker narrow after those guards, or add the null-check the diagnostic asks for. Do not strip the existing empty-state guards.
- If `safe_malloc<buffer>((buffer){0})` is rejected (compound literal with an owned field), fall back to the raw form: `_Unsafe { buffer *raw = (buffer *)calloc(1, sizeof(buffer)); force_assert(raw); buffer *_Owned b = __take_from_raw(raw); }`.

**Validated in Tasks 2–3 (apply directly; the compiler confirmed these):**
- `memcpy`/`mempcpy`/`strlen` (and the other libc string externs) are `_Unsafe` externs **and** their `char* → void*`/`const char*` arg passes a borrow-to-raw conversion that the safe zone rejects. So each call from a `_Safe` body must be wrapped `_Unsafe { … }` (minimal — just the call/raw-write group). The plan text saying "memcpy stays as-is" was wrong for this toolchain.
- A `_Borrow` (esp. `_Borrow restrict`) parameter **cannot be forwarded** as an argument to another `_Borrow` param — re-borrow at the call site: `f(b)` → `f(&_Mut *b)`, `g(s)` → `g(&_Const *s)`, `buffer_clen(b)` → `buffer_clen(&_Const *b)`. This cascades into *non-`_Safe`* callers too the moment a callee's signature gains `_Borrow`; those re-borrows are pure mechanical arg fixes — do NOT mark the caller `_Safe` unless its own task says so.
- Marking a function `_Safe` requires `_Safe` on **both** its `.h` declaration and `.c` definition, or `_Safe` callers won't resolve it.
- Narrowing/qualifier-adding conversions are forbidden in the safe zone: add explicit `(uint32_t)`/`(size_t)` casts where the original relied on implicit narrowing, and drop `const`/`restrict` on local cursor variables (optimizer hints only; behavior-neutral). Keep `const`/`restrict` on parameters.

---

## Task 1: Scaffolding & baseline

**Files:**
- Create: `src/bsc_compat.h`
- Modify: `src/buffer.h` (add one include near the top, after `#include "first.h"`)
- Modify: `CLAUDE.md` (add a "BSC Project Compile Command" section)
- Create (generated, git-ignored): `build-cmake/` via cmake

- [ ] **Step 1: Generate `config.h`**

Run:
```sh
cmake -S . -B build-cmake -Wno-dev -DWITH_PCRE2=OFF -DWITH_PCRE=OFF
```
Expected: `-- Build files have been written to: .../build-cmake`, and `build-cmake/build/config.h` exists. (PCRE is disabled only because pcre2 dev headers are absent here; we just need `config.h`.)

- [ ] **Step 2: Create the macro-guard shim `src/bsc_compat.h`**

```c
#ifndef LI_BSC_COMPAT_H
#define LI_BSC_COMPAT_H
/* BiSheng C ownership/safety keywords. Under the BSC compiler (__bishengc
 * defined) these are real keywords. For every other compiler (plain C) they
 * must vanish so annotated headers still parse. _Nullable/_Nonnull are guarded
 * too: Clang accepts them in plain C but GCC (the default cmake/autotools
 * compiler) does not, so leaving them live breaks the includers under GCC. */
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
```

- [ ] **Step 3: Include the shim first in `buffer.h`**

In `src/buffer.h`, immediately after the existing `#include "first.h"` (line 3), add:
```c
#include "bsc_compat.h"
```

- [ ] **Step 4: Verify the un-annotated file still borrow-checks clean**

Run THE VERIFY COMMAND (above).
Expected: exit 0, no output. (The shim is a no-op under `-x bsc`; nothing is annotated yet.)

- [ ] **Step 5: Verify plain-C consumers are unaffected (both compilers)**

```sh
# stock clang, plain C
clang -DHAVE_CONFIG_H -Ibuild-cmake/build -Isrc -fsyntax-only src/buffer.c
# BSC clang in PLAIN-C mode (no -x bsc)
~/bsc/llvm-project/install/bin/clang -DHAVE_CONFIG_H -Ibuild-cmake/build -Isrc -fsyntax-only src/buffer.c
```
Expected: both exit 0. (Proves `bsc_compat.h` keeps `buffer.h` valid plain C.)

- [ ] **Step 6: Verify the full project still builds**

```sh
cmake --build build-cmake -j4
```
Expected: build succeeds (the 69 includers and build wiring are unaffected).

- [ ] **Step 7: Document the toolchain in `CLAUDE.md`**

Append this section to `CLAUDE.md`:
```markdown
## BSC Project Compile Command

BiSheng C pilot translation lives in `src/buffer.c` / `src/buffer.h`. Annotations are
macro-guarded by `src/bsc_compat.h` so plain-C builds are unaffected.

- BSC compiler: `~/bsc/llvm-project/install/bin/clang` (clang 15.0.4, supports `-x bsc`)
- libcbs include: `/home/zly/bsc/llvm-project/install/include/libcbs`
- runtime lib (link only): `/home/zly/bsc/llvm-project/install/lib` (`-lstdcbs`)

Generate config.h once (meson/autotools absent here; cmake present):
    cmake -S . -B build-cmake -Wno-dev -DWITH_PCRE2=OFF -DWITH_PCRE=OFF

Verify (borrow-check buffer.c, no link):
    ~/bsc/llvm-project/install/bin/clang -x bsc -DHAVE_CONFIG_H \
      -Ibuild-cmake/build -Isrc \
      -I/home/zly/bsc/llvm-project/install/include/libcbs \
      -Wno-nullability-completeness -fsyntax-only src/buffer.c

Test (behavioral parity):  ctest --test-dir build-cmake -R '^test_buffer'
```

- [ ] **Step 8: Ignore the cmake build dir and commit**

```sh
grep -qxF 'build-cmake/' .gitignore || echo 'build-cmake/' >> .gitignore
git add src/bsc_compat.h src/buffer.h CLAUDE.md .gitignore
git commit -m "bsc: add macro-guard shim and pilot scaffolding for buffer translation"
```

---

## Task 2: Allocation / lifecycle core + `_Owned` struct field (the atomic pivot)

This task flips `buffer.ptr` to `_Owned` and makes the **entire file** ownership-correct, then marks the allocation/lifecycle functions `_Safe`. After this task the verify command is green; later tasks only add `_Safe` + safe-zone coverage to the remaining functions.

**Files:**
- Modify: `src/buffer.h` (struct definition + declarations of `buffer_init`, `buffer_free`, `buffer_free_ptr`, `buffer_move`, `buffer_string_prepare_copy`, `buffer_string_prepare_append`, `buffer_extend`, `buffer_commit`)
- Modify: `src/buffer.c` (definitions of the above + `buffer_realloc`, `buffer_alloc_replace`, `buffer_string_prepare_append_resize`; plus minimal owned-correctness fixes at every other `b->ptr` site)

- [ ] **Step 1: Promote the struct field in `buffer.h`**

Change the struct (lines 22–29) to:
```c
typedef struct {
	char *_Owned _Nullable ptr;   /* _Nullable: documented "empty" state has ptr == NULL */

	/* "used" includes a terminating 0 */
	uint32_t used;
	/* size of allocated buffer at *ptr */
	uint32_t size;
} buffer;
```

- [ ] **Step 2: Annotate the lifecycle declarations in `buffer.h`**

Apply (keep all existing `__attribute_*` macros):
```c
buffer *_Owned buffer_init(void);                      /* was: buffer* buffer_init(void); */
void buffer_free(buffer *_Owned _Nullable b);          /* was: buffer *b  (b can be NULL) */
void buffer_free_ptr(buffer *_Borrow b);               /* frees only b->ptr; struct lives on */
void buffer_move(buffer *_Borrow restrict b, buffer *_Borrow restrict src);
char* buffer_string_prepare_copy(buffer *_Borrow b, size_t size);   /* returns raw cursor */
char* buffer_string_prepare_append(buffer *_Borrow b, size_t size); /* returns raw cursor */
char* buffer_extend(buffer *_Borrow restrict b, size_t x);         /* returns raw cursor */
void buffer_commit(buffer *_Borrow b, size_t size);
```
Note: return type stays raw `char*` — these return an **interior pointer** into `b->ptr` (Category C arithmetic cursor), which is exactly why append callers don't touch the owned field.

- [ ] **Step 3: Translate `buffer_init` (definition, `buffer.c` ~line 14)**

```c
__attribute_noinline__
_Safe buffer *_Owned buffer_init(void) {
    buffer *_Owned b = safe_malloc<buffer>((buffer){0});  /* zero-init: ptr=nullptr,used=0,size=0 */
    return b;
}
```
Add `#include "bishengc_safety.hbs"` near the top of `buffer.c` (after the existing includes). `safe_malloc` aborts on OOM via `bsc_bad_alloc_handler`, subsuming the old `force_assert(b)`.

- [ ] **Step 4: Translate `buffer_free` and `buffer_free_ptr`**

```c
_Safe void buffer_free(buffer *_Owned _Nullable b) {
    if (NULL == b) return;
    safe_free((void *_Nullable _Owned)b->ptr);   /* ptr may be NULL */
    safe_free((void *_Owned)b);                   /* free the struct */
}

_Safe void buffer_free_ptr(buffer *_Borrow b) {
    safe_free((void *_Nullable _Owned)b->ptr);
    b->ptr = nullptr;
    b->used = 0;
    b->size = 0;
}
```
If the compiler reports a "partially moved struct" on `safe_free((void *_Owned)b)` after the `ptr` field was freed, this is expected for a plain struct with an owned field; resolve per the diagnostic (the field is already moved/freed, so the remaining struct free is just the block). Run THE VERIFY COMMAND after this step and read any `note:` lines.

- [ ] **Step 5: Translate `buffer_realloc` and `buffer_alloc_replace` (the realloc dance)**

`buffer_realloc` (~line 49) currently does `b->ptr = realloc(b->ptr, sz);`. Replace the realloc with the ownership dance:
```c
_Safe static char* buffer_realloc(buffer *_Borrow restrict b, const size_t len) {
    /* ... unchanged size computation producing `sz` ... */
    b->size = sz;
    _Unsafe {
        char *raw_old = __move_to_raw(b->ptr);            /* b->ptr was _Owned _Nullable */
        char *raw_new = (char *)realloc(raw_old, sz);
        force_assert(NULL != raw_new);
        b->ptr = __take_from_raw(raw_new);                /* b->ptr owns the resized block */
    }
    return (char *)&_Mut *b->ptr;     /* borrow-then-cast: raw interior cursor; ownership stays in b */
}
```
Returning the cursor: the function returns `b->ptr` as a raw `char*`. Since `b->ptr` is `_Owned`, you must NOT C-cast it to raw — borrow-then-cast (`(char *)&_Mut *b->ptr`) yields the interior cursor while ownership stays in `b`. Apply the same realloc-dance + cursor-return pattern to `buffer_alloc_replace` (~line 71), which first frees `b->ptr` when non-NULL — replace that `free` with `safe_free((void *_Nullable _Owned)b->ptr); b->ptr = nullptr;` before the realloc.

- [ ] **Step 6: Translate `buffer_string_prepare_copy`, `buffer_string_prepare_append_resize`, `buffer_string_prepare_append`, `buffer_extend`, `buffer_commit`**

These read `b->ptr` (e.g. `? b->ptr : buffer_alloc_replace(...)` and `b->ptr + len`) and return a raw cursor. Replace each direct `b->ptr` *value* read with a borrow-then-cast cursor:
```c
char *d = (char *)&_Mut *b->ptr;     /* raw interior cursor from the owned field */
```
For `buffer_commit` (`b->ptr[sz - 1] = '\0';`), an `_Owned` pointer can't be subscripted — rewrite as:
```c
_Unsafe { ((char *)&_Mut *b->ptr)[sz - 1] = '\0'; }
```
Mark all five `_Safe`. Run THE VERIFY COMMAND; the only remaining errors should be in functions not yet touched in this task.

- [ ] **Step 7: Translate `buffer_move` (the owned-field swap)**

`buffer_move` does `buffer tmp; tmp = *src; *src = *b; *b = tmp;` — a bit-copy swap of a struct containing an `_Owned` field. Write it `_Safe` and run the verify command. If the checker rejects the struct assignments (duplicated/owned-field copy), wrap the three-line swap:
```c
_Safe void buffer_move(buffer *_Borrow restrict b, buffer *_Borrow restrict src) {
    buffer_clear(b);
    _Unsafe {
        buffer tmp = *src; *src = *b; *b = tmp;   /* move ownership of ptr between b and src */
    }
}
```
Only widen the `_Unsafe` if the diagnostic requires; the swap is a single logical move so `forget` is typically unnecessary here (no field is left dangling — every `ptr` ends owned by exactly one buffer). Confirm against the compiler.

- [ ] **Step 8: Make every remaining `b->ptr` site owned-correct (compile-only, not yet `_Safe`)**

The field flip breaks the comparison readers and the encoding/path/case functions even though they are not `_Safe` yet. Fix each so the file compiles, leaving the `_Safe` marking for Tasks 3–5. Sites and fixes:
- `buffer_eq_icase_slen` (429), `buffer_eq_slen` (435), `buffer_is_equal` (445) — pass `b->ptr` to `buffer_eq_icase_ssn`/`memcmp`. Replace `b->ptr` with `(const char *)&_Const *b->ptr` (borrow-then-cast, read-only).
- `buffer_substr_replace` (476–482) — `b->ptr+offset` arithmetic and `replace->ptr`. Take one raw cursor at the top: `_Unsafe { char *bp = (char *)&_Mut *b->ptr; const char *rp = (const char *)&_Const *replace->ptr; ... }`.
- `buffer_urldecode_path` (794–816), `buffer_path_simplify` (865–953), `buffer_to_lower` (957), `buffer_to_upper` (966) — each takes the `b->ptr` value into a working pointer. Replace `b->ptr` with `(unsigned char *)&_Mut *b->ptr` (or `char *`), inside `_Unsafe` if not yet `_Safe`.

Run THE VERIFY COMMAND after each fix.

- [ ] **Step 9: Verify clean and commit**

Run THE VERIFY COMMAND.
Expected: exit 0, no output (whole file is owned-correct; allocation/lifecycle core is `_Safe`).
```sh
git add src/buffer.h src/buffer.c
git commit -m "bsc: own buffer.ptr; translate allocation/lifecycle core to _Safe"
```

---

## Task 3: copy / append family → `_Safe`

**Files:**
- Modify: `src/buffer.h` (declarations + the `static inline` definitions for `buffer_copy_buffer`, `buffer_append_buffer`, `buffer_append_char`, `buffer_append_slash`, `buffer_truncate`, `buffer_blank`, `buffer_clear`, `buffer_reset`)
- Modify: `src/buffer.c` (`buffer_copy_string`, `buffer_copy_string_len`, `buffer_copy_string_len_lc`, `buffer_append_string`, `buffer_append_string_len`, `buffer_append_str2`, `buffer_append_str3`, `buffer_append_iovec`, `buffer_append_path_len`)

- [ ] **Step 1: Annotate signatures**

In both files, set buffer params to `buffer *_Borrow restrict` (mut) and string inputs to `const char *_Borrow restrict`. Source buffers (in `buffer_copy_buffer`/`buffer_append_buffer`) are `const buffer *_Borrow restrict`. Example:
```c
void buffer_copy_string_len(buffer *_Borrow restrict b, const char *_Borrow restrict s, size_t len);
void buffer_append_string_len(buffer *_Borrow restrict b, const char *_Borrow restrict s, size_t len);
```

- [ ] **Step 2: Mark `_Safe` and translate bodies**

Mark each function `_Safe`. The append functions write through the raw cursor from `buffer_extend`/`buffer_string_prepare_*` (already raw — no owned-field access), so most need no `_Unsafe`. For `buffer_copy_string_len` (`char *d = (len < b->size) ? b->ptr : buffer_alloc_replace(b,len);`), replace the `b->ptr` branch with the borrow-cast cursor `(char *)&_Mut *b->ptr`. For the `static inline` header functions that subscript (`buffer_append_char`: `b->ptr[b->used-1]=c`), use `_Unsafe { ((char *)&_Mut *b->ptr)[...] = ...; }`. `memcpy`/`mempcpy` calls into a raw cursor stay as-is (raw pointers, not owned).

- [ ] **Step 3: Verify and commit**

Run THE VERIFY COMMAND. Expected: exit 0.
```sh
git add src/buffer.h src/buffer.c
git commit -m "bsc: translate buffer copy/append family to _Safe"
```

---

## Task 4: numeric / encoding / path / case → `_Safe`

These hold the bulk of the raw-subscript `_Unsafe` seams.

**Files:**
- Modify: `src/buffer.h` (declarations) and `src/buffer.c`: `buffer_append_uint_hex_lc`, `buffer_append_int`, `buffer_append_strftime`, `li_itostrn`, `li_utostrn`, `li_hex2bin`, `li_tohex_lc`, `li_tohex_uc`, `buffer_substr_replace`, `buffer_append_string_encoded_hex_lc`, `buffer_append_string_encoded_hex_uc`, `buffer_append_string_encoded`, `buffer_append_string_c_escaped`, `buffer_urldecode_path`, `buffer_path_simplify`, `buffer_to_lower`, `buffer_to_upper`

- [ ] **Step 1: Annotate signatures**

`buffer *` params → `buffer *_Borrow restrict`; `const buffer *` → `const buffer *_Borrow restrict`; string inputs → `const char *_Borrow`. The `li_*` helpers operate on caller-supplied raw `char *buf` cursors — keep those raw (Category C arithmetic), but annotate any `buffer *`/`const char *` they take. Example:
```c
void buffer_append_string_encoded(buffer *_Borrow restrict b, const char *_Borrow restrict s, size_t len, buffer_encoding_t encoding);
```

- [ ] **Step 2: Mark `_Safe`, write plain bodies, let the compiler place `_Unsafe`**

Mark each `_Safe`. These functions index `b->ptr[i]`, walk pointers (`*p++`, `dst - b->ptr`), and call the raw `li_tohex_*`/`li_*` helpers. For each diagnostic:
- raw subscript / pointer walk over the buffer → take one cursor at function top: `char * const out = (char *)&_Mut *b->ptr;` (use `unsigned char *` where the original does), and operate on `out`. Wrap only the minimal raw statements in `_Unsafe` if the checker still rejects pointer arithmetic.
- the `b->used = (dst - b->ptr) + 1;` length recomputation (urldecode/path_simplify) — compute against the same raw `out` base cursor, not the owned field.
- variadic / formatted calls (none expected here, but `strftime` in `buffer_append_strftime`) — if the checker rejects the `strftime` call, wrap that one statement in `_Unsafe`.

Watch the two known port hazards (spec + c-to-bsc skill): preserve `default:` emit branches in any `switch` that writes output, and keep pointer-offset arithmetic relative to the correct base.

- [ ] **Step 3: Verify and commit**

Run THE VERIFY COMMAND. Expected: exit 0.
```sh
git add src/buffer.h src/buffer.c
git commit -m "bsc: translate buffer numeric/encoding/path/case fns to _Safe"
```

---

## Task 5: comparison readers + remaining header inlines → `_Safe`

**Files:**
- Modify: `src/buffer.c`: `buffer_eq_icase_ssn`, `buffer_eq_icase_ss`, `buffer_eq_icase_slen`, `buffer_eq_slen`, `buffer_is_equal`
- Modify: `src/buffer.h` (`static inline`): `buffer_clen`, `buffer_string_space`, `buffer_is_unset`, `buffer_is_blank`, `buffer_has_slash_suffix`, `buffer_has_pathsep_suffix`, `light_isdigit`/`isxdigit`/`isalpha`/`isalnum`/`isprint`/`iscntrl`/`iscntrl_or_utf8_invalid_byte`

- [ ] **Step 1: Annotate as read-only (`const`) and mark `_Safe`**

Readers must take `const buffer *_Borrow b` and (for `light_is*`) plain `int`. Apply the const-getter discipline so they are callable from `const` contexts:
```c
_Safe int buffer_is_equal(const buffer *_Borrow a, const buffer *_Borrow b);
static inline _Safe uint32_t buffer_clen(const buffer *_Borrow b);
```
`buffer_eq_*` and `buffer_is_equal` pass `b->ptr`/`a->ptr` to `memcmp` — read-only, so use `(const char *)&_Const *b->ptr`. The `b->used == 0 ? : ` guards already protect the NULL-`ptr` empty state; keep them.

- [ ] **Step 2: Verify and commit**

Run THE VERIFY COMMAND. Expected: exit 0 (now the entire translation unit's functions are `_Safe`).
```sh
git add src/buffer.h src/buffer.c
git commit -m "bsc: translate buffer comparison readers and header inlines to _Safe"
```

---

## Task 6: Final verification & documentation

- [ ] **Step 1: Borrow-check clean (success criterion A)**

Run THE VERIFY COMMAND. Expected: exit 0, no output.

- [ ] **Step 2: Includers unaffected — `buffer.h` stays dual-valid (success criterion B)**

A translated `buffer.c` is a BSC-only TU (it contains `bishengc_safety.hbs` + builtins), so it can
**no longer** be parsed by gcc/stock-clang — and that is fine (spec §6 scopes out build-system wiring).
The integrity check is that the *header* stays dual-valid so the includers are untouched. Sweep every
standalone `src/*.c` **except `buffer.c`** under gcc and confirm zero `buffer.h`-related failures:
```sh
for f in src/*.c; do [ "$f" = src/buffer.c ] && continue; \
  gcc -DHAVE_CONFIG_H -Ibuild-cmake/build -Isrc -fsyntax-only "$f" 2>&1; done | grep -i 'buffer\.h'
```
Expected: no output (the only failing TUs are pre-existing: missing optional-dep headers, Windows-only,
lemon/X-macro templates — none mention `buffer.h`). Spot-check stock-clang + BSC-plain-C on one includer.

- [ ] **Step 3: (folded into Step 2)** — `cmake --build` of the whole project is intentionally *not*
expected to succeed post-translation, because it would compile `buffer.c` with gcc. Building a linked
artifact requires compiling `buffer.c` with `-x bsc` and linking `-lstdcbs` (Step 4's recipe).

- [ ] **Step 4: Behavioral parity via the unit test (success criterion C)**

`ctest` would compile `buffer.c` with gcc and fail, so build the parity runner directly: `buffer.o`
under `-x bsc` + a plain-C harness that `#include`s **`buffer.h`** (not `buffer.c`) and calls
`test_buffer()`, linked with `-lstdcbs`. The repo's `src/t/test_buffer.c` is **not** modified — the
`#include "buffer.c"` → `"buffer.h"` swap happens only in a throwaway copy (it uses only public API,
and `_Owned`/`_Borrow` erase at codegen so the gcc objects link against the BSC `buffer.o`):
```sh
BSC=~/bsc/llvm-project/install/bin/clang
LIBCBS=/home/zly/bsc/llvm-project/install/include/libcbs
LIBDIR=/home/zly/bsc/llvm-project/install/lib; W=/tmp/bsc_test_buffer; mkdir -p $W
$BSC -x bsc -DHAVE_CONFIG_H -Ibuild-cmake/build -Isrc -I$LIBCBS \
  -Wno-nullability-completeness -c src/buffer.c -o $W/buffer.o
sed 's|#include "buffer.c"|#include "buffer.h"|' src/t/test_buffer.c > $W/tb.c
printf 'void test_buffer(void);\nint main(void){test_buffer();return 0;}\n' > $W/m.c
gcc -DHAVE_CONFIG_H -Ibuild-cmake/build -Isrc -c $W/tb.c -o $W/tb.o
gcc -DHAVE_CONFIG_H -Ibuild-cmake/build -Isrc -c src/ck.c -o $W/ck.o
gcc -DHAVE_CONFIG_H -Ibuild-cmake/build -Isrc -c $W/m.c  -o $W/m.o
$BSC $W/tb.o $W/buffer.o $W/ck.o $W/m.o -L$LIBDIR -lstdcbs -o $W/run && $W/run; echo "EXIT $?"
```
Expected: `EXIT 0` (all `test_buffer` assertions pass).

- [ ] **Step 5: Audit the `_Owned`/`_Unsafe` surface (success criterion D)**

```sh
echo "_Owned:";  grep -c '_Owned'  src/buffer.c src/buffer.h
echo "_Borrow:"; grep -c '_Borrow' src/buffer.c src/buffer.h
echo "_Unsafe:"; grep -c '_Unsafe' src/buffer.c
```
Confirm `_Owned` count > 0 (skill minimum bar) and that every `_Unsafe` block is minimal — re-read each and delete any that the file compiles without.

- [ ] **Step 6: Record the ownership summary and changelog**

Append an "Outcome" section to the spec (`docs/superpowers/specs/2026-05-23-buffer-c-to-bsc-pilot-design.md`) with the counts from Step 5 and any cases escalated to `_Unsafe` (with the diagnostic that forced each). Add a `NEWS` entry under the current development section, e.g.:
```
  - [pilot] buffer.c/buffer.h translated to BiSheng C with ownership annotations
    (memory-safety hardening; plain-C builds unaffected via src/bsc_compat.h)
```

- [ ] **Step 7: Commit**

```sh
git add docs/superpowers/specs/2026-05-23-buffer-c-to-bsc-pilot-design.md NEWS
git commit -m "bsc: document buffer pilot outcome and add NEWS entry"
```

---

## Self-review notes (for the executor)

- **If the verify command fails after the field flip with errors in functions you haven't reached:** that's expected mid-Task-2; Step 8 of Task 2 is exactly the sweep that clears them. The file must be green only at each *commit*.
- **If `buffer_move`'s swap forces a wide `_Unsafe`:** reconsider expressing it as explicit per-field moves rather than a struct bit-copy (spec §8 risk).
- **`force_assert`/`ck_assert_failed`** calls stay as-is; they are plain function calls, not pointer ops.
- **Do not** promote `buffer` to `_Owned struct`, modify any of the 69 includers, or add the BSC compiler to a build system — all out of scope (spec §6).
