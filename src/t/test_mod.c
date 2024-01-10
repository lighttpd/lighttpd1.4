#include "first.h"

#undef NDEBUG
#include <assert.h>

#include "chunk.h"

void test_mod_access (void);
void test_mod_alias (void);
void test_mod_evhost (void);
void test_mod_expire (void);
void test_mod_indexfile (void);
void test_mod_simple_vhost (void);
void test_mod_ssi (void);
void test_mod_staticfile (void);
void test_mod_userdir (void);

int main(void) {
    chunkqueue_set_tempdirs_default(NULL, 0);

    test_mod_access();
    test_mod_alias();
    test_mod_evhost();
    test_mod_expire();
    test_mod_indexfile();
    test_mod_simple_vhost();
    test_mod_ssi();
    test_mod_staticfile();
    test_mod_userdir();

    return 0;
}


#if defined(LIGHTTPD_STATIC)

#include "base_decls.h" /*(plugin *)*/

/* For static builds, plugin.c contains references to module init funcs
 * and if those modules are included in test_mod.c tests, then those
 * symbols will be missing from test_mod, so create stubs for module
 * init funcs, but rename to skip those included in test_mod.c tests. */
#define mod_access         mod_access_dup
#define mod_alias          mod_alias_dup
#define mod_evhost         mod_evhost_dup
#define mod_expire         mod_expire_dup
#define mod_indexfile      mod_indexfile_dup
#define mod_simple_vhost   mod_simple_vhost_dup
#define mod_ssi            mod_ssi_dup
#define mod_staticfile     mod_staticfile_dup
#define mod_userdir        mod_userdir_dup

/* macro renaming above would not be needed with weak symbols,
 * but this works on platforms without support for weak symbols */
#define PLUGIN_INIT_EXPAND(x) \
        int x ## _plugin_init(plugin *p); \
        int x ## _plugin_init(plugin *p) { UNUSED(p); return 0; }
#define PLUGIN_INIT(x) \
        PLUGIN_INIT_EXPAND(x)

#include "plugin-static.h"

#undef PLUGIN_INIT
#undef PLUGIN_INIT_EXPAND

#endif /* LIGHTTPD_STATIC */
