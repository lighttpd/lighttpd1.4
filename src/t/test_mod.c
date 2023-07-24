#include "first.h"

#undef NDEBUG
#include <assert.h>

#include "chunk.h"

void test_mod_access (void);
void test_mod_alias (void);
void test_mod_evhost (void);
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
    test_mod_indexfile();
    test_mod_simple_vhost();
    test_mod_ssi();
    test_mod_staticfile();
    test_mod_userdir();

    return 0;
}
