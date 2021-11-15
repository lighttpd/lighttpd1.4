#include "first.h"

#undef NDEBUG
#include <assert.h>

void test_array (void);
void test_base64 (void);
void test_buffer (void);
void test_burl (void);
void test_keyvalue (void);
void test_request (void);

int main() {
    test_array();
    test_base64();
    test_buffer();
    test_burl();
    test_keyvalue();
    test_request();

    return 0;
}
