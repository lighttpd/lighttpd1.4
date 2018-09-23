#include "first.h"

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "array.h"
#include "buffer.h"

static void test_array_get_int_ptr (void) {
    data_integer *di;
    int *i;
    array *a = array_init();

    i = array_get_int_ptr(a, CONST_STR_LEN("abc"));
    assert(NULL != i);
    *i = 4;
    i = array_get_int_ptr(a, CONST_STR_LEN("abc"));
    assert(NULL != i);
    assert(*i == 4);
    di = (data_integer *)array_get_element_klen(a, CONST_STR_LEN("does-not-exist"));
    assert(NULL == di);
    di = (data_integer *)array_get_element_klen(a, CONST_STR_LEN("abc"));
    assert(NULL != di);
    assert(di->value == 4);

    array_free(a);
}

static void test_array_insert_value (void) {
    data_string *ds;
    array *a = array_init();

    array_insert_value(a, CONST_STR_LEN("def"));
    ds = (data_string *)a->data[0];
    assert(NULL != ds);
    assert(buffer_is_equal_string(ds->value, CONST_STR_LEN("def")));

    array_free(a);
}

static void test_array_insert_key_value (void) {
    data_string *ds;
    array *a = array_init();

    array_insert_key_value(a, CONST_STR_LEN("abc"), CONST_STR_LEN("alfrag"));
    ds = (data_string *)array_get_element_klen(a, CONST_STR_LEN("does-not-exist"));
    assert(NULL == ds);
    ds = (data_string *)array_get_element_klen(a, CONST_STR_LEN("abc"));
    assert(NULL != ds);
    assert(buffer_is_equal_string(ds->key, CONST_STR_LEN("abc")));
    assert(buffer_is_equal_string(ds->value, CONST_STR_LEN("alfrag")));

    array_insert_key_value(a, CONST_STR_LEN("abc"), CONST_STR_LEN("hameplman"));
    ds = (data_string *)array_get_element_klen(a, CONST_STR_LEN("does-not-exist"));
    assert(NULL == ds);
    ds = (data_string *)array_get_element_klen(a, CONST_STR_LEN("abc"));
    assert(NULL != ds);
    assert(buffer_is_equal_string(ds->key, CONST_STR_LEN("abc")));
    assert(buffer_is_equal_string(ds->value, CONST_STR_LEN("alfrag, hameplman")));

    array_insert_key_value(a, CONST_STR_LEN("123"), CONST_STR_LEN("alfrag"));
    ds = (data_string *)array_get_element_klen(a, CONST_STR_LEN("does-not-exist"));
    assert(NULL == ds);
    ds = (data_string *)array_get_element_klen(a, CONST_STR_LEN("123"));
    assert(NULL != ds);
    assert(buffer_is_equal_string(ds->key, CONST_STR_LEN("123")));
    assert(buffer_is_equal_string(ds->value, CONST_STR_LEN("alfrag")));

    array_free(a);
}

static void test_array_set_key_value (void) {
    data_string *ds;
    array *a = array_init();

    array_set_key_value(a, CONST_STR_LEN("abc"), CONST_STR_LEN("def"));
    ds = (data_string *)array_get_element_klen(a, CONST_STR_LEN("does-not-exist"));
    assert(NULL == ds);
    ds = (data_string *)array_get_element_klen(a, CONST_STR_LEN("abc"));
    assert(NULL != ds);
    assert(buffer_is_equal_string(ds->key, CONST_STR_LEN("abc")));
    assert(buffer_is_equal_string(ds->value, CONST_STR_LEN("def")));

    array_set_key_value(a, CONST_STR_LEN("abc"), CONST_STR_LEN("ghi"));
    ds = (data_string *)array_get_element_klen(a, CONST_STR_LEN("does-not-exist"));
    assert(NULL == ds);
    ds = (data_string *)array_get_element_klen(a, CONST_STR_LEN("abc"));
    assert(NULL != ds);
    assert(buffer_is_equal_string(ds->key, CONST_STR_LEN("abc")));
    assert(buffer_is_equal_string(ds->value, CONST_STR_LEN("ghi")));

    array_free(a);
}

int main() {
    test_array_get_int_ptr();
    test_array_insert_value();
    test_array_insert_key_value();
    test_array_set_key_value();

    return 0;
}
