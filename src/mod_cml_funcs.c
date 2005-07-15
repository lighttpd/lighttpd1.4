#include <sys/stat.h>
#include <time.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>

#include "buffer.h"
#include "server.h"
#include "log.h"
#include "plugin.h"
#include "response.h"

#include "mod_cml.h"
#include "mod_cml_funcs.h"

#ifdef USE_OPENSSL
# include <openssl/md5.h>
#else
# include "md5_global.h"
# include "md5.h"
#endif

#define HASHLEN 16
typedef unsigned char HASH[HASHLEN];
#define HASHHEXLEN 32
typedef char HASHHEX[HASHHEXLEN+1];
#ifdef USE_OPENSSL
#define IN const
#else
#define IN 
#endif
#define OUT

#ifdef HAVE_LUA_H

int f_crypto_md5(lua_State *L) {
	MD5_CTX Md5Ctx;
	HASH HA1;
	buffer b;
	char hex[33];
	int n = lua_gettop(L);
	
	b.ptr = hex;
	b.used = 0;
	b.size = sizeof(hex);
	
	if (n != 1) {
		lua_pushstring(L, "expected one argument");
		lua_error(L);
	}
	
	if (!lua_isstring(L, 1)) {
		lua_pushstring(L, "argument has to be a string");
		lua_error(L);
	}
	
	MD5_Init(&Md5Ctx);
	MD5_Update(&Md5Ctx, (unsigned char *)lua_tostring(L, 1), lua_strlen(L, 1));
	MD5_Final(HA1, &Md5Ctx);
	
	buffer_copy_string_hex(&b, (char *)HA1, 16);
	
	lua_pushstring(L, b.ptr);
	
	return 1;
}


int f_file_mtime(lua_State *L) {
	struct stat st;
	int n = lua_gettop(L);
	
	if (n != 1) {
		lua_pushstring(L, "expected one argument");
		lua_error(L);
	}
	
	if (!lua_isstring(L, 1)) {
		lua_pushstring(L, "argument has to be a string");
		lua_error(L);
	}
	
	if (-1 == stat(lua_tostring(L, 1), &st)) {
		lua_pushstring(L, "stat failed");
		lua_error(L);
	}
	
	lua_pushnumber(L, st.st_mtime);
	
	return 1;
}

#ifdef HAVE_MEMCACHE_H
int f_memcache_exists(lua_State *L) {
	char *r;
	int n = lua_gettop(L);
	struct memcache *mc;
	
	if (!lua_islightuserdata(L, lua_upvalueindex(1))) {
		lua_pushstring(L, "where is my userdata ?");
		lua_error(L);
	}
	
	mc = lua_touserdata(L, lua_upvalueindex(1));
	
	if (n != 1) {
		lua_pushstring(L, "expected one argument");
		lua_error(L);
	}
	
	if (!lua_isstring(L, 1)) {
		lua_pushstring(L, "argument has to be a string");
		lua_error(L);
	}
	
	if (NULL == (r = mc_aget(mc, 
				 lua_tostring(L, 1), lua_strlen(L, 1)))) {
				
		lua_pushboolean(L, 0);
		return 1;
	}
	
	free(r);
	
	lua_pushboolean(L, 1);
	return 1;
}

int f_memcache_get_string(lua_State *L) {
	char *r;
	int n = lua_gettop(L);
	
	struct memcache *mc;
	
	if (!lua_islightuserdata(L, lua_upvalueindex(1))) {
		lua_pushstring(L, "where is my userdata ?");
		lua_error(L);
	}
	
	mc = lua_touserdata(L, lua_upvalueindex(1));
	
	
	if (n != 1) {
		lua_pushstring(L, "expected one argument");
		lua_error(L);
	}
	
	if (!lua_isstring(L, 1)) {
		lua_pushstring(L, "argument has to be a string");
		lua_error(L);
	}
	
	if (NULL == (r = mc_aget(mc, 
				 lua_tostring(L, 1), lua_strlen(L, 1)))) {
		lua_pushnil(L);
		return 1;
	}
	
	lua_pushstring(L, r);
	
	free(r);
	
	return 1;
}

int f_memcache_get_long(lua_State *L) {
	char *r;
	int n = lua_gettop(L);
	
	struct memcache *mc;
	
	if (!lua_islightuserdata(L, lua_upvalueindex(1))) {
		lua_pushstring(L, "where is my userdata ?");
		lua_error(L);
	}
	
	mc = lua_touserdata(L, lua_upvalueindex(1));
	
	
	if (n != 1) {
		lua_pushstring(L, "expected one argument");
		lua_error(L);
	}
	
	if (!lua_isstring(L, 1)) {
		lua_pushstring(L, "argument has to be a string");
		lua_error(L);
	}
	
	if (NULL == (r = mc_aget(mc, 
				 lua_tostring(L, 1), lua_strlen(L, 1)))) {
		lua_pushnil(L);
		return 1;
	}
	
	lua_pushnumber(L, strtol(r, NULL, 10));
	
	free(r);
	
	return 1;
}
#endif

#endif
