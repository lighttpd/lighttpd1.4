# Compile the port for QNX

**NOTE**: QNX ports are only supported from a **Linux host** operating system

### Install dependencies

`sudo apt install automake`

`sudo apt install pkg-config`

### Generate GNU build tool ./configure and all needed Makefiles

`./autogen.sh`

### Setup QNX SDP environment

`source <path-to-sdp>/qnxsdp-env.sh`

### Build and install lighttpd binaries to SDP

`JLEVEL=$(nproc) make -C qnx/build install`

**All binary files have to be installed to SDP**
* $QNX_TARGET/x86_64/usr/local/lib/mod_*.so
* $QNX_TARGET/x86_64/usr/local/sbin/lighttpd
* $QNX_TARGET/x86_64/usr/local/sbin/lighttpd-angel
* $QNX_TARGET/aarch64le/usr/local/lib/mod_*.so
* $QNX_TARGET/aarch64le/usr/local/sbin/lighttpd
* $QNX_TARGET/aarch64le/usr/local/sbin/lighttpd-angel

### Build and install lighttpd binaries to specific path

`JLEVEL=$(nproc) make -C qnx/build install USE_INSTALL_ROOT=true INSTALL_ROOT_nto=<full-path>`

**All binary files have to be installed to specific path**
* \<full-path\>/x86_64/usr/local/lib/mod_*.so
* \<full-path\>/x86_64/usr/local/sbin/lighttpd
* \<full-path\>/x86_64/usr/local/sbin/lighttpd-angel
* \<full-path\>/aarch64le/usr/local/lib/mod_*.so
* \<full-path\>/aarch64le/usr/local/sbin/lighttpd
* \<full-path\>/aarch64le/usr/local/sbin/lighttpd-angel
