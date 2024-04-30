# Testing lighttpd1.4 web server on QNX

**NOTE**: QNX ports are only supported from a **Linux host** operating system

lighttpd web server normally wants to be tested on the same machine it was built on. This obviously doesn't work when cross-compiling for QNX. The gist is to build, then copy the whole lighttpd tests tree on a target. This will include all the relevant files and directory structure which lighttpd expects when running its test suite.

# Running the Test Suite

### Install dependencies

`sudo apt install automake`

`sudo apt install pkg-config`

### Generate GNU build tool ./configure and all needed Makefiles

`./autogen.sh`

### Setup QNX SDP environment

`source <path-to-sdp>/qnxsdp-env.sh`

### Install test dependencies (QNX8.0 only)

- Install com.qnx.qnx800.target.utils.perl QNX package to your SDP

### Build and install all lighttpd tests

`JLEVEL=$(nproc) CPULIST=x86_64 make -C qnx/build check`

or

`JLEVEL=$(nproc) CPULIST=x86_64 make -C qnx/build check USE_INSTALL_ROOT=true INSTALL_ROOT_nto=<full-path>`

### Then build your QNX image using mkqnximage and the following options:

`export LIGHTTPD_ROOT=$PWD`

`mkdir test_image && cd test_image`

`mkqnximage --extra-dirs=$LIGHTTPD_ROOT/qnx/test/mkqnximage --clean --run --force --test-lighttpd=$QNX_TARGET/x86_64/usr/local/bin/lighttpd_tests`

or

`mkqnximage --extra-dirs=$LIGHTTPD_ROOT/qnx/test/mkqnximage --clean --run --force --test-lighttpd=<full-path>/x86_64/usr/local/bin/lighttpd_tests`

### Once the target has booted, the lighttpd tests will be located in /data/lighttpd:

`cd /data/lighttpd`

`./base_testsuite.sh`

### Test execution summary

```
...
==========================================
Unit tests summary for lighttpd 1.4.73
==========================================
# TOTAL: 3
# PASS: 3
# FAIL: 0
==========================================
```

### QNX7.1
```
...
All tests successful.
Files=4, Tests=221,  0 wallclock secs ( 0.04 usr  0.00 sys +  0.46 cusr  0.00 csys =  0.50 CPU)
Result: PASS
```

### QNX8.0 ea3
```
...
All tests successful.
Files=4, Tests=221,  3 wallclock secs ( 0.05 usr  0.00 sys +  0.70 cusr  0.00 csys =  0.75 CPU)
Result: PASS
```

### QNX8.0 GA
```
...
All tests successful.
Files=4, Tests=221,  1 wallclock secs ( 0.04 usr  0.00 sys +  0.43 cusr  0.00 csys =  0.47 CPU)
Result: PASS
```
