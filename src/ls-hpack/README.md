[![Build Status](https://travis-ci.com/litespeedtech/ls-hpack.svg?branch=master)](https://travis-ci.com/litespeedtech/ls-hpack)
[![Build Status](https://api.cirrus-ci.com/github/litespeedtech/ls-hpack.svg)](https://cirrus-ci.com/github/litespeedtech/ls-hpack)
[![Build status](https://ci.appveyor.com/api/projects/status/6ev71ecmm3j2u9o5?svg=true)](https://ci.appveyor.com/project/litespeedtech/ls-hpack)

LS-HPACK: LiteSpeed HPACK Library
=================================

Description
-----------

LS-HPACK provides functionality to encode and decode HTTP headers using
HPACK compression mechanism specified in RFC 7541.

Documentation
-------------

The API is documented in include/lshpack.h.  To see usage examples,
see the unit tests.

Requirements
------------

To build LS-HPACK, you need CMake.  The library uses XXHASH at runtime.

Platforms
---------

The library has been tested on the following platforms:
- Linux
- FreeBSD
- Windows

Copyright (c) 2018 - 2020 LiteSpeed Technologies Inc
