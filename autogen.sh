#!/bin/sh
# Run this to generate all the initial makefiles, etc.

set -e

autoreconf --force --install
echo "Now type './configure ...' and 'make' to compile."
