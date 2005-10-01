#!/bin/sh

## get some parameters from the makefile

export srcdir=$1
export top_builddir=$2
export SHELL

$3
