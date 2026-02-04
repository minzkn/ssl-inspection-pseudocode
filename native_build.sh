#!/bin/sh

make -j$(nproc) \
DEF_ENABLE_TEST_VECTOR=yes \
${*}
