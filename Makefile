#
#   Copyright (C) 2018 MINZKN.COM
#   All rights reserved.
#
#   Maintainers
#     JaeHyuk Cho <mailto:minzkn@minzkn.com>
#

# 본 Makefile 구현은 Parallel build 를 완전하게 지원합니다. (의존관계를 100% 풀어서 빌드되도록 고려되어 있습니다.)
# make -j<jobs>

# .EXPORT_ALL_VARIABLES: # DO NOT USE !
MAKEFLAGS                    ?=#
export MAKEFLAGS

DEF_ENABLE_DPDK_LCORE :=no#
DEF_ENABLE_TEST_VECTOR :=yes#

SHELL_BASH :=$(wildcard /bin/bash)#
ifneq ($(SHELL_BASH),)
SHELL :=$(SHELL_BASH)# bash shell default using
else
SHELL ?=/bin/sh#
endif
MAKE ?=make#

# .EXPORT_ALL_VARIABLES: # DO NOT USE !
MAKEFLAGS                    ?=#
export MAKEFLAGS
export PATH

HOST_NAME :=$(shell hostname --short)#
HOST_USER :=$(shell whoami)#
HOST_ARCH :=$(shell echo "$(shell uname -m)" | sed \
    -e s/sun4u/sparc64/ \
    -e s/arm.*/arm/ \
    -e s/sa110/arm/ \
    -e s/s390x/s390/ \
    -e s/parisc64/parisc/ \
    -e s/ppc.*/powerpc/ \
    -e s/mips.*/mips/ \
)# auto detect architecture
HOST_OS :=$(shell echo "$(shell uname)" | sed \
    -e  s/Linux/linux/ \
    -e  s/Darwin/darwin/ \
)# auto detect os
HOST_VENDOR :=pc#
HOST_LIBC :=gnu#
HOST_LABEL :=$(HOST_ARCH)#
HOST_BUILD_PROFILE :=$(HOST_ARCH)-$(HOST_VENDOR)-$(HOST_OS)-$(HOST_LIBC)#

TARGET_ARCH :=$(HOST_ARCH)#
TARGET_VENDOR :=$(HOST_VENDOR)#
TARGET_OS :=$(HOST_OS)#
TARGET_LIBC :=$(HOST_LIBC)#
TARGET_LABEL :=$(TARGET_ARCH)#
TARGET_BUILD_PROFILE :=$(TARGET_ARCH)-$(TARGET_VENDOR)-$(TARGET_OS)-$(TARGET_LIBC)#

PKGCONF ?= pkg-config#

EXT_DEPEND :=.d#
EXT_C_SOURCE :=.c#
EXT_CXX_SOURCE :=.cpp#
EXT_C_HEADER :=.h#
EXT_CXX_HEADER :=.h#
EXT_OBJECT :=.o#
EXT_LINK_OBJECT :=.lo#
EXT_ARCHIVE :=.a#
EXT_SHARED :=.so#
EXT_EXEC :=#
EXT_CONFIG :=.conf#

KERNEL_DIR ?=$(KERNEL_PATH)#

CROSS_COMPILE :=#

ECHO :=echo#
SYMLINK :=ln -sf#
SED :=sed#
INSTALL :=install#
INSTALL_BIN :=$(INSTALL) -m0755#
INSTALL_LIB :=$(INSTALL) -m0755#
INSTALL_DIR :=$(INSTALL) -d -m0755#
INSTALL_DATA :=$(INSTALL) -m0644#
INSTALL_CONF :=$(INSTALL) -m0644#

CC :=$(CROSS_COMPILE)gcc#
CPP :=$(CROSS_COMPILE)gcc -E#
LD :=$(CROSS_COMPILE)ld#
AR :=$(CROSS_COMPILE)ar#
RM :=rm -f#
RMDIR :=rm -rf#
COPY_FILE :=cp -f#
CAT :=cat#
TOUCH :=touch#
STRIP :=$(CROSS_COMPILE)strip#

THIS_NAME :=sslid#
THIS_VERSION :=2.0#

DESTDIR :=./rootfs# default staging directory
CFLAGS_COMMON :=#
CFLAGS :=#
LDFLAGS_COMMON :=#
LDFLAGS :=#
LDFLAGS_EXEC :=-rdynamic -fPIE -pie#
LDFLAGS_SHARED_COMMON :=#
LDFLAGS_SHARED_LINK :=#
LDFLAGS_SHARED :=#
ARFLAGS_COMMON :=#
ARFLAGS :=#

CFLAGS_COMMON +=-O2#
#CFLAGS_COMMON +=-g# For GDB
CFLAGS_COMMON +=-pipe#
CFLAGS_COMMON +=-fPIC#
#CFLAGS_COMMON +=-fomit-frame-pointer# backtrace() daes not work !
CFLAGS_COMMON +=-fno-omit-frame-pointer# backtrace() will work normally.
#CFLAGS_COMMON +=-ansi#
CFLAGS_COMMON +=-Wall -W#
CFLAGS_COMMON +=-Wshadow#
CFLAGS_COMMON +=-Wcast-qual#
CFLAGS_COMMON +=-Wcast-align#
CFLAGS_COMMON +=-Wpointer-arith#
CFLAGS_COMMON +=-Wbad-function-cast#
CFLAGS_COMMON +=-Wstrict-prototypes#
CFLAGS_COMMON +=-Wmissing-prototypes#
CFLAGS_COMMON +=-Wmissing-declarations#
CFLAGS_COMMON +=-Wnested-externs#
CFLAGS_COMMON +=-Winline#
CFLAGS_COMMON +=-Wwrite-strings#
CFLAGS_COMMON +=-Wchar-subscripts#
CFLAGS_COMMON +=-Wformat#
CFLAGS_COMMON +=-Wformat-security#
CFLAGS_COMMON +=-Wimplicit#
CFLAGS_COMMON +=-Wmain#
CFLAGS_COMMON +=-Wmissing-braces#
CFLAGS_COMMON +=-Wparentheses#
CFLAGS_COMMON +=-Wredundant-decls#
CFLAGS_COMMON +=-Wreturn-type#
CFLAGS_COMMON +=-Wsequence-point#
CFLAGS_COMMON +=-Wsign-compare#
CFLAGS_COMMON +=-Wswitch#
CFLAGS_COMMON +=-Wuninitialized#
CFLAGS_COMMON +=-Wunknown-pragmas#
CFLAGS_COMMON +=-Wcomment#
CFLAGS_COMMON +=-Wundef#
CFLAGS_COMMON +=-Wunused#
#CFLAGS_COMMON +=-Wunreachable-code#
#CFLAGS_COMMON +=-Wconversion#
#CFLAGS_COMMON +=-Wpadded#

#CFLAGS_COMMON +=-Wno-deprecated-declarations# For OpenSSL deprecated warning disable option

CFLAGS_COMMON +=-I./include -I.#
ifneq ($(STAGING_DIR),)
CFLAGS_COMMON +=-I$(STAGING_DIR)/usr/include# buildroot로 빌드하는 경우
endif

ifneq ($(shell $(PKGCONF) --exists openssl && echo 0),0)
$(warning "no installation of openssl found (PKGCONF)")
else
CFLAGS_COMMON += $(shell $(PKGCONF) --cflags openssl)#
endif

ifeq ($(DEF_ENABLE_DPDK_LCORE),yes)
ifneq ($(shell $(PKGCONF) --exists libdpdk && echo 0),0)
$(error "no installation of libdpdk found")
else
CFLAGS_COMMON += $(shell $(PKGCONF) --cflags libdpdk)#
CFLAGS_COMMON += -Ddef_sslid_use_dpdk_lcore=1#
endif
endif

CFLAGS_COMMON +=-D_REENTRANT# thread safety (optional)
CFLAGS_COMMON +=-D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64# enable 64-bits file i/o compatibility (optional)
CFLAGS_COMMON +=-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0# glibc run-time compatibility compile (optional)

ifeq ($(DEF_ENABLE_TEST_VECTOR),yes)
CFLAGS_COMMON +=-Ddef_sslid_test_vector=1#
else
CFLAGS_COMMON +=-Udef_sslid_test_vector#
endif

LDFLAGS_SHARED_COMMON +=-L.#
ifneq ($(STAGING_DIR),)
LDFLAGS_SHARED_COMMON +=-L$(STAGING_DIR)/lib# buildroot로 빌드하는 경우
LDFLAGS_SHARED_COMMON +=-L$(STAGING_DIR)/usr/lib# buildroot로 빌드하는 경우
endif
LDFLAGS +=-s#

ARFLAGS_COMMON +=rcs#

TARGET :=$(THIS_NAME)$(EXT_EXEC)# executable shared object

# default make goal
.PHONY: all world rebuild install
all world: __build_all
rebuild: clean all

install: all
	@$(ECHO) "[**] installing (DESTDIR=\"$(DESTDIR)\")"
	@$(INSTALL_DIR) "$(DESTDIR)/"
	@$(INSTALL_DIR) "$(DESTDIR)/usr/"
	@$(INSTALL_DIR) "$(DESTDIR)/usr/bin/"
	@$(INSTALL_BIN) "$(THIS_NAME)" "$(DESTDIR)/usr/bin/"
	@$(ECHO) "[**] installed (DESTDIR=\"$(DESTDIR)\")"

# clean project
.PHONY: distclean clean
distclean: clean
clean:
	@$(ECHO) "[**] $(@)"
	@$(RM) $(wildcard *$(EXT_OBJECT) *$(EXT_DEPEND) *$(EXT_LINK_OBJECT) *$(EXT_ARCHIVE) *$(EXT_SHARED) *$(EXT_SHARED).*) $(TARGET)
ifneq ($(wildcard ./rootfs),)
	@$(RMDIR) ./rootfs
endif

# real build depend
.PHONY: __build_all
__build_all: $(TARGET)
	@$(ECHO) "[**] build complete ($(^))"
	$(if $(THIS_VERSION),@$(ECHO) "   - THIS_VERSION=\"$(THIS_VERSION)\"")
	$(if $(HOST_BUILD_PROFILE),@$(ECHO) "   - HOST_BUILD_PROFILE=\"$(HOST_BUILD_PROFILE)\"")
	$(if $(TARGET_BUILD_PROFILE),@$(ECHO) "   - TARGET_BUILD_PROFILE=\"$(TARGET_BUILD_PROFILE)\"")
	$(if $(CROSS_COMPILE),@$(ECHO) "   - CROSS_COMPILE=\"$(CROSS_COMPILE)\"")
	$(if $(strip $(CFLAGS_COMMON) $(CFLAGS)),@$(ECHO) "   - CFLAGS=\"$(strip $(CFLAGS_COMMON) $(CFLAGS))\"")
	$(if $(strip $(LDFLAGS_COMMON) $(LDFLAGS)),@$(ECHO) "   - LDFLAGS=\"$(strip $(LDFLAGS_COMMON) $(LDFLAGS))\"")
	$(if $(strip $(LDFLAGS_EXEC)),@$(ECHO) "   - LDFLAGS_EXEC=\"$(strip $(LDFLAGS_EXEC) $(LDFLAGS_SHARED_LINK))\"")
	$(if $(strip $(LDFLAGS_SHARED_COMMON) $(LDFLAGS_SHARED)),@$(ECHO) "   - LDFLAGS_SHARED=\"$(strip $(LDFLAGS_SHARED_COMMON) $(LDFLAGS_SHARED) $(LDFLAGS_SHARED_LINK))\"")
	$(if $(strip $(ARFLAGS_COMMON) $(ARFLAGS)),@$(ECHO) "   - ARFLAGS=\"$(strip $(ARFLAGS_COMMON) $(ARFLAGS))\"")
	$(if $(KERNEL_PATH),@$(ECHO) "   - KERNEL_PATH=\"$(KERNEL_PATH)\"",$(if $(KERNEL_DIR),@$(ECHO) "   - KERNEL_DIR=\"$(KERNEL_DIR)\""))
	$(if $(DEF_ENABLE_DPDK_LCORE),@$(ECHO) "   - DEF_ENABLE_DPDK_LCORE=\"$(DEF_ENABLE_DPDK_LCORE)\"")
	$(if $(DEF_ENABLE_TEST_VECTOR),@$(ECHO) "   - DEF_ENABLE_TEST_VECTOR=\"$(DEF_ENABLE_TEST_VECTOR)\"")

# exec link (-fPIE -pie => shared object build)
MAIN_SOURCE_LIST_ALL :=$(notdir $(wildcard ./*$(EXT_C_SOURCE)))# auto detect source all
MAIN_SOURCE_LIST_EXCLUDE :=# exclude source
MAIN_SOURCE_LIST :=$(if $(MAIN_SOURCE_LIST_EXCLUDE),$(filter-out $(MAIN_SOURCE_LIST_EXCLUDE),$(MAIN_SOURCE_LIST_ALL)),$(MAIN_SOURCE_LIST_ALL))# auto detect source with filter-out
MAIN_OBJECTS :=$(MAIN_SOURCE_LIST:%$(EXT_C_SOURCE)=%$(EXT_OBJECT))# auto generate object by source
ifneq ($(shell $(PKGCONF) --exists openssl && echo 0),0)
$(THIS_NAME)$(EXT_EXEC): LDFLAGS_SHARED_LINK+=-lssl -lcrypto
else
$(THIS_NAME)$(EXT_EXEC): LDFLAGS_SHARED_LINK+=$(shell $(PKGCONF) --libs openssl)#
endif
ifeq ($(DEF_ENABLE_DPDK_LCORE),yes)
ifneq ($(shell $(PKGCONF) --exists libdpdk && echo 0),0)
$(error "no installation of libdpdk found")
else
$(THIS_NAME)$(EXT_EXEC): LDFLAGS_SHARED_LINK+=$(shell $(PKGCONF) --libs libdpdk)#
endif
endif
$(THIS_NAME)$(EXT_EXEC): LDFLAGS_SHARED_LINK+=-lpthread -ldl
$(THIS_NAME)$(EXT_EXEC): $(MAIN_OBJECTS)
	@$(ECHO) "[LD] $(notdir $(@)) <= $(notdir $(^)) (LDFLAGS=\"$(strip $(LDFLAGS_SHARED_COMMON) $(LDFLAGS_SHARED) $(LDFLAGS_COMMON) $(LDFLAGS) $(LDFLAGS_EXEC) $(LDFLAGS_SHARED_LINK))\")"
	@$(CC) $(LDFLAGS_SHARED_COMMON) $(LDFLAGS_SHARED) $(LDFLAGS_COMMON) $(LDFLAGS) $(LDFLAGS_EXEC) -o "$(@)" $(^) $(LDFLAGS_SHARED_LINK)
	@$(STRIP) --remove-section=.comment --remove-section=.note $(@) # strong strip (optional)
$(MAIN_OBJECTS): CFLAGS_COMMON+=-fPIE

# common compile
%$(EXT_OBJECT): ./%$(EXT_C_SOURCE) Makefile
	@$(ECHO) "[CC] $(notdir $(@)) <= $(notdir $(<))"
	@$(CC) $(CFLAGS_COMMON) $(CFLAGS) -c -o "$(@)" "$(<)"
	@$(CC) -MMD $(CFLAGS_COMMON) $(CFLAGS) -c -o "$(@)" "$(<)" # create depend rule file (strong depend check, optional)

# include depend rules (strong depend check, optional)
override THIS_DEPEND_RULES_LIST:=$(wildcard *$(EXT_DEPEND))#
ifneq ($(THIS_DEPEND_RULES_LIST),)
sinclude $(THIS_DEPEND_RULES_LIST)
endif

.DEFAULT:
	@$(ECHO) "[!!] unknown goal ($(@))"

# vim:set noexpandtab tabstop=4 shiftwidth=4 softtabstop=4 autoindent cindent smarttab fileencoding=utf8:
# End of Makefile
