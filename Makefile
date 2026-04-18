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

DEF_ENABLE_ZLIB_BUILD :=no# yes or no
ifeq ($(DEF_ENABLE_ZLIB_BUILD),yes)
DEF_PATH_ZLIB :=./zlib-1.2.11#
endif

DEF_ENABLE_OPENSSL_BUILD :=yes# yes or no
ifeq ($(DEF_ENABLE_OPENSSL_BUILD),yes)
DEF_PATH_OPENSSL :=./openssl-1.1.1w#
#DEF_PATH_OPENSSL :=./openssl-3.2.0# TODO
endif

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
THIS_VERSION :=1.0# wlogs version

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
#CFLAGS_COMMON +=-g#
CFLAGS_COMMON +=-pipe#
CFLAGS_COMMON +=-fPIC#
#CFLAGS_COMMON +=-fomit-frame-pointer# backtrace() daes not work !
CFLAGS_COMMON +=-fno-omit-frame-pointer# backtrace() will work normally.
CFLAGS_COMMON +=-ansi# logv2.h is not standard C code
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
##CFLAGS_COMMON +=-Wunreachable-code#
CFLAGS_COMMON +=-Wconversion#
##CFLAGS_COMMON +=-Wpadded#
CFLAGS_COMMON +=-I./include -I.#
ifneq ($(STAGING_DIR),)
CFLAGS_COMMON +=-I$(STAGING_DIR)/usr/include# buildroot로 빌드하는 경우
else
# BEGIN: buildroot가 아닌 직접 빌드 하는 경우 이 부분에서 Header include 경로를 맞춰주세요.
ifneq ($(wildcard ../../../staging_dir/target-x86_64_glibc-2.23/usr/include),)
CFLAGS_COMMON +=-I../../../staging_dir/target-x86_64_glibc-2.23/usr/include# buildroot 빌드 후 직접 local 빌드하 가능하도록
endif
# END: buildroot가 아닌 직접 빌드 하는 경우 이 부분에서 Header include 경로를 맞춰주세요.
endif
ifneq ($(KERNEL_DIR),)
CFLAGS_COMMON +=-I$(KERNEL_DIR)/include/future/log# buildroot로 빌드하는 경우
else
ifneq ($(wildcard ../kernel),)
CFLAGS_COMMON +=-I../kernel/include/future/log# buildroot 빌드 후 직접 local 빌드하 가능하도록
endif
endif
ifeq ($(DEF_ENABLE_ZLIB_BUILD),yes)
CFLAGS_COMMON +=-I$(DEF_PATH_ZLIB)/include#
CFLAGS_COMMON +=-I$(DEF_PATH_ZLIB)#
endif
ifeq ($(DEF_ENABLE_OPENSSL_BUILD),yes)
CFLAGS_COMMON +=-I$(DEF_PATH_OPENSSL)/include#
CFLAGS_COMMON +=-I$(DEF_PATH_OPENSSL)/ssl#
CFLAGS_COMMON +=-I$(DEF_PATH_OPENSSL)#
endif
CFLAGS_COMMON +=-D_REENTRANT# thread safety (optional)
CFLAGS_COMMON +=-D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64# enable 64-bits file i/o compatibility (optional)
CFLAGS_COMMON +=-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0# glibc run-time compatibility compile (optional)

LDFLAGS_SHARED_COMMON +=-L.#
ifneq ($(STAGING_DIR),)
LDFLAGS_SHARED_COMMON +=-L$(STAGING_DIR)/lib# buildroot로 빌드하는 경우
LDFLAGS_SHARED_COMMON +=-L$(STAGING_DIR)/usr/lib# buildroot로 빌드하는 경우
else
# BEGIN: buildroot가 아닌 직접 빌드 하는 경우 이 부분에서 Library link 경로를 맞춰주세요.
ifneq ($(wildcard ../../../staging_dir/target-x86_64_glibc-2.23/usr/lib),)
LDFLAGS_SHARED_COMMON +=-L../../../staging_dir/target-x86_64_glibc-2.23/lib# buildroot 빌드 후 직접 local 빌드하 가능하도록
LDFLAGS_SHARED_COMMON +=-L../../../staging_dir/target-x86_64_glibc-2.23/usr/lib# buildroot 빌드 후 직접 local 빌드하 가능하도록
endif
# END: buildroot가 아닌 직접 빌드 하는 경우 이 부분에서 Library link 경로를 맞춰주세요.
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
	$(if $(TARGET_BUILD_PROFILE),@$(ECHO) "   - TARGET_BUILD_PROFILE=\"$(TARGET_BUILD_PROFILE)\"")
	$(if $(CROSS_COMPILE),@$(ECHO) "   - CROSS_COMPILE=\"$(CROSS_COMPILE)\"")
	$(if $(strip $(CFLAGS_COMMON) $(CFLAGS)),@$(ECHO) "   - CFLAGS=\"$(strip $(CFLAGS_COMMON) $(CFLAGS))\"")
	$(if $(strip $(LDFLAGS_COMMON) $(LDFLAGS)),@$(ECHO) "   - LDFLAGS=\"$(strip $(LDFLAGS_COMMON) $(LDFLAGS))\"")
	$(if $(strip $(LDFLAGS_EXEC)),@$(ECHO) "   - LDFLAGS_EXEC=\"$(strip $(LDFLAGS_EXEC) $(LDFLAGS_SHARED_LINK))\"")
	$(if $(strip $(LDFLAGS_SHARED_COMMON) $(LDFLAGS_SHARED)),@$(ECHO) "   - LDFLAGS_SHARED=\"$(strip $(LDFLAGS_SHARED_COMMON) $(LDFLAGS_SHARED) $(LDFLAGS_SHARED_LINK))\"")
	$(if $(strip $(ARFLAGS_COMMON) $(ARFLAGS)),@$(ECHO) "   - ARFLAGS=\"$(strip $(ARFLAGS_COMMON) $(ARFLAGS))\"")
	$(if $(KERNEL_PATH),@$(ECHO) "   - KERNEL_PATH=\"$(KERNEL_PATH)\"",$(if $(KERNEL_DIR),@$(ECHO) "   - KERNEL_DIR=\"$(KERNEL_DIR)\""))
	$(if $(DEF_ENABLE_ZLIB_BUILD),@$(ECHO) "   - DEF_ENABLE_ZLIB_BUILD=\"$(DEF_ENABLE_ZLIB_BUILD)\"")
	$(if $(DEF_ENABLE_OPENSSL_BUILD),@$(ECHO) "   - DEF_ENABLE_OPENSSL_BUILD=\"$(DEF_ENABLE_OPENSSL_BUILD)\"")

# exec link (-fPIE -pie => shared object build)
MAIN_SOURCE_LIST_ALL :=$(notdir $(wildcard ./*$(EXT_C_SOURCE)))# auto detect source all
MAIN_SOURCE_LIST_EXCLUDE :=# exclude source
MAIN_SOURCE_LIST :=$(if $(MAIN_SOURCE_LIST_EXCLUDE),$(filter-out $(MAIN_SOURCE_LIST_EXCLUDE),$(MAIN_SOURCE_LIST_ALL)),$(MAIN_SOURCE_LIST_ALL))# auto detect source with filter-out
MAIN_OBJECTS :=$(MAIN_SOURCE_LIST:%$(EXT_C_SOURCE)=%$(EXT_OBJECT))# auto generate object by source
ifeq ($(DEF_ENABLE_OPENSSL_BUILD),yes)
MAIN_OBJECTS +=$(DEF_PATH_OPENSSL)/libssl.a $(DEF_PATH_OPENSSL)/libcrypto.a#
else
$(THIS_NAME)$(EXT_EXEC): LDFLAGS_SHARED_LINK+=-lssl -lcrypto
endif
ifeq ($(DEF_ENABLE_ZLIB_BUILD),yes)
MAIN_OBJECTS +=$(DEF_PATH_ZLIB)/libz.a#
else
$(THIS_NAME)$(EXT_EXEC): LDFLAGS_SHARED_LINK+=-lz
endif
$(THIS_NAME)$(EXT_EXEC): LDFLAGS_SHARED_LINK+=-lpthread -ldl
$(THIS_NAME)$(EXT_EXEC): $(MAIN_OBJECTS)
	@$(ECHO) "[LD] $(notdir $(@)) <= $(notdir $(^)) (LDFLAGS=\"$(strip $(LDFLAGS_SHARED_COMMON) $(LDFLAGS_SHARED) $(LDFLAGS_COMMON) $(LDFLAGS) $(LDFLAGS_EXEC) $(LDFLAGS_SHARED_LINK))\")"
	@$(CC) $(LDFLAGS_SHARED_COMMON) $(LDFLAGS_SHARED) $(LDFLAGS_COMMON) $(LDFLAGS) $(LDFLAGS_EXEC) -o "$(@)" $(^) $(LDFLAGS_SHARED_LINK)
	@$(STRIP) --remove-section=.comment --remove-section=.note $(@) # strong strip (optional)
$(MAIN_OBJECTS): CFLAGS_COMMON+=-fPIE

ifeq ($(DEF_ENABLE_ZLIB_BUILD),yes)
.PHONY: zlib-install
install: zlib-install
zlib-install: $(DEF_PATH_ZLIB)/.build-zlib
	@$(ECHO) "[**] installing... ($(@))"
	@$(MAKE) --directory "$(DEF_PATH_ZLIB)" --no-print-directory DESTDIR="$(abspath $(DESTDIR))" install > /dev/null
$(DEF_PATH_ZLIB)/libz.a: $(DEF_PATH_ZLIB)/.build-zlib
$(DEF_PATH_ZLIB)/.build-zlib: $(DEF_PATH_ZLIB)/Makefile
	@$(ECHO) "[**] configuring... ($(@))"
	@cd $(DEF_PATH_ZLIB) && \
		CROSS_PREFIX="$(CROSS_COMPILE)" \
		CFLAGS="-fPIC" \
		CPPFLAGS="-D_REENTRANT -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0" \
		LDFLAGS="" \
		./configure \
			--prefix='/usr' \
			--shared \
			> /dev/null
	@$(ECHO) "[**] building... ($(@))"
	@$(MAKE) --directory "$(DEF_PATH_ZLIB)" --no-print-directory DESTDIR="$(abspath $(DESTDIR))" CC="$(CC)" LD="$(LD)" CPP="$(CPP)" all > /dev/null
	@$(TOUCH) "$(@)"
.PHONY: zlib-clean
clean: zlib-clean
zlib-clean:
	@$(ECHO) "[**] clean ($(@))"
ifneq ($(wildcard $(DEF_PATH_ZLIB)/Makefile),)
	@$(MAKE) --directory "$(DEF_PATH_ZLIB)" --no-print-directory distclean > /dev/null
	@$(RM) $(DEF_PATH_ZLIB)/.build-zlib
endif
endif

ifeq ($(DEF_ENABLE_OPENSSL_BUILD),yes)
.PHONY: openssl-install
install: openssl-install
openssl-install: $(DEF_PATH_OPENSSL)/.build-openssl
	@$(ECHO) "[**] installing... ($(@))"
	@$(MAKE) --directory "$(DEF_PATH_OPENSSL)" --no-print-directory DESTDIR="$(abspath $(DESTDIR))" install > /dev/null
$(DEF_PATH_OPENSSL)/libssl.a $(DEF_PATH_OPENSSL)/libcrypto.a: $(DEF_PATH_OPENSSL)/.build-openssl
$(DEF_PATH_OPENSSL)/.build-openssl: $(DEF_PATH_OPENSSL)/Makefile
	@$(ECHO) "[**] depending... ($(@))"
	@$(MAKE) --directory "$(DEF_PATH_OPENSSL)" --no-print-directory DESTDIR="$(abspath $(DESTDIR))" depend > /dev/null
	@$(ECHO) "[**] building... ($(@))"
	@$(MAKE) --directory "$(DEF_PATH_OPENSSL)" --no-print-directory DESTDIR="$(abspath $(DESTDIR))" all > /dev/null
	@$(TOUCH) "$(@)"
ifeq ($(DEF_ENABLE_ZLIB_BUILD),yes)
$(DEF_PATH_OPENSSL)/Makefile: $(DEF_PATH_ZLIB)/.build-zlib
endif
$(DEF_PATH_OPENSSL)/Makefile: $(wildcard $(DEF_PATH_OPENSSL)/Configure $(DEF_PATH_OPENSSL)/configure $(DEF_PATH_OPENSSL)/config)
	@$(ECHO) "[**] configuring... ($(@))"
	@cd $(DEF_PATH_OPENSSL) && \
		./Configure \
			--prefix='/usr' \
			--openssldir='/etc/ssl' \
			--libdir='/usr/lib' \
			-D_REENTRANT \
			-D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 \
			-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
			shared threads zlib \
			$(TARGET_OS)-$(TARGET_ARCH) \
			> /dev/null
.PHONY: openssl-clean
clean: openssl-clean
openssl-clean:
	@$(ECHO) "[**] clean ($(@))"
ifneq ($(wildcard $(DEF_PATH_OPENSSL)/Makefile),)
	@$(MAKE) --directory "$(DEF_PATH_OPENSSL)" --no-print-directory distclean > /dev/null
	@$(RM) $(DEF_PATH_OPENSSL)/.build-openssl
endif
endif

# common compile
ifeq ($(DEF_ENABLE_OPENSSL_BUILD),yes)
%$(EXT_OBJECT): ./%$(EXT_C_SOURCE) Makefile $(DEF_PATH_OPENSSL)/.build-openssl
else
%$(EXT_OBJECT): ./%$(EXT_C_SOURCE) Makefile
endif	
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
