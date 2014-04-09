#
# liballium Makefile.am
# Yawning Angel (yawning at schwanenlied dot me)
#

AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

AM_CFLAGS = -Wall -Werror -Wextra

lib_LTLIBRARIES = liballium-@ALLIUM_API_VERSION@.la

liballium_@ALLIUM_API_VERSION@_la_CPPFLAGS = -I$(srcdir)/include
liballium_@ALLIUM_API_VERSION@_la_SOURCES = src/bstrlib.c \
	src/allium_ptcfg.c \
	src/allium_util.c

liballium_@ALLIUM_API_VERSION@_la_LDFLAGS = -version-info $(ALLIUM_SO_VERSION)

liballiumincludedir = ${includedir}/allium
liballiuminclude_HEADERS = include/allium.h \
	include/allium_ptcfg.h \
	include/bstrlib.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = liballium-$(ALLIUM_API_VERSION).pc

TESTS = ptcfg_test

check_PROGRAMS = ptcfg_test

ptcfg_test_CPPFLAGS = -I$(srcdir)/include
ptcfg_test_LDADD = $(top_builddir)/liballium-@ALLIUM_API_VERSION@.la
ptcfg_test_SOURCES = tests/ptcfg_test.c

dist_noinst_SCRIPTS = autogen.sh
