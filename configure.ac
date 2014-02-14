#
# liballium configure.ac
# Yawning Angel (yawning at schwanenlied dot me)
#

AC_INIT([liballium],
	[0.0.1],
	[yawning at schwanenlied dot me],
	[liballium],
	[https://github.com/Yawning/liballium])
AC_PREREQ([2.69])
AM_INIT_AUTOMAKE([no-define foreign -Wall])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CC
AM_PROG_AR
LT_INIT()

# liballium requires
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([arpa/inet.h])
AC_CHECK_HEADERS([netdb.h])
AC_CHECK_HEADERS([netinet/in.h])
AC_CHECK_HEADERS([stddef.h])
AC_CHECK_FUNCS([putenv])
AC_CHECK_FUNCS([setenv])
AC_CHECK_FUNCS([getaddrinfo])
AC_CHECK_FUNCS([freeaddrinfo])
AC_TYPE_SIZE_T

# bstrlib requires
AC_CHECK_HEADERS([limits.h])
AC_CHECK_FUNCS([memset])
AC_CHECK_TYPES([ptrdiff_t])

AC_SUBST([ALLIUM_SO_VERSION], [0:1:0])
AC_SUBST([ALLIUM_API_VERSION], [1.0])

AC_CONFIG_FILES([Makefile
		 liballium-${ALLIUM_API_VERSION}.pc:liballium.pc.in])
AC_OUTPUT
