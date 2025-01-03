#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.72])
AC_INIT([banhammer],[0.2],[alexander@wittig.name])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/banlib.h])
AC_CONFIG_HEADERS([src/config.h])
AM_INIT_AUTOMAKE
AC_USE_SYSTEM_EXTENSIONS

# Checks for programs.
AC_PROG_CC

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h netdb.h net/if.h netinet/in.h stddef.h stdlib.h unistd.h string.h sys/param.h sys/socket.h syslog.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T

# Checks for common library functions.
AC_FUNC_MALLOC
m4_warn([obsolete],[your code may safely assume C89 semantics that RETSIGTYPE is void.
Remove this warning and the `AC_CACHE_CHECK' when you adjust the code.])dnl
AC_CACHE_CHECK([return type of signal handlers],[ac_cv_type_signal],[AC_COMPILE_IFELSE(
[AC_LANG_PROGRAM([#include <sys/types.h>
#include <signal.h>
],
		 [return *(signal (0, 0)) (0) == 1;])],
		   [ac_cv_type_signal=int],
		   [ac_cv_type_signal=void])])
AC_DEFINE_UNQUOTED([RETSIGTYPE],[$ac_cv_type_signal],[Define as the return type of signal handlers
		    (`int' or `void').])

AC_CHECK_FUNCS([socket strcasecmp strchr strdup strtol random srandomdev])
AM_FUNC_GETLINE

# Check for libutil
AC_CHECK_LIB([util], [pidfile_open], [LIBS="$LIBS -lutil"], [AC_MSG_ERROR([Did not find FreeBSD libutil])] )

# Try to find PCRE unless deactivated
AC_ARG_WITH([pcre],
            [AS_HELP_STRING([--with-pcre=[[prefix]]],[Use PCRE regex library @<:@default=check@:>@])],
            [],
            [with_pcre="check"]
)
AS_IF([test ".$with_pcre" != ".no"],
  [
    # if a path is provided, use that, otherwise try to guess one
    AS_IF([test -d $with_pcre],
        [pcre_path="$with_pcre"],
        [AS_IF([test -d "${prefix}"],
            [pcre_path="${prefix}"],
            [pcre_path="/usr/local"])
        ]
    )
    OLDLDFLAGS="$LDFLAGS"; LDFLAGS="$LDFLAGS -L$pcre_path/lib"
    OLDCPPFLAGS="$CPPFLAGS"; CPPFLAGS="$CPPFLAGS -I$pcre_path/include"
    AC_CHECK_LIB([pcre],[pcre_compile],
      [
        LDADD="$LDADD -L$pcre_path/lib -lpcre"
        AM_CPPFLAGS="$AM_CPPFLAGS -I$pcre_path/include"
        AC_SUBST(AM_CPPFLAGS)
        AC_SUBST(LDADD)
        AC_DEFINE([HAVE_LIBPCRE],[],[Define to 1 if you have PCRE installed])
        AC_MSG_NOTICE([Building with PCRE regular expressions library in $pcre_path])
      ],
      [
        AS_IF([test ".$with_pcre" != ".check"],[AC_MSG_ERROR([PCRE regular expressions library not found])],[with_pcre="no"])
      ]
    )
    CPPFLAGS="$OLDCPPFLAGS"
    LDFLAGS="$OLDLDFLAGS"
  ]
)

# If PCRE deactivated or not found, try POSIX instead
AS_IF([test ".$with_pcre" = ".no"],
  [
    AC_CHECK_FUNCS([regcomp],
      [
        AC_MSG_NOTICE([Building with POSIX regular expressions library])
      ],
      [
        AC_MSG_ERROR([No supported regular expression library found.])
      ]
    )
  ]
)

# Check if we have at least IPFW2
AC_CHECK_TYPE([struct ip_fw],
  [
    AC_DEFINE([HAVE_IPFW2],[],[Define to 1 if you have IPFW2])
  ],
  [
    AC_MSG_ERROR([At least IPFW2 is required to build.])
  ],
  [
#include <stddef.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip_fw.h>
  ]
)

# Check if we even have IPFW3
AC_CHECK_TYPE([ip_fw3_opheader],
  [
    AC_DEFINE([HAVE_IPFW3],[],[Define to 1 if you have IPFW3])
    have_ipfw3=yes
  ],
  [],
  [
#include <stddef.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip_fw.h>
  ]
)

# Check if we have IPv6
# from http://www.codealias.info/technotes/autotools_by_example
AC_MSG_CHECKING(for IPv6 support)
AC_CACHE_VAL(ac_cv_ipv6,
      AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
      /* Make sure the definitions for AF_INET6 and struct sockaddr_in6
       * are defined, and that we can actually create an IPv6 TCP socket.
       */
      main()
      {
              int fd;
              struct sockaddr_in6 foo;
              fd = socket(AF_INET6, SOCK_STREAM, 0);
              exit(fd >= 0 ? 0 : 1);
      }]])],[ac_cv_ipv6=yes],[ac_cv_ipv6=no],[ac_cv_ipv6=no]))
AC_MSG_RESULT($ac_cv_ipv6)
if test $ac_cv_ipv6 = yes ; then
      AC_DEFINE(WITH_IPV6,,"check if system supports IPV6")
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

