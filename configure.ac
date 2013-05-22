dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(libopenkey, 0.2)
AC_PROG_CC

AC_CANONICAL_SYSTEM

dnl Initialize automake
AM_INIT_AUTOMAKE([1.11])

dnl Silent build output
AM_SILENT_RULES([yes])

dnl this allows us specify individual liking flags for each target
AM_PROG_CC_C_O 
AC_PROG_CC_C99

dnl Initialize Libtool
LT_INIT

dnl Check if Libtool is present
dnl Libtool is used for building share libraries 
AC_PROG_LIBTOOL

PKG_CHECK_MODULES([DEPS], [libnfc >= 1.7.0 libfreefare >= 0.3.5 uuid])

AC_CHECK_HEADERS([security/pam_appl.h], [], [AC_MSG_ERROR([[PAM header files not found, install libpam-dev.]])])
AC_CHECK_HEADERS([security/pam_modules.h security/_pam_macros.h security/pam_modutil.h], [], [],  [#include <sys/types.h>
#include <security/pam_appl.h>])

AC_CHECK_LIB([pam], [pam_start])

AC_SUBST(PAMDIR, "\$(exec_prefix)/lib/security")
AC_ARG_WITH(pam-dir,
  AC_HELP_STRING([--with-pam-dir=DIR],
                 [Where to install PAM module [[PREFIX/lib/security]]]),
            [case "${withval}" in
            /*) PAMDIR="${withval}";;
            ./*|../*) AC_MSG_ERROR(Bad value for --with-pam-dir);;
            *) PAMDIR="\$(exec_prefix)/lib/${withval}";;
            esac])
AC_MSG_NOTICE([PAM installation path $PAMDIR])

AM_PATH_LIBGCRYPT

AC_CONFIG_FILES(Makefile
                examples/Makefile
                tools/Makefile
                libopenkey/Makefile
                pam/Makefile
                include/Makefile)
AC_OUTPUT