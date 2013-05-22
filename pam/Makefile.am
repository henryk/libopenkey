LDADD = $(DEPS_LIBS)

libdir = $(PAMDIR)

lib_LTLIBRARIES = pam_openkey.la

pam_openkey_la_SOURCES = pam_openkey.c $(top_srcdir)/tools/helpers.c
pam_openkey_la_LDFLAGS = -module -avoid-version $(top_srcdir)/libopenkey/libopenkey.la
pam_openkey_la_CPPFLAGS = -I. -I$(top_srcdir)/tools -I$(top_srcdir)/include $(DEPS_CFLAGS)