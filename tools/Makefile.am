bin_PROGRAMS=openkey-producer openkey-manager openkey-authenticator

openkey_producer_SOURCES= openkey-producer.c helpers.c
openkey_manager_SOURCES= openkey-manager.c helpers.c
openkey_authenticator_SOURCES= openkey-authenticator.c helpers.c

AM_LDFLAGS = $(top_srcdir)/libopenkey/libopenkey.la
LDADD = $(DEPS_LIBS)

AM_CPPFLAGS = -I. -I$(top_srcdir)/include $(DEPS_CFLAGS)
