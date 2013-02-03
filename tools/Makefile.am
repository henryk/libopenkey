bin_PROGRAMS=openkey-producer

openkey_producer_SOURCES= openkey-producer.c helpers.c

AM_LDFLAGS = $(top_srcdir)/libopenkey/libopenkey.la
LDADD = $(DEPS_LIBS)

AM_CPPFLAGS = -I. -I$(top_srcdir)/include $(DEPS_CFLAGS)
