#######################################
# The list of executables we are building seperated by spaces
# the 'bin_' indicates that these build products will be installed
# in the $(bindir) directory. For example /usr/bin
#bin_PROGRAMS=run_bootstrap

# Because a.out is only a sample program we don't want it to be installed.
# The 'noinst_' prefix indicates that the following targets are not to be
# installed.
noinst_PROGRAMS=run_bootstrap make_card own_card authenticate_card

#######################################
# Build information for each executable. The variable name is derived
# by use the name of the executable with each non alpha-numeric character is
# replaced by '_'. So a.out becomes a_out and the appropriate suffex added.
# '_SOURCES' for example.

# Sources for the a.out 
run_bootstrap_SOURCES= run_bootstrap.c
make_card_SOURCES = make_card.c
own_card_SOURCES = own_card.c
authenticate_card_SOURCES = authenticate_card.c

# Linker options for a.out
AM_LDFLAGS = $(top_srcdir)/libopenkey/libopenkey.la
LDADD = $(DEPS_LIBS) $(LIBGCRYPT_LIBS)

# Compiler options for a.out
AM_CPPFLAGS = -I$(top_srcdir)/include $(DEPS_CFLAGS)
