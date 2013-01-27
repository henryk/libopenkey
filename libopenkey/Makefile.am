#######################################
# The list of libraries we are building seperated by spaces.
# The 'lib_' indicates that these build products will be installed
# in the $(libdir) directory. For example /usr/lib
lib_LTLIBRARIES = libopenkey.la

#######################################
# Build information for each library

# Sources for libopenkey
libopenkey_la_SOURCES = libopenkey.c

# Linker options libTestProgram
libopenkey_la_LDFLAGS = 

# Compiler options. Here we are adding the include directory
# to be searched for headers included in the source code.
libopenkey_la_CPPFLAGS = -I$(top_srcdir)/include $(DEPS_CFLAGS)
libopenkey_la_LIBADD = $(DEPS_LIBS)

