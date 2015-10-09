## This is the shared library to be built
lib_LTLIBRARIES = libmoddiary.la

apache_CFLAGS=`@apxs@ -q CFLAGS` `@apxs@ -q EXTRA_INCLUDES`
apache_LIBEXECDIR=`@apxs@ -q LIBEXECDIR`

## Define the source file for the module
libmoddiary_la_SOURCES = mod_diary.c
libmoddiary_la_CFLAGS = -Wall $(apache_CFLAGS) -I@discount_dir@/include -I@clearsilver_dir@/include/ClearSilver/
libmoddiary_la_LDFLAGS = -L@discount_dir@/lib -lmarkdown -L@clearsilver_dir@/lib -lneo_cs -lneo_utl -lneo_cgi -lz

bin_PROGRAMS = diary-mkindex
diary_mkindex_SOURCES = diary-mkindex.c
diary_mkindex_CFLAGS = -I@discount_dir@/include -I@clearsilver_dir@/include/ClearSilver/
diary_mkindex_LDFLAGS = -L@discount_dir@/lib -lmarkdown -L@clearsilver_dir@/lib -lneo_cs -lneo_utl

## Define that an include directory is required.
INCLUDES = -D_LARGEFILE64_SOURCE
#DEFS =
EXTRA_DIST = README.md

install: .libs/libmoddiary.so
	install $< $(apache_LIBEXECDIR)/mod_diary.so

