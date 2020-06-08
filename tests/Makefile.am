AM_CPPFLAGS = -I$(top_srcdir)/libusb
LDADD = ../libusb/libusb-1.0.la
LIBS =

noinst_PROGRAMS = stress fuzz

stress_SOURCES = stress.c libusb_testlib.h testlib.c

fuzz_SOURCES = fuzz.c libusb_testlib.h testlib
