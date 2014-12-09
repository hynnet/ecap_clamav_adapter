lib_LTLIBRARIES = \
	ecap_clamav_adapter.la

noinst_HEADERS = \
	Adapter.h \
	Service.h \
	Xaction.h \
	Debugger.h \
	Antivirus.h \
	ClamAv.h \
	Gadgets.h \
	\
	autoconf.h

ecap_clamav_adapter_la_SOURCES = \
	Adapter.cc \
	Service.cc \
	Xaction.cc \
	Debugger.cc \
	Gadgets.cc \
	ClamAv.cc

ecap_clamav_adapter_la_CPPFLAGS = $(LIBECAP_CFLAGS)
ecap_clamav_adapter_la_LDFLAGS = -module -avoid-version
ecap_clamav_adapter_la_LIBADD = $(LIBECAP_LIBS) -lclamav

DISTCLEANFILES = \
        autoconf.h

AM_CPPFLAGS = -I$(top_srcdir)/src

