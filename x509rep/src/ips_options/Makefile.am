file_list = \
ips_ssl_x509rep.cc \
x509rep_conf.h \
x509rep_conf.cc \
util_net.h \
util_net.cc \
ssl.h \
ssl.cc \
x509rep_packet_info.h \
x509rep_packet_info.cc \
x509rep_SSL_decoder.h \
x509rep_SSL_basic_decoder.h \
x509rep_SSL_basic_decoder.cc \
x509rep_x509_chain_object.h \
x509Rep_basic_chain_object.h \
x509Rep_basic_chain_object.cc \
x509rep_fingerprint.h \
x509rep_basic_fingerprint.h \
x509rep_basic_fingerprint.cc 


optlibdir = $(pkglibdir)/ips_options
LDADD = x509rep

optlib_LTLIBRARIES = libips_x509rep.la
#libips_x509rep_la_CXXFLAGS = $(AM_CXXFLAGS) -lx509rep
libips_x509rep_la_LDFLAGS = -export-dynamic -shared
libips_x509rep_la_SOURCES = $(file_list)

CXXFLAGS = @CXXFLAGS@ "-L/usr/lib -lssl -lcrypto"

