
noinst_LTLIBRARIES = \
	libp11-rpc-daemon.la \
	libp11-rpc-module.la \
	p11-rpc-test-module.la

noinst_PROGRAMS = \
	p11-rpc-test-daemon
	
INCLUDES = -I. \
	-I$(top_srcdir) \
	-I$(top_builddir)
	
# ------------------------------------------------------------------------------
# The dispatch code

libp11_rpc_daemon_la_SOURCES = \
	p11-rpc-calls.h \
	p11-rpc-dispatch.c \
	p11-rpc-message.c \
	p11-rpc-message.h \
	p11-rpc-util.c

libp11_rpc_daemon_la_LIBADD = \
	$(top_builddir)/common/libgkr-common-buffer.la 

# ------------------------------------------------------------------------------
# The module code 

libp11_rpc_module_la_SOURCES = \
	p11-rpc-calls.h \
	p11-rpc-dispatch.c \
	p11-rpc-message.c \
	p11-rpc-message.h \
	p11-rpc-util.c

libp11_rpc_module_la_LIBADD = \
	$(top_builddir)/common/libgkr-common-buffer.la 

# ------------------------------------------------------------------------------
# The test module 

p11_rpc_test_module_la_LDFLAGS = \
	-module -avoid-version \
	-no-undefined -export-symbols-regex 'C_GetFunctionList'

p11_rpc_test_module_la_SOURCES = \
	p11-rpc-test-module.c

p11_rpc_test_module_la_LIBADD = \
	-lpthread \
	$(top_builddir)/common/libgkr-common-buffer.la \
	libp11-rpc-module.la

# -----------------------------------------------------------------------------
# The test daemon 

p11_rpc_test_daemon_SOURCES = \
	p11-rpc-test-daemon.c
	
p11_rpc_test_daemon_LDADD = \
	-ldl -lpthread \
	libp11-rpc-daemon.la
	