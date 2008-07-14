
EXTRA_DIST = \
	ca-example \
	cu-test \
	test-helpers.c test-helpers.h \
	gtest-helpers.c gtest-helpers.h \
	prep-tests.sh prep-gtest.sh \
	run-tests.sh \
	test.make gtest.make

INCLUDES=					\
	-I$(top_srcdir) 		\
	-I$(top_builddir) 		\
	$(GTK_CFLAGS) 			\
	$(GLIB_CFLAGS) 
	
LIBS = \
	$(GTK_LIBS) \
	$(GLIB_LIBS) \
	$(GTHREAD_LIBS)
	
noinst_PROGRAMS= \
	list-keyrings \
	test-keyring \
	test-keyring-two
	
# ------------------------------------------------------------------------------
# Simply list all the keyrings and whatever they have access to

list_keyrings_SOURCES = \
	list-keyrings.c

list_keyrings_LDADD = \
	$(top_builddir)/library/libgnome-keyring.la

# ------------------------------------------------------------------------------
# A generic testing program

test_keyring_SOURCES = \
	test-keyrings.c

test_keyring_LDADD = \
	$(top_builddir)/library/libgnome-keyring.la

test_keyring_two_SOURCES = \
	test-keyrings.c

test_keyring_two_LDADD = \
	$(top_builddir)/library/libgnome-keyring.la


# ------------------------------------------------------------------------------
# Run the tests

run: run-auto

run-auto: 
	sh run-tests.sh $(top_srcdir) test-auto

run-prompt: 
	sh run-tests.sh $(top_srcdir) test-auto
