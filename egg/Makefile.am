
noinst_LTLIBRARIES += \
	libegg.la \
	libegg-asn1x.la \
	libegg-buffer.la \
	libegg-creds.la \
	libegg-secure.la \
	libegg-prompt.la \
	libegg-hex.la \
	libegg-test.la

libegg_la_CFLAGS = \
	$(LIBTASN1_CFLAGS) \
	$(GLIB_CFLAGS)

libegg_la_SOURCES = \
	egg/dotlock.c egg/dotlock.h \
	egg/egg-armor.c egg/egg-armor.h \
	egg/egg-asn1x.c egg/egg-asn1x.h \
	egg/egg-asn1-defs.c egg/egg-asn1-defs.h \
	egg/egg-buffer.c egg/egg-buffer.h \
	egg/egg-byte-array.c egg/egg-byte-array.h \
	egg/egg-cleanup.c egg/egg-cleanup.h \
	egg/egg-dh.c egg/egg-dh.h \
	egg/egg-dn.c egg/egg-dn.h \
	egg/egg-error.h \
	egg/egg-file-tracker.c egg/egg-file-tracker.h \
	egg/egg-hex.c egg/egg-hex.h \
	egg/egg-hkdf.c egg/egg-hkdf.h \
	egg/egg-libgcrypt.c egg/egg-libgcrypt.h \
	egg/egg-oid.c egg/egg-oid.h \
	egg/egg-padding.c egg/egg-padding.h \
	egg/egg-openssl.c egg/egg-openssl.h \
	egg/egg-unix-credentials.c egg/egg-unix-credentials.h \
	egg/egg-secure-memory.c egg/egg-secure-memory.h \
	egg/egg-spawn.c egg/egg-spawn.h \
	egg/egg-symkey.c egg/egg-symkey.h \
	egg/egg-testing.c egg/egg-testing.h \
	egg/egg-timegm.c egg/egg-timegm.h \
	egg/egg-asn1-defs.h \
	egg/pk.asn.h egg/pkix.asn.h \
	$(NULL)

ASN1_FILES += \
	egg/pk.asn \
	egg/pkix.asn \
	$(NULL)

# --------------------------------------------------------------------
# COMMON STUFF COMPILED INTO SMALLER COMPONENTS

libegg_asn1x_la_SOURCES = \
	egg/egg-asn1x.c egg/egg-asn1x.h \
	egg/egg-asn1-defs.c egg/egg-asn1-defs.h

libegg_asn1x_la_CFLAGS = \
	$(LIBTASN1_CFLAGS) \
	$(GLIB_CFLAGS)

libegg_secure_la_SOURCES = \
	egg/egg-secure-memory.c egg/egg-secure-memory.h

libegg_buffer_la_SOURCES = \
	egg/egg-buffer.c egg/egg-buffer.h

libegg_creds_la_SOURCES = \
	egg/egg-unix-credentials.c egg/egg-unix-credentials.h

libegg_prompt_la_SOURCES = \
	egg/egg-dh.c egg/egg-dh.h \
	egg/egg-hex.c egg/egg-hex.h \
	egg/egg-hkdf.c egg/egg-hkdf.h \
	egg/egg-libgcrypt.c egg/egg-libgcrypt.h \
	egg/egg-padding.c egg/egg-padding.h \
	egg/egg-secure-memory.c egg/egg-secure-memory.h

libegg_prompt_la_CFLAGS = \
	-DEGG_DH_NO_ASN1=1 \
	$(LIBGCRYPT_CFLAGS) \
	$(GLIB_CFLAGS)

libegg_prompt_la_LIBS = \
	$(LIBGCRYPT_LIBS) \
	$(GLIB_LIBS)

libegg_hex_la_SOURCES = \
	egg/egg-hex.c egg/egg-hex.h

libegg_hex_la_CFLAGS = \
	$(GLIB_CFLAGS)

libegg_hex_la_LIBS = \
	$(GLIB_LIBS)

libegg_test_la_SOURCES = \
	egg/egg-testing.c egg/egg-testing.h

libegg_test_la_CFLAGS = \
	$(GLIB_CFLAGS)

libegg_test_la_LIBS = \
	$(GLIB_LIBS)

ASN1_FILES += \
	egg/pk.asn \
	egg/pkix.asn \
	egg/test.asn

# -------------------------------------------------------------------
# TESTS

EXTRA_DIST += egg/fixtures

egg_LIBS =  \
	libegg.la \
	$(LIBGCRYPT_LIBS) \
	$(GTHREAD_LIBS) \
	$(GOBJECT_LIBS) \
	$(GLIB_LIBS)

egg_TESTS = \
	test-asn1 \
	test-asn1x \
	test-dn \
	test-cleanup \
	test-hex \
	test-hkdf \
	test-oid \
	test-secmem \
	test-padding \
	test-symkey \
	test-armor \
	test-openssl \
	test-dh \
	test-file-tracker \
	test-spawn

test_asn1_SOURCES = egg/test-asn1.c egg/test.asn.h
test_asn1_LDADD = $(egg_LIBS)

test_asn1x_SOURCES = egg/test-asn1x.c
test_asn1x_LDADD = libegg-asn1x.la $(egg_LIBS)

test_dn_SOURCES = egg/test-dn.c
test_dn_LDADD = $(egg_LIBS)

test_cleanup_SOURCES = egg/test-cleanup.c
test_cleanup_LDADD = $(egg_LIBS)

test_file_tracker_SOURCES = egg/test-file-tracker.c
test_file_tracker_LDADD = $(egg_LIBS)

test_hex_SOURCES = egg/test-hex.c
test_hex_LDADD = $(egg_LIBS)

test_hkdf_SOURCES = egg/test-hkdf.c
test_hkdf_LDADD = $(egg_LIBS)

test_oid_SOURCES = egg/test-oid.c
test_oid_LDADD = $(egg_LIBS)

test_secmem_SOURCES = egg/test-secmem.c
test_secmem_LDADD = $(egg_LIBS)

test_padding_SOURCES = egg/test-padding.c
test_padding_LDADD = $(egg_LIBS)

test_symkey_SOURCES = egg/test-symkey.c
test_symkey_LDADD = $(egg_LIBS)

test_armor_SOURCES = egg/test-armor.c
test_armor_LDADD = $(egg_LIBS)

test_openssl_SOURCES = egg/test-openssl.c
test_openssl_LDADD = $(egg_LIBS)

test_dh_SOURCES = egg/test-dh.c
test_dh_LDADD = $(egg_LIBS)

test_spawn_SOURCES = egg/test-spawn.c
test_spawn_LDADD = $(egg_LIBS)

check_PROGRAMS += $(egg_TESTS)
TESTS += $(egg_TESTS)
