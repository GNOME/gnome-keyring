
# ------------------------------------------------------------------------------
# The GKM library

noinst_LTLIBRARIES += \
	libgkm.la

gkm_BUILT = \
	gkm-marshal.c gkm-marshal.h

BUILT_SOURCES += $(gkm_BUILT)

libgkm_la_SOURCES = \
	pkcs11/gkm/gkm-aes-key.c \
	pkcs11/gkm/gkm-aes-key.h \
	pkcs11/gkm/gkm-aes-mechanism.c \
	pkcs11/gkm/gkm-aes-mechanism.h \
	pkcs11/gkm/gkm-assertion.c \
	pkcs11/gkm/gkm-assertion.h \
	pkcs11/gkm/gkm-attributes.c \
	pkcs11/gkm/gkm-attributes.h \
	pkcs11/gkm/gkm-certificate.c \
	pkcs11/gkm/gkm-certificate.h \
	pkcs11/gkm/gkm-certificate-key.c \
	pkcs11/gkm/gkm-certificate-key.h \
	pkcs11/gkm/gkm-credential.c \
	pkcs11/gkm/gkm-credential.h \
	pkcs11/gkm/gkm-crypto.c \
	pkcs11/gkm/gkm-crypto.h \
	pkcs11/gkm/gkm-data-asn1.c \
	pkcs11/gkm/gkm-data-asn1.h \
	pkcs11/gkm/gkm-data-der.c \
	pkcs11/gkm/gkm-data-der.h \
	pkcs11/gkm/gkm-data-types.h \
	pkcs11/gkm/gkm-debug.c \
	pkcs11/gkm/gkm-debug.h \
	pkcs11/gkm/gkm-dh-key.c \
	pkcs11/gkm/gkm-dh-key.h \
	pkcs11/gkm/gkm-dh-mechanism.c \
	pkcs11/gkm/gkm-dh-mechanism.h \
	pkcs11/gkm/gkm-dh-private-key.c \
	pkcs11/gkm/gkm-dh-private-key.h \
	pkcs11/gkm/gkm-dh-public-key.c \
	pkcs11/gkm/gkm-dh-public-key.h \
	pkcs11/gkm/gkm-dsa-mechanism.c \
	pkcs11/gkm/gkm-dsa-mechanism.h \
	pkcs11/gkm/gkm-factory.c \
	pkcs11/gkm/gkm-factory.h \
	pkcs11/gkm/gkm-generic-key.c \
	pkcs11/gkm/gkm-generic-key.h \
	pkcs11/gkm/gkm-hkdf-mechanism.c \
	pkcs11/gkm/gkm-hkdf-mechanism.h \
	pkcs11/gkm/gkm-log.c \
	pkcs11/gkm/gkm-log.h \
	pkcs11/gkm/gkm-manager.c \
	pkcs11/gkm/gkm-manager.h \
	pkcs11/gkm/gkm-memory-store.c \
	pkcs11/gkm/gkm-memory-store.h \
	pkcs11/gkm/gkm-mock.c \
	pkcs11/gkm/gkm-mock.h \
	pkcs11/gkm/gkm-module.c \
	pkcs11/gkm/gkm-module.h \
	pkcs11/gkm/gkm-module-ep.h \
	pkcs11/gkm/gkm-null-key.c \
	pkcs11/gkm/gkm-null-key.h \
	pkcs11/gkm/gkm-null-mechanism.c \
	pkcs11/gkm/gkm-null-mechanism.h \
	pkcs11/gkm/gkm-object.c \
	pkcs11/gkm/gkm-object.h \
	pkcs11/gkm/gkm-oids.h \
	pkcs11/gkm/gkm-private-xsa-key.c \
	pkcs11/gkm/gkm-private-xsa-key.h \
	pkcs11/gkm/gkm-public-xsa-key.c \
	pkcs11/gkm/gkm-public-xsa-key.h \
	pkcs11/gkm/gkm-rsa-mechanism.c \
	pkcs11/gkm/gkm-rsa-mechanism.h \
	pkcs11/gkm/gkm-secret.c \
	pkcs11/gkm/gkm-secret.h \
	pkcs11/gkm/gkm-secret-key.c \
	pkcs11/gkm/gkm-secret-key.h \
	pkcs11/gkm/gkm-serializable.c \
	pkcs11/gkm/gkm-serializable.h \
	pkcs11/gkm/gkm-session.c \
	pkcs11/gkm/gkm-session.h \
	pkcs11/gkm/gkm-sexp.c \
	pkcs11/gkm/gkm-sexp.h \
	pkcs11/gkm/gkm-sexp-key.c \
	pkcs11/gkm/gkm-sexp-key.h \
	pkcs11/gkm/gkm-store.c \
	pkcs11/gkm/gkm-store.h \
	pkcs11/gkm/gkm-test.c \
	pkcs11/gkm/gkm-test.h \
	pkcs11/gkm/gkm-timer.c \
	pkcs11/gkm/gkm-timer.h \
	pkcs11/gkm/gkm-transaction.c \
	pkcs11/gkm/gkm-transaction.h \
	pkcs11/gkm/gkm-trust.c \
	pkcs11/gkm/gkm-trust.h \
	pkcs11/gkm/gkm-types.h \
	pkcs11/gkm/gkm-util.c \
	pkcs11/gkm/gkm-util.h \
	$(gkm_BUILT)
libgkm_la_CFLAGS = \
	-I$(srcdir)/pkcs11 \
	-DG_LOG_DOMAIN=\"Gkm\" \
	$(GOBJECT_CFLAGS) \
	$(LIBGCRYPT_CFLAGS) \
	$(LIBTASN1_CFLAGS) \
	$(GLIB_CFLAGS)
libgkm_la_LIBADD = \
	libegg.la \
	$(GOBJECT_LIBS) \
	$(LIBGCRYPT_LIBS) \
	$(GLIB_LIBS)

gkm-marshal.h: pkcs11/gkm/gkm-marshal.list $(GLIB_GENMARSHAL)
	$(GLIB_GENMARSHAL) $< --header --prefix=gkm_marshal > $@
gkm-marshal.c: pkcs11/gkm/gkm-marshal.list $(GLIB_GENMARSHAL)
	echo "#include \"gkm-marshal.h\"" > $@ && \
	$(GLIB_GENMARSHAL) $< --body --prefix=gkm_marshal >> $@

EXTRA_DIST += \
	pkcs11/gkm/gkm-marshal.list

# -------------------------------------------------------------------------------
# TESTS

EXTRA_DIST += pkcs11/gkm/fixtures

noinst_LIBRARIES += libgkm-mock.a

libgkm_mock_a_SOURCES = \
	pkcs11/gkm/mock-module.c \
	pkcs11/gkm/mock-module.h \
	pkcs11/gkm/mock-locked-object.c \
	pkcs11/gkm/mock-locked-object.h \
	pkcs11/gkm/test.asn.h

gkm_LIBS = \
	libgkm-mock.a \
	libgkm.la \
	libegg.la \
	$(GLIB_LIBS) \
	$(GTHREAD_LIBS) \
	$(LIBGCRYPT_LIBS)

gkm_TESTS = \
	test-attributes \
	test-credential \
	test-data-asn1 \
	test-data-der \
	test-memory-store \
	test-object \
	test-certificate \
	test-secret \
	test-sexp \
	test-store \
	test-timer \
	test-transaction

test_attributes_SOURCES = pkcs11/gkm/test-attributes.c
test_attributes_LDADD = $(gkm_LIBS)

test_credential_SOURCES = pkcs11/gkm/test-credential.c
test_credential_LDADD = $(gkm_LIBS)

test_data_asn1_SOURCES = pkcs11/gkm/test-data-asn1.c
test_data_asn1_LDADD = $(gkm_LIBS)

test_data_der_SOURCES = pkcs11/gkm/test-data-der.c
test_data_der_LDADD = $(gkm_LIBS)

test_memory_store_SOURCES = pkcs11/gkm/test-memory-store.c
test_memory_store_LDADD = $(gkm_LIBS)

test_object_SOURCES = pkcs11/gkm/test-object.c
test_object_LDADD = $(gkm_LIBS)

test_certificate_SOURCES = pkcs11/gkm/test-certificate.c
test_certificate_LDADD = $(gkm_LIBS)

test_secret_SOURCES = pkcs11/gkm/test-secret.c
test_secret_LDADD = $(gkm_LIBS)

test_sexp_SOURCES = pkcs11/gkm/test-sexp.c
test_sexp_LDADD = $(gkm_LIBS)

test_store_SOURCES = pkcs11/gkm/test-store.c
test_store_LDADD = $(gkm_LIBS)

test_timer_SOURCES = pkcs11/gkm/test-timer.c
test_timer_LDADD = $(gkm_LIBS)

test_transaction_SOURCES = pkcs11/gkm/test-transaction.c
test_transaction_LDADD = $(gkm_LIBS)

ASN1_FILES += pkcs11/gkm/test.asn

check_PROGRAMS += $(gkm_TESTS)
TESTS += $(gkm_TESTS)
