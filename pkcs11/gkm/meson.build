libgkm_sources = files(
  'gkm-aes-key.c',
  'gkm-aes-mechanism.c',
  'gkm-assertion.c',
  'gkm-attributes.c',
  'gkm-certificate.c',
  'gkm-certificate-key.c',
  'gkm-credential.c',
  'gkm-crypto.c',
  'gkm-data-asn1.c',
  'gkm-data-der.c',
  'gkm-debug.c',
  'gkm-dh-key.c',
  'gkm-dh-mechanism.c',
  'gkm-dh-private-key.c',
  'gkm-dh-public-key.c',
  'gkm-dsa-mechanism.c',
  'gkm-ecdsa-mechanism.c',
  'gkm-factory.c',
  'gkm-generic-key.c',
  'gkm-hkdf-mechanism.c',
  'gkm-log.c',
  'gkm-manager.c',
  'gkm-memory-store.c',
  'gkm-mock.c',
  'gkm-module.c',
  'gkm-null-key.c',
  'gkm-null-mechanism.c',
  'gkm-object.c',
  'gkm-private-xsa-key.c',
  'gkm-public-xsa-key.c',
  'gkm-rsa-mechanism.c',
  'gkm-secret.c',
  'gkm-secret-key.c',
  'gkm-serializable.c',
  'gkm-session.c',
  'gkm-sexp.c',
  'gkm-sexp-key.c',
  'gkm-store.c',
  'gkm-test.c',
  'gkm-timer.c',
  'gkm-transaction.c',
  'gkm-trust.c',
  'gkm-util.c',
)

gkm_marshal = gnome.genmarshal('gkm-marshal',
  sources: 'gkm-marshal.list',
  prefix: 'gkm_marshal',
  valist_marshallers: true,
)

libgkm_deps = [
  glib_dep,
  gobject_dep,
  libgcrypt_dep,

  libegg_dep,
]

libgkm = static_library('gkm',
  sources: [ libgkm_sources, gkm_marshal, ],
  dependencies: libgkm_deps,
  include_directories: config_h_inc,
)

libgkm_dep = declare_dependency(
  link_with: libgkm,
  include_directories: [
    include_directories('.'),
    include_directories('..'), # for gkm/gkm-{crypto,assertion}.h
  ],
  sources: gkm_marshal[1],
)

# Tests
libgkm_mock_sources = files(
  'mock-module.c',
  'mock-locked-object.c',
)

libgkm_mock_deps = [
  glib_dep,
  gobject_dep,

  libgkm_dep,
]

libgkm_mock_cflags = [
  '-DSRCDIR="@0@"'.format(source_root),
]

libgkm_mock = library('gkm-mock',
  sources: libgkm_mock_sources,
  dependencies: libgkm_mock_deps,
  c_args: libgkm_mock_cflags,
  include_directories: config_h_inc,
)

libgkm_tests = [
  'attributes',
  'credential',
  'data-asn1',
  'data-der',
  'memory-store',
  'object',
  'certificate',
  'secret',
  'sexp',
  'store',
  'timer',
  'transaction',
]

libgkm_tests_cflags = [
  '-DSRCDIR="@0@"'.format(source_root),
]

foreach test_name : libgkm_tests
  test_bin = executable(
    test_name,
    sources: f'test-@test_name@.c',
    dependencies: [ libgkm_dep, libgkm_deps ],
    link_with: libgkm_mock,
    c_args: libgkm_tests_cflags,
    include_directories: config_h_inc,
  )

  test(test_name, test_bin,
    suite: 'gkm',
  )
endforeach
