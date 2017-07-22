libegg_sources = files(
  'dotlock.c',
  'egg-armor.c',
  'egg-asn1-defs.c',
  'egg-asn1x.c',
  'egg-buffer.c',
  'egg-byte-array.c',
  'egg-cleanup.c',
  'egg-dh.c',
  'egg-dn.c',
  'egg-file-tracker.c',
  'egg-hex.c',
  'egg-hkdf.c',
  'egg-libgcrypt.c',
  'egg-oid.c',
  'egg-openssl.c',
  'egg-padding.c',
  'egg-secure-memory.c',
  'egg-symkey.c',
  'egg-testing.c',
  'egg-timegm.c',
  'egg-unix-credentials.c',
)

libegg_deps = [
  glib_dep,
  gck_dep,
  gobject_dep,
  libgcrypt_dep,
]

libegg_cflags = [
  '-DHAVE_CONFIG_H',
]

libegg = static_library('egg',
  libegg_sources,
  dependencies: libegg_deps,
  c_args: libegg_cflags,
  include_directories: config_h_inc,
)

libegg_dep = declare_dependency(
  link_with: libegg,
  include_directories: include_directories('..'),
)

libegg_tests = [
  'asn1',
  'asn1x',
  'dn',
  'cleanup',
  'hex',
  'hkdf',
  'oid',
  'secmem',
  'padding',
  'symkey',
  'armor',
  'openssl',
  'dh',
  'file-tracker',
]

libegg_tests_cflags = [
  '-DSRCDIR="@0@"'.format(source_root),
]

foreach test_name : libegg_tests
  test_bin = executable(test_name,
    f'test-@test_name@.c',
    dependencies: [ libegg_deps, libegg_dep ],
    c_args: libegg_tests_cflags,
    include_directories: config_h_inc,
  )

  test(test_name, test_bin,
    suite: 'egg',
  )
endforeach
