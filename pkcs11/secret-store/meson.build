libgkm_secret_store_sources = files(
  'gkm-secret-binary.c',
  'gkm-secret-collection.c',
  'gkm-secret-compat.c',
  'gkm-secret-data.c',
  'gkm-secret-fields.c',
  'gkm-secret-item.c',
  'gkm-secret-module.c',
  'gkm-secret-object.c',
  'gkm-secret-search.c',
  'gkm-secret-textual.c',
)

libgkm_secret_store_deps = [
  glib_dep,
  gobject_dep,
  libgcrypt_dep,
  gmodule_dep,

  libegg_dep,
  libgkm_dep,
]

# The secret-store component code
libgkm_secret_store_static = static_library('gkm-secret-store',
  libgkm_secret_store_sources,
  name_prefix: '',
  dependencies: libgkm_secret_store_deps,
  include_directories: config_h_inc,
)

libgkm_secret_store_dep = declare_dependency(
  link_with: libgkm_secret_store_static,
)

# The secret-store standalone module
libgkm_secret_store = shared_library('gkm-secret-store-standalone',
  [ libgkm_secret_store_sources, 'gkm-secret-standalone.c' ],
  name_prefix: '',
  dependencies: libgkm_secret_store_deps,
  link_args: pkcs11_module_linkflags,
  link_depends: pkcs11_module_symbolmap,
  include_directories: config_h_inc,
  install: true,
  install_dir: gkr_pkglibdir,
)

# Tests
dump_keyring0_format = executable('dump-keyring0-format',
  'dump-keyring0-format.c',
  dependencies: libgkm_secret_store_deps,
)

libgkm_secret_store_tests = [
  {
    'name': 'secret-compat',
    'needs-mock': false,
  },
  {
    'name': 'secret-fields',
    'needs-mock': false,
  },
  {
    'name': 'secret-data',
    'needs-mock': false,
  },
  {
    'name': 'secret-object',
    'needs-mock': true,
  },
  {
    'name': 'secret-collection',
    'needs-mock': true,
  },
  {
    'name': 'secret-item',
    'needs-mock': true,
  },
  {
    'name': 'secret-schema',
    'needs-mock': true,
  },
  {
    'name': 'secret-search',
    'needs-mock': true,
  },
  {
    'name': 'secret-textual',
    'needs-mock': true,
  },
  {
    'name': 'secret-binary',
    'needs-mock': true,
  },
]

libgkm_secret_store_tests_deps = [
  gck_dep,
  gcr_base_dep,

  libgkm_secret_store_deps,
  libgkm_secret_store_dep,
]

libgkm_secret_store_tests_cflags = [
  '-DSRCDIR="@0@"'.format(source_root),
]

foreach _test : libgkm_secret_store_tests
  test_name = _test['name']

  test_sources = [ f'test-@test_name@.c' ]
  if _test['needs-mock']
    test_sources += 'mock-secret-module.c'
  endif

  test_bin = executable(test_name,
    test_sources,
    dependencies: libgkm_secret_store_tests_deps,
    c_args: libgkm_secret_store_tests_cflags,
    include_directories: config_h_inc,
  )

  test(test_name, test_bin,
    suite: 'gkm::secret-store',
  )
endforeach
