libgkm_gnome2_store_sources = files(
  'gkm-gnome2-file.c',
  'gkm-gnome2-module.c',
  'gkm-gnome2-private-key.c',
  'gkm-gnome2-public-key.c',
  'gkm-gnome2-storage.c',
)

libgkm_gnome2_store_deps = [
  glib_dep,
  gobject_dep,
  libgcrypt_dep,
  gmodule_dep,

  libegg_dep,
  libgkm_dep,
]

# The gnome2-store component code
libgkm_gnome2_store_static = static_library('gkm-gnome2-store',
  libgkm_gnome2_store_sources,
  name_prefix: '',
  dependencies: libgkm_gnome2_store_deps,
  include_directories: config_h_inc,
)

libgkm_gnome2_store_dep = declare_dependency(
  link_with: libgkm_gnome2_store_static,
)

# The gnome2-store standalone module
libgkm_gnome2_store_module = shared_library('gkm-gnome2-store-standalone',
  [ libgkm_gnome2_store_sources, 'gkm-gnome2-standalone.c' ],
  name_prefix: '',
  dependencies: libgkm_gnome2_store_deps,
  link_args: pkcs11_module_linkflags,
  link_depends: pkcs11_module_symbolmap,
  include_directories: config_h_inc,
  install: true,
  install_dir: gkr_pkglibdir,
)

# Tests
libgkm_gnome2_store_tests = [
  {
    'name': 'gnome2-file',
    'needs-mock': false,
  },
  {
    'name': 'gnome2-storage',
    'needs-mock': true,
  },
  {
    'name': 'gnome2-private-key',
    'needs-mock': true,
  },
  {
    'name': 'import',
    'needs-mock': false,
  },
]

libgkm_gnome2_store_tests_deps = [
  gck_dep,
  gcr_base_dep,

  libgkm_gnome2_store_deps,
  libgkm_gnome2_store_dep,
]

libgkm_gnome2_store_tests_cflags = [
  '-DSRCDIR="@0@"'.format(source_root),
]

foreach _test : libgkm_gnome2_store_tests
  test_name = _test['name']

  test_sources = [ f'test-@test_name@.c' ]
  if _test['needs-mock']
    test_sources += 'mock-gnome2-module.c'
  endif

  test_bin = executable(test_name,
    test_sources,
    dependencies: libgkm_gnome2_store_tests_deps,
    c_args: libgkm_gnome2_store_tests_cflags,
    include_directories: config_h_inc,
  )

  test(test_name, test_bin,
    suite: 'gkm::gnome2-store',
  )
endforeach
