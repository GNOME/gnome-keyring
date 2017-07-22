libgkm_rpc_layer_sources = files(
  'gkm-rpc-dispatch.c',
  'gkm-rpc-message.c',
  'gkm-rpc-util.c',
)

libgkm_rpc_layer_deps = [
  glib_dep,
  gobject_dep,
  libgcrypt_dep,

  libegg_dep,
  libgkm_dep,
]

libgkm_rpc_layer = static_library('gkm-rpc-layer',
  sources: libgkm_rpc_layer_sources,
  dependencies: libgkm_rpc_layer_deps,
  include_directories: config_h_inc,
)

libgkm_rpc_layer_dep = declare_dependency(
  link_with: libgkm_rpc_layer,
)

# The module code, built as the public gnome-keyring module

# This is the location that some older software looks for modules
p11_module_path = get_option('pkcs11-modules')
if p11_module_path == ''
  p11_module_path = p11_kit_dep.get_variable('p11_module_path')
endif

gkr_pkcs11_module_sources = [
  'gkm-rpc-module.c',
  'gkm-rpc-message.c',
  'gkm-rpc-util.c',
]

gkr_pkcs11_module_deps = [
  glib_dep,
  libegg_dep,
]

gkr_pkcs11_module = shared_library('gnome-keyring-pkcs11',
  name_prefix: '',
  sources: gkr_pkcs11_module_sources,
  dependencies: gkr_pkcs11_module_deps,
  link_args: pkcs11_module_linkflags,
  link_depends: pkcs11_module_symbolmap,
  include_directories: config_h_inc,
  install: true,
  install_dir: p11_module_path,
)

# This is the configuration file that p11-kit uses to load the module
p11_system_config_module = get_option('pkcs11-config')
if p11_system_config_module == ''
  p11_system_config_module = p11_kit_dep.get_variable('p11_system_config_modules')
endif
configure_file(
  input: 'gnome-keyring.module.in',
  output: '@BASENAME@',
  copy: true,
  install_dir: p11_system_config_module,
)

# Tests
libgkm_rpc_layer_tests = [
  'initialize',
]

libgkm_rpc_layer_tests_deps = [
  gck_dep,
  gcr_base_dep,

  libgkd_test_dep,
  libgkm_rpc_layer_deps,
  libgkm_rpc_layer_dep,
]

libgkm_rpc_layer_tests_cflags = [
  f'-DSRCDIR="@source_root@"',
  f'-DTEST_GKR_DAEMON_BIN="@test_gkr_daemon_bin@"',
  f'-DTEST_GKR_PKCS11_MODULE="@0@"'.format(gkr_pkcs11_module.full_path()),
]

foreach test_name : libgkm_rpc_layer_tests
  test_bin = executable(test_name,
    f'test-@test_name@.c',
    dependencies: libgkm_rpc_layer_tests_deps,
    c_args: libgkm_rpc_layer_tests_cflags,
    include_directories: config_h_inc,
  )

  test(test_name, test_bin,
    suite: 'gkm::rpc-layer',
  )
endforeach
