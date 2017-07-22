# Only export pam_sm_* symbols
pam_gkr_symbolmap = meson.current_source_dir() / 'pam-gkr.map'
pam_gkr_linkflags = cc.get_supported_link_arguments(
  '-Wl,--no-undefined',
  '-Wl,--version-script,@0@'.format(pam_gkr_symbolmap),
)

libpam_gkr_sources = files(
  'gkr-pam-client.c',
  'gkr-pam-module.c',
  'gkr-pam-stubs.c',
)

libpam_gkr_deps = [
  libpam_dep,
  libegg_dep,
]

if libselinux_dep.found()
  libpam_gkr_deps += libselinux_dep
endif

libpam_gkr_cflags = [
  '-DGNOME_KEYRING_DAEMON="@0@"'.format(gkr_prefix / get_option('bindir') / 'gnome-keyring-daemon'),
]

libpam_gkr = shared_library('pam_gnome_keyring',
  libpam_gkr_sources,
  name_prefix: '',
  c_args: libpam_gkr_cflags,
  dependencies: libpam_gkr_deps,
  link_args: pam_gkr_linkflags,
  link_depends: pam_gkr_symbolmap,
  include_directories: config_h_inc,
  install: true,
  install_dir: get_option('libdir') / 'security',
)

libpam_gkr_dep = declare_dependency(
  link_with: libpam_gkr,
)

# Tests
libpam_gkr_test_deps = [
  glib_dep,
  gio_dep,
  libpam_dep,

  libegg_dep,
  libgkd_test_dep,
  libgkd_control_dep,
]

libpam_gkr_test_cflags = [
  f'-DSRCDIR="@source_root@"',
  f'-DBUILDDIR="@build_root@"',
  f'-DTEST_GKR_DAEMON_BIN="@test_gkr_daemon_bin@"',
  '-DSYSCONFDIR="@0@"'.format(get_option('sysconfdir')),
]

libpam_gkr_test_bin = executable('test-pam',
  'test-pam.c',
  dependencies: libpam_gkr_test_deps,
  c_args: libpam_gkr_test_cflags,
  include_directories: config_h_inc,
)

test('test-pam', libpam_gkr_test_bin,
  suite: 'pam',
)
