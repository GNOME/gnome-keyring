subdir('control')
subdir('dbus')
subdir('login')
if get_option('ssh-agent')
  subdir('ssh-agent')
endif

# The daemon executable
gkr_daemon_sources = files(
  'gkd-main.c',
  'gkd-capability.c',
  'gkd-pkcs11.c',
  'gkd-util.c',
)

if get_option('ssh-agent')
  gkr_daemon_sources += files(
    'gkd-glue.c',
  )
endif

gkr_daemon_deps = [
  gio_dep,
  gio_unix_dep,
  glib_dep,
  gobject_dep,
  libgcrypt_dep,
  libsystemd_dep,

  libegg_dep,
  libgkm_dep,
  libgkm_gnome2_store_dep,
  libgkm_rpc_layer_dep,
  libgkm_secret_store_dep,
  libgkm_ssh_store_dep,
  libgkm_wrap_layer_dep,
  libgkm_xdg_store_dep,
  libgkd_control_dep,
  libgkd_dbus_dep,
  libgkd_login_dep,
]

if get_option('ssh-agent')
  gkr_daemon_deps += libgkd_ssh_dep
endif

if libcap_ng_dep.found()
  gkr_daemon_deps += libcap_ng_dep
endif

gkr_daemon = executable('gnome-keyring-daemon',
  gkr_daemon_sources,
  dependencies: gkr_daemon_deps,
  include_directories: config_h_inc,
  install: true,
  install_rpath: gkr_pkglibdir,
)

# Desktop files
desktop_input_files = [
  'gnome-keyring-pkcs11.desktop.in.in',
  'gnome-keyring-secrets.desktop.in.in',
]

if get_option('ssh-agent')
  desktop_input_files += 'gnome-keyring-ssh.desktop.in.in'
endif

autostartdir = join_paths(get_option('sysconfdir'), 'xdg', 'autostart')

foreach desktop_input_file : desktop_input_files
  i18n.merge_file(
    input: configure_file(
      input: desktop_input_file,
      output: '@BASENAME@',
      configuration: {
        'bindir': gkr_bindir,
        'VERSION': meson.project_version(),
      },
    ),
    output: '@BASENAME@',
    type: 'desktop',
    po_dir: po_dir,
    install: true,
    install_dir: autostartdir,
  )
endforeach

# Service files
service_input_files = [
  'org.gnome.keyring.service.in',
  'org.freedesktop.secrets.service.in',
  'org.freedesktop.impl.portal.Secret.service.in',
]

foreach service_input_file : service_input_files
  configure_file(
    input: service_input_file,
    output: '@BASENAME@',
    configuration: {
      'bindir': gkr_bindir,
    },
    install_dir: get_option('datadir') / 'dbus-1' / 'services',
  )
endforeach

if libsystemd_dep.found()
  configure_file(
    input: 'gnome-keyring-daemon.service.in',
    output: '@BASENAME@',
    configuration: {
      'bindir': gkr_bindir,
    },
    install_dir: systemd_user_unit_dir,
  )

  install_data(
    'gnome-keyring-daemon.socket',
    install_dir: systemd_user_unit_dir,
  )
endif

# Portal files
install_data('gnome-keyring.portal',
  install_dir: get_option('datadir') / 'xdg-desktop-portal' / 'portals',
)

# Tests
gkr_daemon_tests = [
  'startup',
  'shutdown',
]

gkr_daemon_tests_cflags = [
  f'-DSRCDIR="@source_root@"',
  f'-DTEST_GKR_DAEMON_BIN="@test_gkr_daemon_bin@"',
]

foreach test_name : gkr_daemon_tests
  test_bin = executable(test_name,
    f'test-@test_name@.c',
    dependencies: [ gkr_daemon_deps, libgkd_test_dep ],
    c_args: gkr_daemon_tests_cflags,
    include_directories: config_h_inc,
  )

  test(test_name, test_bin,
    suite: 'gkr-daemon',
    is_parallel: false,
  )
endforeach
