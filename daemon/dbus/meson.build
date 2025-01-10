libgkd_dbus_secrets_gen = gnome.gdbus_codegen('gkd-secrets-generated',
  sources: 'org.freedesktop.Secrets.xml',
  interface_prefix: 'org.freedesktop.Secrets.',
  namespace: 'Gkd',
  annotations: [
    [ 'org.freedesktop.Secret.Service',    'org.gtk.GDBus.C.Name', 'ExportedService'    ],
    [ 'org.freedesktop.Secret.Collection', 'org.gtk.GDBus.C.Name', 'ExportedCollection' ],
    [ 'org.freedesktop.Secret.Item',       'org.gtk.GDBus.C.Name', 'ExportedItem'       ],
    [ 'org.freedesktop.Secret.Session',    'org.gtk.GDBus.C.Name', 'ExportedSession'    ],
    [ 'org.freedesktop.Secret.Prompt',     'org.gtk.GDBus.C.Name', 'ExportedPrompt'     ],
  ],
  autocleanup: 'all',
)

libgkd_dbus_daemon_gen = gnome.gdbus_codegen('gkd-daemon-generated',
  sources: 'org.gnome.keyring.Daemon.xml',
  interface_prefix: 'org.gnome.keyring.Daemon',
  namespace: 'Gkd',
  annotations: [
    [ 'org.gnome.keyring.Daemon', 'org.gtk.GDBus.C.Name', 'ExportedDaemon' ],
  ],
  autocleanup: 'all',
)

libgkd_dbus_internal_gen = gnome.gdbus_codegen('gkd-internal-generated',
  sources: 'org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface.xml',
  interface_prefix: 'org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface',
  namespace: 'Gkd',
  annotations: [
    [ 'org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface', 'org.gtk.GDBus.C.Name', 'ExportedInternal' ],
  ],
  autocleanup: 'all',
)

libgkd_dbus_portal_gen = gnome.gdbus_codegen('gkd-portal-generated',
  sources: 'org.freedesktop.impl.portal.Secret.xml',
  interface_prefix: 'org.freedesktop.impl.portal.Secret.',
  namespace: 'Gkd',
  annotations: [
    [ 'org.freedesktop.impl.portal.Secret', 'org.gtk.GDBus.C.Name', 'ExportedPortal' ],
  ],
  autocleanup: 'all',
)

libgkd_dbus_portalreq_gen = gnome.gdbus_codegen('gkd-portal-request-generated',
  sources: 'org.freedesktop.impl.portal.Request.xml',
  interface_prefix: 'org.freedesktop.impl.portal.Request.',
  namespace: 'Gkd',
  annotations: [
    [ 'org.freedesktop.impl.portal.Request', 'org.gtk.GDBus.C.Name', 'ExportedPortalRequest' ],
  ],
  autocleanup: 'all',
)

libgkd_dbus_sources = [
  'gkd-dbus.c',
  'gkd-dbus-environment.c',
  'gkd-dbus-secrets.c',
  'gkd-dbus-session.c',
  'gkd-secret-change.c',
  'gkd-secret-create.c',
  'gkd-secret-dispatch.c',
  'gkd-secret-error.c',
  'gkd-secret-exchange.c',
  'gkd-secret-lock.c',
  'gkd-secret-objects.c',
  'gkd-secret-portal.c',
  'gkd-secret-property.c',
  'gkd-secret-prompt.c',
  'gkd-secret-secret.c',
  'gkd-secret-service.c',
  'gkd-secret-session.c',
  'gkd-secret-unlock.c',
  'gkd-secret-util.c',

  libgkd_dbus_secrets_gen,
  libgkd_dbus_daemon_gen,
  libgkd_dbus_internal_gen,
  libgkd_dbus_portal_gen,
  libgkd_dbus_portalreq_gen,
]

libgkd_dbus_deps = [
  glib_dep,
  gio_dep,
  gio_unix_dep,
  gobject_dep,
  gck_dep,
  gcr_base_dep,
  libegg_dep,
]

libgkd_dbus_lib = static_library('gkd-dbus',
  libgkd_dbus_sources,
  dependencies: libgkd_dbus_deps,
  include_directories: config_h_inc,
)

libgkd_dbus_dep = declare_dependency(
  link_with: libgkd_dbus_lib,
)

# Tests
libgkd_dbus_testservice_deps = [
  glib_dep,
  gio_dep,
  gobject_dep,
  libegg_dep,
  libgcrypt_dep,
  libgkd_test_dep,
]

libgkd_dbus_testservice_cflags = [
  '-DSRCDIR="@0@"'.format(source_root),
  f'-DTEST_GKR_DAEMON_BIN="@test_gkr_daemon_bin@"',
]

libgkd_dbus_testservice = library('gkr-daemon-test-service',
  'test-service.c',
  dependencies: libgkd_dbus_testservice_deps,
  c_args: libgkd_dbus_testservice_cflags,
  include_directories: config_h_inc,
)

libgkd_dbus_tests = [
  'dbus-util',
  'dbus-search',
  'dbus-items',
  'dbus-signals',
  'dbus-lock',
  'dbus-portal',
]

libgkd_dbus_tests_deps = [
  libgkd_test_dep,
  libgkd_dbus_dep,
  libgkd_dbus_deps,
]

libgkd_dbus_tests_cflags = [
]

foreach test_name : libgkd_dbus_tests
  test_bin = executable(test_name,
    f'test-@test_name@.c',
    dependencies: libgkd_dbus_tests_deps,
    link_with: libgkd_dbus_testservice,
    c_args: libgkd_dbus_tests_cflags,
    include_directories: config_h_inc,
  )

  test(test_name, test_bin,
    suite: 'gkr-daemon-dbus',
  )
endforeach
