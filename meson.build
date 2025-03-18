project('gnome-keyring', 'c',
  version: '48.0',
  meson_version: '>= 1.0',
)

gnome = import('gnome')
i18n = import('i18n')

# Version
gkr_major_version = '3'

# Common variables
cc = meson.get_compiler('c')
gkr_prefix = get_option('prefix')
gkr_bindir = gkr_prefix / get_option('bindir')
gkr_pkglibdir = gkr_prefix / get_option('libdir') / 'gnome-keyring' / 'devel'
config_h_inc = include_directories('.')
po_dir = meson.current_source_dir() / 'po'
source_root = meson.current_source_dir()
build_root = meson.current_build_dir()

# Dependencies
glib_version = '2.80'
glib_version_macro = 'GLIB_VERSION_@0@'.format(glib_version.replace('.', '_'))
glib_dep = declare_dependency(
  dependencies: dependency('glib-2.0', version: f'>= @glib_version@'),
  compile_args: [
    f'-DGLIB_VERSION_MIN_REQUIRED=@glib_version_macro@',
    f'-DGLIB_VERSION_MAX_ALLOWED=@glib_version_macro@',
  ],
)
gio_dep = dependency('gio-2.0', version: f'>= @glib_version@')
gio_unix_dep = dependency('gio-unix-2.0', version: f'>= @glib_version@')
gmodule_dep = dependency('gmodule-no-export-2.0', version: f'>= @glib_version@')
gobject_dep = dependency('gobject-2.0', version: f'>= @glib_version@')
threads_dep = dependency('threads')
gck_dep = dependency('gck-1', version: '>= 3.3.4')
gcr_base_dep = dependency('gcr-base-3', version: '>= 3.27.90')
libgcrypt_dep = dependency('libgcrypt', version: '>= 1.2.2')
libcap_ng_dep = dependency('libcap-ng', required: false)
p11_kit_dep = dependency('p11-kit-1')

libselinux_dep = dependency('libselinux', required: get_option('selinux'))
libsystemd_dep = dependency('libsystemd', required: get_option('systemd'))

if libsystemd_dep.found()
  systemd_user_unit_dir = dependency('systemd').get_variable('systemduserunitdir', pkgconfig_define: ['prefix', gkr_prefix])
endif

if get_option('ssh-agent')
  ssh_agent_bin = find_program('ssh-agent')
  ssh_add_bin = find_program('ssh-add')
endif

if get_option('pam')
  libpam_dep = cc.find_library('pam')
endif

# Check for some types
have_socklen_t = cc.has_type('socklen_t',
  prefix: '\n'.join([
    '#include <sys/types.h>',
    '#include <sys/socket.h>',
    '#include <netdb.h>',
  ]),
)
have_struct_cmsgcred = cc.has_type('struct cmsgcred',
  prefix: '\n'.join([
    '#include <sys/types.h>',
    '#include <sys/socket.h>',
  ]),
)

# Project-wide defines
add_project_arguments([
  '-D_GNU_SOURCE',
  '-DGCK_API_SUBJECT_TO_CHANGE',
  '-DGCR_API_SUBJECT_TO_CHANGE',
], language: 'c')

if get_option('debug-mode')
  add_project_arguments([
    '-DWITH_DEBUG=1',
    '-D_DEBUG=1',
  ], language: 'c')
endif

# Configuration
conf = configuration_data()

conf.set_quoted('GETTEXT_PACKAGE', meson.project_name())
conf.set_quoted('LOCALE_DIR', gkr_prefix / get_option('localedir'))
conf.set_quoted('VERSION', meson.project_version())
conf.set_quoted('LIBGCRYPT_VERSION', libgcrypt_dep.version())
conf.set('HAVE_LIBCAPNG', libcap_ng_dep.found())
conf.set('WITH_SELINUX', libselinux_dep.found())
conf.set('WITH_SYSTEMD', libsystemd_dep.found())
if get_option('ssh-agent')
  conf.set('WITH_SSH', true)
  conf.set_quoted('SSH_AGENT', ssh_agent_bin.full_path())
  conf.set_quoted('SSH_ADD', ssh_add_bin.full_path())
endif
conf.set('DOTLOCK_USE_PTHREAD', true)
conf.set('DOTLOCK_GLIB_LOGGING', true)
conf.set('DOTLOCK_EXT_SYM_PREFIX', '_gkm_')
conf.set('HAVE_SOCKLEN_T', have_socklen_t)
conf.set('HAVE_GETPEERUCRED', cc.has_function('getpeerucred'))
conf.set('HAVE_GETPEEREID', cc.has_function('getpeereid'))
conf.set('HAVE_FLOCK', cc.has_function('flock'))
conf.set('HAVE_MLOCK', cc.has_function('mlock'))
conf.set('HAVE_TIMEGM', cc.has_function('timegm'))
conf.set('HAVE_FSYNC', cc.has_function('fsync'))

configure_file(output: 'config.h', configuration: conf)
config_h_dir = include_directories('.')

# Test variables
test_gkr_daemon_bin = meson.current_build_dir() / 'daemon' / 'gnome-keyring-daemon'

# Build libegg (helper module)
subdir('egg')

# Daemon launch lib (needed for tests)
libgkd_test = library('gkd-test',
  files('daemon/gkd-test.c'),
  dependencies: [glib_dep, libegg_dep ],
  c_args: [ '-DBUILDDIR="@0@"'.format(build_root) ],
)

libgkd_test_dep = declare_dependency(
  link_with: libgkd_test,
)

# Other subdirectories
subdir('po')
subdir('pkcs11')
subdir('daemon')
subdir('schema')
subdir('tool')
if get_option('pam')
  subdir('pam')
endif
subdir('docs')

gnome.post_install(
  glib_compile_schemas: true,
)
