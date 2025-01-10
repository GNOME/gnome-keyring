libgkd_ssh_sources = [
  'gkd-ssh-agent-interaction.c',
  'gkd-ssh-agent-process.c',
  'gkd-ssh-agent-preload.c',
  'gkd-ssh-agent-service.c',
  'gkd-ssh-agent-util.c',
]

libgkd_ssh_deps = [
  glib_dep,
  gio_dep,
  gio_unix_dep,
  gcr_base_dep,
]

libgkd_ssh_lib = static_library('gkd-ssh',
  libgkd_ssh_sources,
  dependencies: libgkd_ssh_deps,
  include_directories: config_h_inc,
)

libgkd_ssh_dep = declare_dependency(
  link_with: libgkd_ssh_lib,
)

# Tests
libgkd_ssh_tests = [
]

libgkd_ssh_tests_cflags = [
  #'-DBUILDDIR="@0@"'.format(meson.current_build_dir()),
]

foreach test_name : libgkd_ssh_tests
  test_bin = executable(test_name,
    '@0@.c'.format(test_name),
    dependencies: [ libgkd_ssh_dep, libgkd_ssh_deps ],
    link_with: libgkd_ssh_testservice,
    c_args: libgkd_ssh_tests_cflags,
    include_directories: config_h_inc,
  )

  test(test_name, test_bin,
    suite: 'gkr-daemon-ssh',
  )
endforeach
