libgkd_control_sources = files(
  'gkd-control-server.c',
  'gkd-control-client.c',
)

libgkd_control_deps = [
  glib_dep,
  libegg_dep,
]

libgkd_control = static_library('gkd-control',
  libgkd_control_sources,
  dependencies: libgkd_control_deps,
  include_directories: config_h_inc,
)

libgkd_control_dep = declare_dependency(
  link_with: libgkd_control,
)

# Tests
libgkd_control_tests = [
  'frob-control-change',
  'frob-control-init',
  'frob-control-unlock',
  'frob-control-quit',
]

foreach test_name : libgkd_control_tests
  test_bin = executable(test_name,
    '@0@.c'.format(test_name),
    dependencies: [ libgkd_control_dep, libgkd_control_deps ],
  )
endforeach
