libgkd_login_sources = files(
  'gkd-login.c',
  'gkd-login-interaction.c',
  'gkd-login-password.c',
)

libgkd_login_deps = [
  glib_dep,
  gio_dep,
  gck_dep,
  gcr_base_dep,
]

libgkd_login_lib = static_library('gkd-login',
  libgkd_login_sources,
  dependencies: libgkd_login_deps,
  include_directories: config_h_inc,
)

libgkd_login_dep = declare_dependency(
  link_with: libgkd_login_lib,
)
