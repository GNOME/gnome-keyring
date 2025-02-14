gnome_keyring_tool_sources = files(
  'gkr-tool.c',
  'gkr-tool-import.c',
  'gkr-tool-trust.c',
  'gkr-tool-version.c',
)

gnome_keyring_tool_deps = [
  glib_dep,
  gck_dep,
  gcr_base_dep,
  libegg_dep,
]

gnome_keyring_tool_name = f'gnome-keyring-@gkr_major_version@'
gnome_keyring_tool = executable(
  gnome_keyring_tool_name,
  gnome_keyring_tool_sources,
  dependencies: gnome_keyring_tool_deps,
  include_directories: config_h_inc,
  install: true,
  install_dir: gkr_bindir,
)

# Install a link from gnome-keyring > gnome-keyring-@gkr_major_version@ to maintain compatibility
install_symlink(
  'gnome-keyring',
  pointing_to: gnome_keyring_tool_name,
  install_dir: gkr_bindir,
)
