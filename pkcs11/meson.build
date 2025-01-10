# We want to make sure our PKCS#11 modules only export C_GetFunctionList and some GModule symbols
pkcs11_module_symbolmap = meson.current_source_dir() / 'pkcs11-module.map'
pkcs11_module_linkflags = cc.get_supported_link_arguments(
  '-Wl,--no-undefined',
  '-Wl,--version-script,@0@'.format(pkcs11_module_symbolmap),
)

subdir('gkm')
subdir('rpc-layer')
subdir('wrap-layer')

# The stores
subdir('gnome2-store')
subdir('secret-store')
subdir('ssh-store')
subdir('xdg-store')
