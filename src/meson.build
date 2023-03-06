tokenverification_gui_sources = [
  'server/TokenConfigServerInterface.vala',
  'gui/TokenApplication.vala',
  'gui/TokenWindow.vala',
  'gui/main.vala',
  'gui/TokenJsAdapter.vala'
]

tokenverification_server_sources = [
  'server/main.vala',
  'server/TokenConfigServer.vala',
  'server/TokenConfigServerInterface.vala'
]

tokenverification_daemon_sources = [
  'main.vala'
]

glib = dependency('glib-2.0',      version: '>= 2.50')
gio = dependency('gio-2.0',       version: '>= 2.50')
gee = dependency('gee-0.8',       version: '>= 0.20')
gobject = dependency('gobject-2.0')
soup = dependency('libsoup-2.4')
gnome = import('gnome')
json = dependency('json-glib-1.0', method : 'pkg-config')
template_glib = dependency('template-glib-1.0', required: true)
webkit = dependency('webkit2gtk-4.0')
jwt = dependency('libjwt', method : 'pkg-config')
gnutls = dependency('gnutls', method : 'pkg-config')
gcrypt = dependency('libgcrypt', method : 'pkg-config')

tokenverification_deps = [
  glib,
  gio,
  gee,
  gobject,
  soup,
  gcrypt,
  template_glib,
  json
]

cargs = [
   '-g'
 ]

# Zuel_sources = Zuel_sources + gnome.compile_resources('app-resources', '../app. gresource.xml', source_dir: '../')

tokenverification_gui_sources += gnome.compile_resources('tokenverification-gui-resources',
  'tokenverification.gresource.xml',
  c_name: 'tokenverification_gui',
  source_dir: ['../']
)

executable('tokenverification-gui', tokenverification_gui_sources,
  dependencies: tokenverification_deps + webkit + dependency('gtk+-3.0'),
       install: true,
       c_args: cargs
)

executable('tokenverification-server', tokenverification_server_sources,
  dependencies: tokenverification_deps,
       install: true,
       c_args: cargs
)

executable('tokenverification-daemon', tokenverification_daemon_sources,
  dependencies: tokenverification_deps,
       install: true,
)
