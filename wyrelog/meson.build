wyrelog_inc = include_directories('..')

wyrelog_public_headers = files(
  'error.h',
  'wyrelog.h',
)

wyrelog_sources = files(
  'wyl-access-decision.c',
  'wyl-audit-event.c',
  'wyl-boot.c',
  'wyl-decide.c',
  'wyl-dl-static.c',
  'wyl-error.c',
  'wyl-events.c',
  'wyl-fsm-principal.c',
  'wyl-fsm-session.c',
  'wyl-guard-expr.c',
  'wyl-handle.c',
  'wyl-id.c',
  'wyl-keyprovider-dev.c',
  'wyl-perm.c',
  'wyl-permission-scope.c',
  'wyl-session.c',
  'wyl-version.c',
)

libwyrelog = library('wyrelog',
  wyrelog_sources,
  include_directories : wyrelog_inc,
  dependencies : [glib_dep, gio_dep, libchronoid_dep],
  install : true,
  soversion : '0',
)

install_headers(wyrelog_public_headers, subdir : 'wyrelog')

wyrelog_dep = declare_dependency(
  link_with : libwyrelog,
  include_directories : wyrelog_inc,
  dependencies : [glib_dep, gio_dep],
)

build_client = libsoup_dep.found()

if build_client
  wyrelog_client_public_headers = files(
    'client.h',
  )

  wyrelog_client_sources = files(
    'wyl-audit-iter.c',
    'wyl-client.c',
  )

  libwyrelog_client = library('wyrelog-client',
    wyrelog_client_sources,
    include_directories : wyrelog_inc,
    dependencies : [glib_dep, gio_dep, libsoup_dep],
    install : true,
    soversion : '0',
  )

  install_headers(wyrelog_client_public_headers, subdir : 'wyrelog')

  wyrelog_client_dep = declare_dependency(
    link_with : libwyrelog_client,
    include_directories : wyrelog_inc,
    dependencies : [glib_dep, gio_dep],
  )
else
  wyrelog_client_dep = disabler()
endif
