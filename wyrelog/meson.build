wyrelog_inc = include_directories('..')

wyrelog_public_headers = files(
  'audit.h',
  'decide.h',
  'error.h',
  'handle.h',
  'perm.h',
  'session.h',
  'version.h',
  'wyrelog.h',
)

wyrelog_sources = files(
  'access/decision.c',
  'audit/event.c',
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

wyrelog_deps = [glib_dep, gio_dep, libchronoid_dep]

wyrelog_c_args = []

if get_option('enable_audit').allowed()
  wyrelog_sources += files('audit/conn.c')
  wyrelog_deps += duckdb_dep
  wyrelog_c_args += '-DWYL_HAS_AUDIT'
endif

libwyrelog = library('wyrelog',
  wyrelog_sources,
  include_directories : wyrelog_inc,
  dependencies : wyrelog_deps,
  c_args : wyrelog_c_args,
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
    'audit/iter.c',
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
