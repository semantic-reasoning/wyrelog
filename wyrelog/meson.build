wyrelog_inc = include_directories('..')

wyrelog_public_headers = files(
  'audit.h',
  'decide.h',
  'engine.h',
  'error.h',
  'events.h',
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
  'wyl-engine.c',
  'wyl-error.c',
  'wyl-events.c',
  'wyl-fsm-principal.c',
  'wyl-fsm-session.c',
  'wyl-guard-expr.c',
  'wyl-handle.c',
  'wyl-id.c',
  'wyl-keyprovider-dev.c',
  'wyl-log.c',
  'wyl-perm.c',
  'wyl-permission-scope.c',
  'wyl-session.c',
  'wyl-version.c',
)

wyrelog_deps = [glib_dep, gio_dep, libchronoid_dep, wirelog_dep]

wyrelog_log_levels = {
  'none' : 0,
  'error' : 1,
  'warn' : 2,
  'info' : 3,
  'debug' : 4,
  'trace' : 5,
}
wyrelog_log_max = wyrelog_log_levels[get_option('wyrelog_log_max_level')]

wyrelog_c_args = [
  '-DWYL_LOG_MAX_LEVEL=' + wyrelog_log_max.to_string(),
]

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

wyrelogd_exe = executable('wyrelogd',
  files('daemon/wyrelogd.c'),
  include_directories : wyrelog_inc,
  dependencies : [wyrelog_dep, glib_dep, gio_dep],
  c_args : [
    '-DWYL_DEFAULT_TEMPLATE_DIR="' + get_option('datadir') / 'wyrelog' / 'access' + '"',
  ],
  install : true,
)
