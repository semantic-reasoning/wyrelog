wyrelog_inc = include_directories('..')

wyrelog_public_headers = files(
  'audit.h',
  'break-glass.h',
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
  'access/break-glass.c',
  'access/decision.c',
  'auth/jwt.c',
  'audit/event.c',
  'fact/schema.c',
  'policy/store.c',
  'wyl-boot.c',
  'wyl-decide.c',
  'wyl-dl-static.c',
  'wyl-engine.c',
  'wyl-error.c',
  'wyl-events.c',
  'wyl-fsm-permission-scope.c',
  'wyl-fsm-principal.c',
  'wyl-fsm-session.c',
  'wyl-guard-expr.c',
  'wyl-handle.c',
  'wyl-request-id.c',
  'wyl-id.c',
  'wyl-keyprovider-dev.c',
  'wyl-keyprovider-file.c',
  'wyl-log.c',
  'wyl-perm.c',
  'wyl-permission-scope.c',
  'wyl-session.c',
  'wyl-version.c',
)

wyrelog_deps = [
  glib_dep,
  gio_dep,
  libchronoid_dep,
  sodium_dep,
  sqlite_dep,
  wirelog_dep,
]

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
if get_option('enable_fact_store').allowed()
  wyrelog_sources += files('fact/compound.c', 'fact/replay.c', 'fact/store.c')
  if not get_option('enable_audit').allowed()
    wyrelog_deps += duckdb_dep
  endif
endif
if get_option('enable_fact_store').allowed()
  wyrelog_c_args += '-DWYL_HAS_FACT_STORE'
endif
if get_option('require_template_manifest')
  wyrelog_c_args += '-DWYL_REQUIRE_TEMPLATE_MANIFEST'
endif

if get_option('enable_break_glass')
  wyrelog_c_args += '-DWYL_HAS_BREAK_GLASS'
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
    dependencies : [wyrelog_dep, glib_dep, gio_dep, libsoup_dep],
    install : true,
    soversion : '0',
  )

  install_headers(wyrelog_client_public_headers, subdir : 'wyrelog')

  wyrelog_client_dep = declare_dependency(
    link_with : libwyrelog_client,
    include_directories : wyrelog_inc,
    dependencies : [wyrelog_dep, glib_dep, gio_dep],
  )

  wyctl_exe = executable('wyctl',
    files('wyctl/wyctl.c'),
    include_directories : wyrelog_inc,
    dependencies : [wyrelog_client_dep, glib_dep, gio_dep, libsoup_dep],
    install : true,
  )
else
  wyrelog_client_dep = disabler()
  wyctl_exe = disabler()
endif

wyrelogd_deps = [wyrelog_dep, glib_dep, gio_dep, wirelog_dep]
wyrelogd_c_args = [
  '-DWYL_DEFAULT_TEMPLATE_DIR="' + get_option('datadir') / 'wyrelog' / 'access' + '"',
]
if libsoup_dep.found()
  wyrelogd_deps += [libsoup_dep, sodium_dep]
  wyrelogd_c_args += '-DWYL_HAS_DAEMON_HTTP'
endif
if get_option('enable_audit').allowed()
  wyrelogd_deps += duckdb_dep
  wyrelogd_c_args += '-DWYL_HAS_AUDIT'
elif get_option('enable_fact_store').allowed()
  wyrelogd_deps += duckdb_dep
endif
if get_option('enable_fact_store').allowed()
  wyrelogd_c_args += '-DWYL_HAS_FACT_STORE'
endif
if get_option('enable_break_glass')
  wyrelogd_c_args += '-DWYL_HAS_BREAK_GLASS'
endif

wyrelogd_exe = executable('wyrelogd',
  files(
    'daemon/checks.c',
    'daemon/delta.c',
    'daemon/fact-status.c',
    'daemon/http.c',
    'daemon/options.c',
    'daemon/runtime.c',
    'daemon/signals.c',
    'daemon/wyrelogd.c',
  ),
  include_directories : wyrelog_inc,
  dependencies : wyrelogd_deps,
  c_args : wyrelogd_c_args,
  install : true,
)
