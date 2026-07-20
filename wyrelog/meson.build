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
  'auth/mfa-enrollment.c',
  'auth/mfa-validator.c',
  'auth/service-auth-coordination.c',
  'auth/service-credential.c',
  'auth/service-credential-domain.c',
  'auth/service-credential-handoff-delivery-private.c',
  'auth/service-credential-operation-destination-private.c',
  'auth/service-exchange-audit-private.c',
  'auth/service-credential-operation-journal-private.c',
  'auth/service-credential-operation-coordinator-private.c',
  'auth/service-credential-operation-coordinator-auth-private.c',
  'auth/service-credential-operation-coordinator-proof-private.c',
  'auth/service-credential-operation-coordinator-journal-private.c',
  'auth/service-credential-operation-coordinator-fence-private.c',
  'auth/service-credential-operation-coordinator-recovery-private.c',
  'auth/service-credential-operation-coordinator-maintenance-private.c',
  'auth/service-credential-operation-coordinator-cancel-private.c',
  'auth/service-credential-operation-coordinator-remediate-private.c',
  'auth/service-credential-operation-coordinator-retirement-private.c',
  'auth/service-credential-operation-coordinator-execute-private.c',
  'auth/service-credential-operation-coordinator-storage-private.c',
  'auth/service-credential-operation-storage-private.c',
  'auth/service-credential-operation-storage-windows-private.c',
  'auth/service-exchange-projector-private.c',
  'auth/totp.c',
  'audit/event.c',
  'fact/schema.c',
  'policy/store.c',
  'policy/store-lease.c',
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
if host_machine.system() == 'windows'
  advapi32_dep = meson.get_compiler('c').find_library('Advapi32',
    required : true)
else
  advapi32_dep = disabler()
endif

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

daemon_http_private_dep = disabler()

if get_option('enable_audit').allowed()
  wyrelog_sources += files('audit/conn.c')
  wyrelog_deps += duckdb_dep
  wyrelog_c_args += '-DWYL_HAS_AUDIT'
endif
if get_option('enable_fact_store').allowed()
  wyrelog_sources += files('fact/compound.c', 'fact/query.c',
    'fact/replay.c', 'fact/store.c')
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

# Host-only private companion: never installed and never linked into
# libwyrelog. Focused tests and the exact future #358 daemon owner opt in.
service_session_private_lib = static_library('wyrelog-service-session-private',
  'auth/service-session-private.c',
  'auth/service-jwt-private.c',
  include_directories : wyrelog_inc,
  dependencies : [wyrelog_dep, sodium_dep],
  install : false,
  build_by_default : false,
)

service_session_private_dep = declare_dependency(
  link_with : service_session_private_lib,
  dependencies : [wyrelog_dep],
)

if get_option('enable_audit').allowed()
  # Non-installed host companion for the daemon and focused private tests.
  # libwyrelog retains its canonical copies; every external private consumer
  # shares this single additional compilation context.
  service_exchange_private_lib = static_library(
    'wyrelog-service-exchange-private',
    'auth/service-exchange-private.c',
    'auth/service-exchange-limiter-private.c',
    'auth/service-exchange-audit-private.c',
    'auth/service-exchange-projector-private.c',
    include_directories : wyrelog_inc,
    dependencies : [wyrelog_dep, duckdb_dep, sqlite_dep, sodium_dep,
      libchronoid_dep, service_session_private_dep],
    c_args : ['-DWYL_HAS_AUDIT'],
    install : false,
    build_by_default : false,
  )
  service_exchange_private_dep = declare_dependency(
    link_with : [service_exchange_private_lib, service_session_private_lib],
    dependencies : [wyrelog_dep, duckdb_dep, sqlite_dep, sodium_dep,
      libchronoid_dep, service_session_private_dep],
  )

  service_exchange_startup_private_lib = static_library(
    'wyrelog-service-exchange-startup-private',
    'daemon/startup-recovery-private.c',
    include_directories : wyrelog_inc,
    dependencies : [service_exchange_private_dep],
    c_args : ['-DWYL_HAS_AUDIT'],
    install : false,
    build_by_default : false,
  )
  service_exchange_startup_private_dep = declare_dependency(
    link_with : service_exchange_startup_private_lib,
    dependencies : [service_exchange_private_dep],
  )
endif

build_client = libsoup_dep.found()

if build_client
  wyrelog_client_public_headers = files(
    'client.h',
  )

  wyrelog_client_sources = files(
    'audit/iter.c',
    'wyl-client-codec-private.c',
    'wyl-client-url-private.c',
    'wyl-client.c',
  )

  libwyrelog_client = library('wyrelog-client',
    wyrelog_client_sources,
    include_directories : wyrelog_inc,
    dependencies : [wyrelog_dep, glib_dep, gio_dep, libsoup_dep, sodium_dep],
    install : true,
    soversion : '0',
  )

  install_headers(wyrelog_client_public_headers, subdir : 'wyrelog')

  wyrelog_client_dep = declare_dependency(
    link_with : libwyrelog_client,
    include_directories : wyrelog_inc,
    dependencies : [wyrelog_dep, glib_dep, gio_dep],
  )

  wyctl_deps = [wyrelog_client_dep, glib_dep, gio_dep, libsoup_dep,
    sodium_dep, sqlite_dep]
  if host_machine.system() == 'windows'
    wyctl_deps += advapi32_dep
  endif
  wyctl_exe = executable('wyctl',
    files('wyctl/wyctl.c', 'wyctl/wyctl-config.c',
        'wyctl/wyctl-token-file.c', 'wyctl/wyctl-publication-private.c',
        'wyctl/wyctl-publication-windows-private.c'),
    include_directories : wyrelog_inc,
    dependencies : wyctl_deps,
    install : true,
  )

  install_data(
    'wyctl/org.wyrelog.wyctl.gschema.xml',
    install_dir : get_option('datadir') / 'glib-2.0' / 'schemas',
  )

  gnome = import('gnome')
  gnome.post_install(glib_compile_schemas : true)
else
  wyrelog_client_dep = disabler()
  wyctl_exe = disabler()
endif

wyrelogd_deps = [wyrelog_dep, glib_dep, gio_dep, sqlite_dep, wirelog_dep]
wyrelogd_c_args = [
  '-DWYL_DEFAULT_TEMPLATE_DIR="' + get_option('datadir') / 'wyrelog' / 'access' + '"',
]
if libsoup_dep.found()
  daemon_http_private_lib = static_library('wyrelog-daemon-http-private',
    'daemon/http-guards-private.c',
    include_directories : wyrelog_inc,
    dependencies : [glib_dep, gio_dep, libsoup_dep],
    install : false,
    build_by_default : false,
  )
  daemon_http_private_dep = declare_dependency(
    link_with : daemon_http_private_lib,
    dependencies : [glib_dep, gio_dep, libsoup_dep],
  )
  wyrelogd_deps += [libsoup_dep, sodium_dep, service_session_private_dep]
  wyrelogd_deps += daemon_http_private_dep
  wyrelogd_c_args += '-DWYL_HAS_DAEMON_HTTP'
endif
if get_option('enable_audit').allowed()
  wyrelogd_deps += service_exchange_private_dep
  wyrelogd_deps += service_exchange_startup_private_dep
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

wyrelogd_sources = files(
    'daemon/checks.c',
    'daemon/auth-registry-private.c',
    'daemon/delta.c',
    'daemon/fact-status.c',
    'daemon/http.c',
    'daemon/options.c',
    'daemon/runtime.c',
    'daemon/signals.c',
    'daemon/wyrelogd.c',
)
wyrelogd_exe = executable('wyrelogd',
  wyrelogd_sources,
  include_directories : wyrelog_inc,
  dependencies : wyrelogd_deps,
  c_args : wyrelogd_c_args,
  install : true,
)
