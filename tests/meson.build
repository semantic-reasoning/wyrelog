test_smoke = executable('test-smoke',
  'test-smoke.c',
  dependencies : [wyrelog_dep],
)

test('smoke', test_smoke)

test_boot_smoke = executable('test-boot-smoke',
  'test-boot-smoke.c',
  dependencies : [wyrelog_dep],
)

test('boot-smoke', test_boot_smoke)

test('wyrelogd-check', wyrelogd_exe,
  args : [
    '--template-dir',
    meson.project_source_root() / 'templates' / 'access',
    '--check',
  ],
)

if host_machine.system() != 'windows'
  sh = find_program('sh')
  test('wyrelogd-sigterm', sh,
    args : [
      '-c',
      '"' + wyrelogd_exe.full_path() + '" --template-dir "' + meson.project_source_root() / 'templates' / 'access' + '" --listen-port 0 & pid=$!; sleep 1; kill -TERM "$pid"; wait "$pid"',
    ],
    depends : wyrelogd_exe,
  )

  python3 = find_program('python3')
  test('wyrelogd-healthz', sh,
    args : [
      meson.current_source_dir() / 'check-wyrelogd-healthz.sh',
      wyrelogd_exe.full_path(),
      meson.project_source_root() / 'templates' / 'access',
      python3.full_path(),
    ],
    depends : wyrelogd_exe,
  )
endif

test_client_smoke = executable('test-client-smoke',
  'test-client-smoke.c',
  dependencies : [wyrelog_client_dep, libsoup_dep],
)

test('client-smoke', test_client_smoke)

test_client_audit_daemon_c_args = []
if get_option('enable_audit').allowed()
  test_client_audit_daemon_c_args += '-DWYL_TEST_HAS_AUDIT'
endif

test_client_audit_daemon = executable('test-client-audit-daemon',
  'test-client-audit-daemon.c',
  c_args : test_client_audit_daemon_c_args,
  dependencies : [wyrelog_client_dep],
)

if host_machine.system() != 'windows' and build_client
  test('client-audit-daemon', sh,
    args : [
      meson.current_source_dir() / 'check-client-audit-daemon.sh',
      wyrelogd_exe.full_path(),
      test_client_audit_daemon.full_path(),
      meson.project_source_root() / 'templates' / 'access',
      python3.full_path(),
    ],
    depends : [wyrelogd_exe, test_client_audit_daemon],
  )
endif

test_traits_compile = executable('test-traits-compile',
  'test-traits-compile.c',
  dependencies : [wyrelog_dep],
)

test('traits-compile', test_traits_compile)

test_policy_store = executable('test-policy-store',
  'test-policy-store.c',
  c_args : [
    '-DWYL_TEST_SQLITE_SCHEMA_PATH="' + meson.project_source_root() / 'templates' / 'access' / 'sqlite-schema.sql' + '"',
  ],
  dependencies : [wyrelog_dep, sqlite_dep],
)

test('policy-store', test_policy_store)

test_dl_static = executable('test-dl-static',
  'test-dl-static.c',
  dependencies : [wyrelog_dep],
)

test('dl-static', test_dl_static)

test_log = executable('test-log',
  'test-log.c',
  dependencies : [wyrelog_dep],
)

test('log', test_log)

# Compile with ceiling=WARN (2) to verify disabled levels do not
# evaluate their arguments and CRITICAL still bypasses the ceiling.
test_log_ceiling = executable('test-log-ceiling',
  'test-log-ceiling.c',
  c_args : ['-DWYL_LOG_MAX_LEVEL=2'],
  dependencies : [wyrelog_dep],
)

test('log-ceiling', test_log_ceiling)

fsm_principal_dl_path = join_paths(
  meson.project_source_root(),
  'templates', 'access', 'fsm', 'principal.dl',
)

test_fsm_principal = executable('test-fsm-principal',
  'test-fsm-principal.c',
  c_args : [
    '-DWYL_TEST_FSM_PRINCIPAL_DL_PATH="' + fsm_principal_dl_path + '"',
  ],
  dependencies : [wyrelog_dep],
)

test('fsm-principal', test_fsm_principal)

fsm_session_dl_path = join_paths(
  meson.project_source_root(),
  'templates', 'access', 'fsm', 'session.dl',
)

test_fsm_session = executable('test-fsm-session',
  'test-fsm-session.c',
  c_args : [
    '-DWYL_TEST_FSM_SESSION_DL_PATH="' + fsm_session_dl_path + '"',
  ],
  dependencies : [wyrelog_dep],
)

test('fsm-session', test_fsm_session)

test_guard_expr = executable('test-guard-expr',
  'test-guard-expr.c',
  dependencies : [wyrelog_dep],
)

test('guard-expr', test_guard_expr)

fsm_permission_scope_dl_path = join_paths(
  meson.project_source_root(),
  'templates', 'access', 'fsm', 'permission_scope.dl',
)

test_fsm_permission_scope = executable('test-fsm-permission-scope',
  'test-fsm-permission-scope.c',
  c_args : [
    '-DWYL_TEST_FSM_PERMISSION_SCOPE_DL_PATH="' + fsm_permission_scope_dl_path + '"',
  ],
  dependencies : [wyrelog_dep],
)

test('fsm-permission-scope', test_fsm_permission_scope)

access_decision_dl_path = join_paths(
  meson.project_source_root(),
  'templates', 'access', 'decision.dl',
)

test_access_decision = executable('test-access-decision',
  'test-access-decision.c',
  c_args : [
    '-DWYL_TEST_ACCESS_DECISION_DL_PATH="' + access_decision_dl_path + '"',
  ],
  dependencies : [wyrelog_dep],
)

test('access-decision', test_access_decision)

test_fsm_bisim = executable('test-fsm-bisim',
  'test-fsm-bisim.c',
  c_args : [
    '-DWYL_TEST_FSM_PRINCIPAL_DL_PATH="' + fsm_principal_dl_path + '"',
    '-DWYL_TEST_FSM_SESSION_DL_PATH="' + fsm_session_dl_path + '"',
  ],
  dependencies : [wyrelog_dep],
)

test('fsm-bisim', test_fsm_bisim)

test_events = executable('test-events',
  'test-events.c',
  dependencies : [wyrelog_dep],
)

test('events', test_events)

test_keyprovider_dev = executable('test-keyprovider-dev',
  'test-keyprovider-dev.c',
  dependencies : [wyrelog_dep],
)

test('keyprovider-dev', test_keyprovider_dev)

test_id = executable('test-id',
  'test-id.c',
  dependencies : [wyrelog_dep, libchronoid_dep],
)

test('id', test_id)

test_audit_event = executable('test-audit-event',
  'test-audit-event.c',
  dependencies : [wyrelog_dep],
)

test('audit-event', test_audit_event)

test_handle_id = executable('test-handle-id',
  'test-handle-id.c',
  dependencies : [wyrelog_dep],
)

test('handle-id', test_handle_id)

test_handle_engine_pair = executable('test-handle-engine-pair',
  'test-handle-engine-pair.c',
  c_args : [
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
  ],
  dependencies : [wyrelog_dep, wirelog_dep],
)

test('handle-engine-pair', test_handle_engine_pair)

test_session_id = executable('test-session-id',
  'test-session-id.c',
  dependencies : [wyrelog_dep],
)

test('session-id', test_session_id)

test_login_req = executable('test-login-req',
  'test-login-req.c',
  dependencies : [wyrelog_dep],
)

test('login-req', test_login_req)

test_session_username = executable('test-session-username',
  'test-session-username.c',
  c_args : [
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
  ],
  dependencies : [wyrelog_dep, wirelog_dep],
)

test('session-username', test_session_username)

test_decide_req = executable('test-decide-req',
  'test-decide-req.c',
  dependencies : [wyrelog_dep],
)

test('decide-req', test_decide_req)

test_decide_resp = executable('test-decide-resp',
  'test-decide-resp.c',
  dependencies : [wyrelog_dep],
)

test('decide-resp', test_decide_resp)

test_grant_req = executable('test-grant-req',
  'test-grant-req.c',
  dependencies : [wyrelog_dep],
)

test('grant-req', test_grant_req)

test_revoke_req = executable('test-revoke-req',
  'test-revoke-req.c',
  dependencies : [wyrelog_dep],
)

test('revoke-req', test_revoke_req)

test_decide = executable('test-decide',
  'test-decide.c',
  c_args : [
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
  ],
  dependencies : [wyrelog_dep, wirelog_dep],
)

test('decide', test_decide)

test_perm = executable('test-perm',
  'test-perm.c',
  c_args : [
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
  ],
  dependencies : [wyrelog_dep, wirelog_dep],
)

test('perm', test_perm)

test_session_logout = executable('test-session-logout',
  'test-session-logout.c',
  dependencies : [wyrelog_dep],
)

test('session-logout', test_session_logout)

# NOTE: WYL_TEST_TEMPLATE_DIR points at the in-tree source layout
# only. The installed layout (${datadir}/wyrelog/access) — produced
# by install_subdir at the top-level meson.build — is not
# exercised by these tests. Validation of the installed layout is
# tracked as packaging-CI follow-up rather than unit-test concern.
test_engine = executable('test-engine',
  'test-engine.c',
  c_args : [
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
  ],
  dependencies : [wyrelog_dep, wirelog_dep],
)

test('engine', test_engine)

test_engine_intern = executable('test-engine-intern',
  'test-engine-intern.c',
  c_args : [
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
  ],
  dependencies : [wyrelog_dep, wirelog_dep],
)

test('engine-intern', test_engine_intern)

test_engine_io = executable('test-engine-io',
  'test-engine-io.c',
  c_args : [
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
  ],
  dependencies : [wyrelog_dep, wirelog_dep],
)

test('engine-io', test_engine_io)

check_private_headers = find_program(
  '../tools/check-private-headers-not-installed.sh',
)

test('check-private-headers-not-installed', check_private_headers)

check_public_headers = find_program(
  '../tools/check-public-headers-no-novelty-tokens.sh',
)

test('check-public-headers-no-novelty-tokens', check_public_headers)

if get_option('enable_audit').allowed()
  audit_conn_test_env = environment()
  if host_machine.system() == 'windows' \
      and get_option('duckdb_source') == 'prebuilt'
    # Prepend the prebuilt subproject directory to PATH so the
    # Windows loader can find duckdb.dll at test run time. The DLL
    # is not in dependency.sources (that would feed it into the
    # static-archive link step and fail). Instead we add its
    # directory here.
    audit_conn_test_env.prepend('PATH',
      meson.project_source_root() / 'subprojects'
        / 'duckdb-prebuilt-windows-amd64',
      separator : ';')
  endif

  test_audit_conn = executable('test-audit-conn',
    'test-audit-conn.c',
    c_args : [
      '-DWYL_TEST_DUCKDB_SCHEMA_PATH="' + meson.project_source_root() / 'templates' / 'access' / 'duckdb-schema.sql' + '"',
    ],
    dependencies : [wyrelog_dep, duckdb_dep],
  )

  test('audit-conn', test_audit_conn, env : audit_conn_test_env)

  test_audit_emit = executable('test-audit-emit',
    'test-audit-emit.c',
    c_args : [
      '-DWYL_HAS_AUDIT',
      '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
    ],
    dependencies : [wyrelog_dep, duckdb_dep],
  )

  test('audit-emit', test_audit_emit, env : audit_conn_test_env)
endif
