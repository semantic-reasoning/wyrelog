fs = import('fs')
python3 = find_program('python3')
if host_machine.system() == 'windows'
  advapi32_dep = meson.get_compiler('c').find_library('Advapi32',
    required : true)
endif

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
  test('wyrelogd-production-gates', sh,
    args : [
      meson.current_source_dir() / 'check-wyrelogd-production-gates.sh',
      wyrelogd_exe.full_path(),
      meson.project_source_root() / 'templates' / 'access',
      python3.full_path(),
    ],
    depends : wyrelogd_exe,
  )

  test('wyrelogd-profiles', sh,
    args : [
      meson.current_source_dir() / 'check-wyrelogd-profiles.sh',
      wyrelogd_exe.full_path(),
      meson.project_source_root() / 'templates' / 'access',
      python3.full_path(),
    ],
    depends : wyrelogd_exe,
    timeout : 60,
  )

  # Subprocess-level coverage for the --config TOCTOU gate and the
  # --profile-info bootstrap-key staleness probe. The in-process unit
  # tests (test-daemon-options) reach the helpers via reference
  # implementations; this test drives the daemon binary end-to-end so
  # the real open(2)/fstat(2)/sqlite3 paths are exercised.
  test('wyrelogd-conf-gate', sh,
    args : [
      meson.current_source_dir() / 'check-wyrelogd-conf-gate.sh',
      wyrelogd_exe.full_path(),
      meson.project_source_root() / 'templates' / 'access',
      python3.full_path(),
    ],
    depends : wyrelogd_exe,
    timeout : 60,
  )

  wyrelogd_sigterm_cmd = '"' + wyrelogd_exe.full_path()
  wyrelogd_sigterm_cmd += '" --template-dir "'
  wyrelogd_sigterm_cmd += meson.project_source_root() / 'templates' / 'access'
  wyrelogd_sigterm_cmd += '"'
  if build_client
    wyrelogd_sigterm_cmd += ' --listen-port 0'
  endif
  wyrelogd_sigterm_cmd += ' & pid=$!; sleep 1; kill -TERM "$pid"; wait "$pid"'
  test('wyrelogd-sigterm', sh,
    args : [
      '-c',
      wyrelogd_sigterm_cmd,
    ],
    depends : wyrelogd_exe,
  )

  if build_client
    wyrelogd_healthz_expect_audit = '0'
    if get_option('enable_audit').allowed()
      wyrelogd_healthz_expect_audit = '1'
    endif
    test('wyrelogd-healthz', sh,
      args : [
        meson.current_source_dir() / 'check-wyrelogd-healthz.sh',
        wyrelogd_exe.full_path(),
        meson.project_source_root() / 'templates' / 'access',
        python3.full_path(),
        wyrelogd_healthz_expect_audit,
      ],
      depends : wyrelogd_exe,
    )
    test('wyrelogd-startup-readiness', sh,
      args : [
        meson.current_source_dir() / 'check-wyrelogd-startup-readiness.sh',
        wyrelogd_exe.full_path(),
        meson.project_source_root() / 'templates' / 'access',
        python3.full_path(),
      ],
      depends : wyrelogd_exe,
    )
    if get_option('enable_audit').allowed()
      test('wyrelogd-bootstrap-admin', sh,
        args : [
          meson.current_source_dir() / 'check-wyrelogd-bootstrap-admin.sh',
          wyrelogd_exe.full_path(),
          wyctl_exe.full_path(),
          meson.project_source_root() / 'templates' / 'access',
          python3.full_path(),
        ],
        depends : [wyrelogd_exe, wyctl_exe],
        timeout : 180,
      )
    endif
  endif
endif

test_client_smoke = executable('test-client-smoke',
  'test-client-smoke.c',
  dependencies : [wyrelog_client_dep, libsoup_dep],
)

test('client-smoke', test_client_smoke)

if build_client
  test('client-exports', python3,
    args : [
      meson.project_source_root() / 'tools' / 'check-client-exports.py',
      libwyrelog_client.full_path(),
    ],
  )
endif

if build_client
  test_daemon_http_decide_c_args = [
    '-DWYL_HAS_DAEMON_HTTP',
    '-DWYL_TEST_DAEMON_HTTP',
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
    # The four daemon-http-decide variants share one source file with one
    # main() per variant; helpers irrelevant to the active variant remain
    # defined to keep the source readable.
    '-Wno-unused-function',
  ]
  test_daemon_http_decide_deps = [
    wyrelog_dep,
    wyrelog_client_dep,
    libsoup_dep,
    sodium_dep,
    service_session_private_dep,
  ]
  if get_option('enable_fact_store').allowed()
    test_daemon_http_decide_c_args += '-DWYL_HAS_FACT_STORE'
    test_daemon_http_decide_deps += duckdb_dep
  endif
  if get_option('enable_audit').allowed()
    test_daemon_http_decide_c_args += '-DWYL_HAS_AUDIT'
    test_daemon_http_decide_deps += duckdb_dep
    test_daemon_http_decide_deps += service_exchange_private_dep
  endif
  test_daemon_http_decide_deps += daemon_http_private_dep
  test_daemon_http_decide = executable('test-daemon-http-decide',
    'test-daemon-http-decide.c',
    '../wyrelog/daemon/auth-registry-private.c',
    '../wyrelog/daemon/http.c',
    '../wyrelog/daemon/delta.c',
    '../wyrelog/daemon/fact-status.c',
    c_args : test_daemon_http_decide_c_args,
    include_directories : [wyrelog_inc, include_directories('../wyrelog')],
    dependencies : test_daemon_http_decide_deps,
  )

  test('daemon-http-decide', test_daemon_http_decide, timeout : 240)

  test_daemon_http_decide_refresh = executable('test-daemon-http-decide-refresh',
    'test-daemon-http-decide.c',
    '../wyrelog/daemon/auth-registry-private.c',
    '../wyrelog/daemon/http.c',
    '../wyrelog/daemon/delta.c',
    '../wyrelog/daemon/fact-status.c',
    c_args : test_daemon_http_decide_c_args + '-DWYL_TEST_VARIANT_REFRESH',
    include_directories : [wyrelog_inc, include_directories('../wyrelog')],
    dependencies : test_daemon_http_decide_deps,
  )

  test('daemon-http-decide-refresh', test_daemon_http_decide_refresh,
    timeout : 960,
  )

  test_daemon_http_decide_service = executable('test-daemon-http-decide-service',
    'test-daemon-http-decide.c',
    '../wyrelog/daemon/auth-registry-private.c',
    '../wyrelog/daemon/http.c',
    '../wyrelog/daemon/delta.c',
    '../wyrelog/daemon/fact-status.c',
    c_args : test_daemon_http_decide_c_args + '-DWYL_TEST_VARIANT_SERVICE',
    include_directories : [wyrelog_inc, include_directories('../wyrelog')],
    dependencies : test_daemon_http_decide_deps,
  )

  test('daemon-http-decide-service', test_daemon_http_decide_service,
    timeout : 240,
  )

  if get_option('enable_audit').allowed()
    test_daemon_http_decide_audit = executable('test-daemon-http-decide-audit',
      'test-daemon-http-decide.c',
      '../wyrelog/daemon/auth-registry-private.c',
      '../wyrelog/daemon/http.c',
      '../wyrelog/daemon/delta.c',
      '../wyrelog/daemon/fact-status.c',
      c_args : test_daemon_http_decide_c_args + '-DWYL_TEST_VARIANT_AUDIT',
      include_directories : [wyrelog_inc, include_directories('../wyrelog')],
      dependencies : test_daemon_http_decide_deps,
    )

    test('daemon-http-decide-audit', test_daemon_http_decide_audit,
      timeout : 240,
    )
  endif

  test_daemon_http_guards = executable('test-daemon-http-guards',
    'test-daemon-http-guards.c',
    dependencies : [wyrelog_dep, libsoup_dep, daemon_http_private_dep],
  )
  test('daemon-http-guards', test_daemon_http_guards)

  test('daemon-http-guards-structure', python3,
    args : [
      meson.current_source_dir() / 'test-daemon-http-guards-structure.py',
      meson.project_source_root() / 'wyrelog' / 'daemon' / 'http.c',
    ],
  )

  test_daemon_http_mfa_c_args = [
    '-DWYL_HAS_DAEMON_HTTP',
    '-DWYL_TEST_DAEMON_HTTP',
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
  ]
  test_daemon_http_mfa_deps = [
    wyrelog_dep,
    wyrelog_client_dep,
    libsoup_dep,
    sodium_dep,
    sqlite_dep,
    service_session_private_dep,
  ]
  if get_option('enable_fact_store').allowed()
    test_daemon_http_mfa_c_args += '-DWYL_HAS_FACT_STORE'
    test_daemon_http_mfa_deps += duckdb_dep
  endif
  if get_option('enable_audit').allowed()
    test_daemon_http_mfa_c_args += '-DWYL_HAS_AUDIT'
    test_daemon_http_mfa_deps += duckdb_dep
    test_daemon_http_mfa_deps += service_exchange_private_dep
  endif
  test_daemon_http_mfa_deps += daemon_http_private_dep
  test_daemon_http_mfa = executable('test-daemon-http-mfa',
    'test-daemon-http-mfa.c',
    '../wyrelog/daemon/auth-registry-private.c',
    '../wyrelog/daemon/http.c',
    '../wyrelog/daemon/delta.c',
    '../wyrelog/daemon/fact-status.c',
    c_args : test_daemon_http_mfa_c_args,
    include_directories : [wyrelog_inc, include_directories('../wyrelog')],
    dependencies : test_daemon_http_mfa_deps,
  )

  test('daemon-http-mfa', test_daemon_http_mfa, timeout : 60)

  if get_option('enable_fact_store').allowed()
    test_daemon_http_facts_c_args = [
      '-DWYL_HAS_DAEMON_HTTP',
      '-DWYL_HAS_FACT_STORE',
      '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
    ]
    test_daemon_http_facts_deps = [
      wyrelog_dep,
      wyrelog_client_dep,
      libsoup_dep,
      sodium_dep,
      duckdb_dep,
      sqlite_dep,
      service_session_private_dep,
    ]
    if get_option('enable_audit').allowed()
      test_daemon_http_facts_c_args += '-DWYL_HAS_AUDIT'
      test_daemon_http_facts_deps += duckdb_dep
      test_daemon_http_facts_deps += service_exchange_private_dep
    endif
    test_daemon_http_facts_deps += daemon_http_private_dep
    test_daemon_http_facts = executable('test-daemon-http-facts',
      'test-daemon-http-facts.c',
      '../wyrelog/daemon/auth-registry-private.c',
      '../wyrelog/daemon/http.c',
      '../wyrelog/daemon/delta.c',
      '../wyrelog/daemon/fact-status.c',
      c_args : test_daemon_http_facts_c_args,
      include_directories : [wyrelog_inc, include_directories('../wyrelog')],
      dependencies : test_daemon_http_facts_deps,
    )

    test('daemon-http-facts', test_daemon_http_facts,
      timeout : 60,
    )
  endif
endif

test_client_audit_daemon_c_args = []
if get_option('enable_audit').allowed()
  test_client_audit_daemon_c_args += '-DWYL_TEST_HAS_AUDIT'
endif

test_client_audit_daemon = executable('test-client-audit-daemon',
  'test-client-audit-daemon.c',
  c_args : test_client_audit_daemon_c_args,
  dependencies : [wyrelog_client_dep],
)

if build_client and host_machine.system() != 'windows'
  glib_compile_schemas_prog = find_program('glib-compile-schemas')

  wyctl_gschema_staged = configure_file(
    input : '../wyrelog/wyctl/org.wyrelog.wyctl.gschema.xml',
    output : 'org.wyrelog.wyctl.gschema.xml',
    copy : true,
  )

  wyctl_gschemas_compiled = custom_target('wyctl-gschemas-compiled',
    input : wyctl_gschema_staged,
    output : 'gschemas.compiled',
    command : [glib_compile_schemas_prog, '--strict',
               '--targetdir=@OUTDIR@', meson.current_build_dir()],
    build_by_default : true,
  )

  wyctl_gsettings_test_env = environment()
  wyctl_gsettings_test_env.set('GSETTINGS_SCHEMA_DIR',
    meson.current_build_dir())
  wyctl_gsettings_test_env.set('GSETTINGS_BACKEND', 'memory')

  test_wyctl_gschema = executable('test-wyctl-gschema',
    'test-wyctl-gschema.c',
    dependencies : [glib_dep, gio_dep],
  )

  test('wyctl-gschema', test_wyctl_gschema,
    depends : wyctl_gschemas_compiled,
    env : wyctl_gsettings_test_env,
  )

  test_wyctl_config = executable('test-wyctl-config',
    'test-wyctl-config.c',
    '../wyrelog/wyctl/wyctl-config.c',
    include_directories : include_directories('../wyrelog/wyctl'),
    dependencies : [glib_dep, gio_dep],
  )

  test('wyctl-config', test_wyctl_config,
    depends : wyctl_gschemas_compiled,
    env : wyctl_gsettings_test_env,
  )

  test_wyctl_token_file_deps = [glib_dep]
  if host_machine.system() == 'windows'
    test_wyctl_token_file_deps += advapi32_dep
  endif
  test_wyctl_token_file = executable('test-wyctl-token-file',
    'test-wyctl-token-file.c',
    '../wyrelog/wyctl/wyctl-token-file.c',
    include_directories : include_directories('../wyrelog/wyctl'),
    dependencies : test_wyctl_token_file_deps,
  )

  test('wyctl-token-file', test_wyctl_token_file)

  test_wyctl_publication = executable('test-wyctl-publication',
    'test-wyctl-publication.c',
    '../wyrelog/wyctl/wyctl-publication-private.c',
    include_directories : [include_directories('../wyrelog'),
      include_directories('../wyrelog/wyctl')],
    dependencies : [wyrelog_dep, sodium_dep],
  )

  test('wyctl-publication', test_wyctl_publication)

  if host_machine.system() != 'windows'
    test_wyctl_publication_posix = executable('test-wyctl-publication-posix',
      'test-wyctl-publication-posix.c',
      '../wyrelog/wyctl/wyctl-publication-private.c',
      '../wyrelog/wyctl/wyctl-publication-posix-private.c',
      include_directories : [include_directories('../wyrelog'),
        include_directories('../wyrelog/wyctl')],
      dependencies : [wyrelog_dep, sodium_dep],
    )

    test('wyctl-publication-posix', test_wyctl_publication_posix)
  else
    test_wyctl_publication_windows = executable('test-wyctl-publication-windows',
      'test-wyctl-publication-windows.c',
      '../wyrelog/wyctl/wyctl-publication-private.c',
      '../wyrelog/wyctl/wyctl-publication-windows-private.c',
      c_args : ['-DWYL_TEST_WYCTL_PUBLICATION_WINDOWS'],
      include_directories : [include_directories('../wyrelog'),
        include_directories('../wyrelog/wyctl')],
      dependencies : [wyrelog_dep, sodium_dep, advapi32_dep],
    )

    test('wyctl-publication-windows', test_wyctl_publication_windows)
  endif

  test_wyctl_basic = executable('test-wyctl-basic',
    'test-wyctl-basic.c',
    c_args : [
      '-DWYL_TEST_WYCTL_PATH="' + wyctl_exe.full_path() + '"',
    ],
    dependencies : [glib_dep, gio_dep],
  )

  test('wyctl-basic', test_wyctl_basic,
    depends : [wyctl_exe, wyctl_gschemas_compiled],
    env : wyctl_gsettings_test_env,
    timeout : 60,
  )

  test_wyctl_mfa = executable('test-wyctl-mfa',
    'test-wyctl-mfa.c',
    c_args : [
      '-DWYL_TEST_WYCTL_PATH="' + wyctl_exe.full_path() + '"',
    ],
    include_directories : [wyrelog_inc, include_directories('../wyrelog')],
    dependencies : [wyrelog_dep, glib_dep, gio_dep, sqlite_dep, sodium_dep],
  )

  # The MFA harness now exercises the GSettings fallback for --store /
  # --keyprovider (issue #333), so it needs the compiled schema on
  # GSETTINGS_SCHEMA_DIR and the memory backend, just like the
  # wyctl-config / wyctl-basic tests.  Per-test XDG-keyfile fixtures
  # then layer a real GSettings keyfile on top of that schema dir.
  test('wyctl-mfa', test_wyctl_mfa,
    depends : [wyctl_exe, wyctl_gschemas_compiled],
    env : wyctl_gsettings_test_env,
    timeout : 60,
  )

  # Drives `wyctl key status --store' and `wyctl key recover' as a subprocess
  # against an encrypted policy store, fabricating clean-NEW and interrupted
  # OLD+PENDING on-disk states in-process via the rotation crash seam.
  test_wyctl_key = executable('test-wyctl-key',
    'test-wyctl-key.c',
    c_args : [
      '-DWYL_TEST_WYCTL_PATH="' + wyctl_exe.full_path() + '"',
    ],
    include_directories : [wyrelog_inc, include_directories('../wyrelog')],
    dependencies : [wyrelog_dep, glib_dep, gio_dep, sodium_dep],
  )

  test('wyctl-key', test_wyctl_key,
    depends : [wyctl_exe],
    timeout : 60,
  )

  # End-to-end: drives wyctl as a subprocess against an in-process daemon
  # so the policy mutation subcommands exercise the full client -> HTTP
  # -> handler path, including bearer-only credentials and the privileged
  # operator the daemon CLI cannot seed on its own.
  test_wyctl_policy_daemon_c_args = [
    '-DWYL_HAS_DAEMON_HTTP',
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
    '-DWYL_TEST_WYCTL_PATH="' + wyctl_exe.full_path() + '"',
  ]
  test_wyctl_policy_daemon_deps = [
    wyrelog_dep,
    wyrelog_client_dep,
    libsoup_dep,
    sodium_dep,
    service_session_private_dep,
  ]
  if get_option('enable_fact_store').allowed()
    test_wyctl_policy_daemon_c_args += '-DWYL_HAS_FACT_STORE'
    test_wyctl_policy_daemon_deps += duckdb_dep
  endif
  test_wyctl_policy_daemon_deps += daemon_http_private_dep
  test_wyctl_policy_daemon = executable('test-wyctl-policy-daemon',
    'test-wyctl-policy-daemon.c',
    '../wyrelog/daemon/auth-registry-private.c',
    '../wyrelog/daemon/http.c',
    '../wyrelog/daemon/delta.c',
    '../wyrelog/daemon/fact-status.c',
    c_args : test_wyctl_policy_daemon_c_args,
    include_directories : [wyrelog_inc, include_directories('../wyrelog')],
    dependencies : test_wyctl_policy_daemon_deps,
  )

  test('wyctl-policy-daemon', test_wyctl_policy_daemon,
    depends : wyctl_exe,
  )
endif

if host_machine.system() != 'windows' and build_client
  test('wyctl-status-daemon', sh,
    args : [
      meson.current_source_dir() / 'check-wyctl-status-daemon.sh',
      wyctl_exe.full_path(),
      wyrelogd_exe.full_path(),
      meson.project_source_root() / 'templates' / 'access',
      python3.full_path(),
    ],
    depends : [wyctl_exe, wyrelogd_exe],
  )

  test('packaged-install-readiness', sh,
    args : [
      meson.current_source_dir() / 'check-packaged-install-readiness.sh',
      wyrelogd_exe.full_path(),
      wyctl_exe.full_path(),
      meson.project_source_root() / 'templates' / 'access',
      meson.project_source_root(),
      python3.full_path(),
    ],
    depends : [wyctl_exe, wyrelogd_exe],
    # This smoke test exercises the packaged template tree, production
    # --check, credential KeyProvider setup, encrypted-store key rotation,
    # and a live daemon readiness probe.  Keep it isolated from the heavier
    # daemon/audit integration tests so CI runner contention does not trip
    # Meson's default 30s timeout while still keeping a bounded deadline.
    is_parallel : false,
    timeout : 60,
  )

  if get_option('enable_audit').allowed() and get_option('enable_fact_store').allowed()
    test('wyrelogd-datalog-product-flow', sh,
      args : [
        meson.current_source_dir() / 'check-wyrelogd-datalog-product-flow.sh',
        wyrelogd_exe.full_path(),
        wyctl_exe.full_path(),
        meson.project_source_root() / 'templates' / 'access',
        python3.full_path(),
      ],
      depends : [wyctl_exe, wyrelogd_exe],
      is_parallel : false,
      timeout : 90,
    )
  endif

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

test('policy-store', test_policy_store,
  timeout : 90,
)

test_policy_store_service_schema = executable('test-policy-store-service-schema',
  'test-policy-store-service-schema.c',
  c_args : [
    '-DWYL_TEST_SQLITE_SCHEMA_PATH="' + meson.project_source_root() / 'templates' / 'access' / 'sqlite-schema.sql' + '"',
  ],
  include_directories : include_directories('../wyrelog'),
  dependencies : [wyrelog_dep, sqlite_dep],
)

test('policy-store-service-schema', test_policy_store_service_schema,
  timeout : 90,
)

test_fact_schema = executable('test-fact-schema',
  'test-fact-schema.c',
  include_directories : include_directories('../wyrelog'),
  dependencies : [wyrelog_dep, sqlite_dep],
)

test('fact-schema', test_fact_schema)

if get_option('enable_fact_store').allowed()
  test_fact_store = executable('test-fact-store',
    'test-fact-store.c',
    include_directories : include_directories('../wyrelog'),
    dependencies : [wyrelog_dep, wirelog_dep, duckdb_dep, sqlite_dep],
  )

  test('fact-store', test_fact_store)

  test_fact_compound = executable('test-fact-compound',
    'test-fact-compound.c',
    c_args : [
      '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
    ],
    include_directories : include_directories('../wyrelog'),
    dependencies : [wyrelog_dep, duckdb_dep, sqlite_dep],
  )

  test('fact-compound', test_fact_compound)

  test_fact_replay = executable('test-fact-replay',
    'test-fact-replay.c',
    '../wyrelog/daemon/fact-status.c',
    # Keep this consumer audit-macro-unaware to cover cross-TU layout stability.
    c_args : ['-DWYL_HAS_FACT_STORE'],
    include_directories : include_directories('../wyrelog'),
    dependencies : [wyrelog_dep, duckdb_dep, sqlite_dep],
  )

  test('fact-replay', test_fact_replay)
endif

test_policy_store_toctou = executable('test-policy-store-toctou',
  'test-policy-store-toctou.c',
  dependencies : [wyrelog_dep, sqlite_dep, sodium_dep],
)

test('policy-store-toctou', test_policy_store_toctou, timeout : 60)

test_policy_store_lease = executable('test-policy-store-lease',
  'test-policy-store-lease.c',
  include_directories : include_directories('../wyrelog'),
  dependencies : [wyrelog_dep, glib_dep, gio_dep, sqlite_dep],
)

test_policy_store_lease_env = environment()
if host_machine.system() == 'windows'
  glib_genmarshal = glib_dep.get_variable(
    pkgconfig : 'glib_genmarshal',
    default_value : '',
  )
  if glib_genmarshal != '' and fs.is_absolute(glib_genmarshal)
    test_policy_store_lease_env.prepend('PATH',
      fs.parent(glib_genmarshal),
      separator : ';',
    )
  endif
endif

test('policy-store-lease', test_policy_store_lease,
  env : test_policy_store_lease_env,
  timeout : 60,
)

test_policy_store_totp = executable('test-policy-store-totp',
  'test-policy-store-totp.c',
  include_directories : include_directories('../wyrelog'),
  dependencies : [wyrelog_dep, sqlite_dep],
)

test('policy-store-totp', test_policy_store_totp)

test_daemon_mfa_validator = executable('test-daemon-mfa-validator',
  'test-daemon-mfa-validator.c',
  c_args : [
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
  ],
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : [wyrelog_dep, sqlite_dep, sodium_dep],
)

test('daemon-mfa-validator', test_daemon_mfa_validator)

test_daemon_options = executable('test-daemon-options',
  'test-daemon-options.c',
  '../wyrelog/daemon/options.c',
  c_args : [
    # Elide `static` on conf_file_open_safely so the test binary can
    # link the gate directly. Production builds keep it file-local.
    '-DWYL_OPTIONS_TEST_INTERNAL=',
  ],
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : [wyrelog_dep, glib_dep],
)

test('daemon-options', test_daemon_options)

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
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
  ],
  dependencies : [wyrelog_dep, wirelog_dep],
)

test('fsm-permission-scope', test_fsm_permission_scope)

access_decision_dl_path = join_paths(
  meson.project_source_root(),
  'templates', 'access', 'lobac', 'decision.dl',
)
access_decision_legacy_dl_path = join_paths(
  meson.project_source_root(),
  'templates', 'access', 'decision.dl',
)

test_access_decision = executable('test-access-decision',
  'test-access-decision.c',
  c_args : [
    '-DWYL_TEST_ACCESS_DECISION_DL_PATH="' + access_decision_dl_path + '"',
    '-DWYL_TEST_ACCESS_DECISION_LEGACY_DL_PATH="' + access_decision_legacy_dl_path + '"',
  ],
  dependencies : [wyrelog_dep],
)

test('access-decision', test_access_decision)

test_template_tree = executable('test-template-tree',
  'test-template-tree.c',
  c_args : [
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
  ],
  dependencies : [wyrelog_dep],
)

test('template-tree', test_template_tree)

test_decision_latency = executable('test-decision-latency',
  'test-decision-latency.c',
  c_args : [
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
  ],
  dependencies : [wyrelog_dep, wirelog_dep],
)

test('decision-latency', test_decision_latency,
  timeout : 60,
)

test_hardening_fuzz = executable('test-hardening-fuzz',
  'test-hardening-fuzz.c',
  c_args : [
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
  ],
  dependencies : [wyrelog_dep, wirelog_dep],
)

hardening_fuzz_env = environment()
hardening_fuzz_env.set('WYL_FUZZ_ARTIFACT_DIR',
  meson.current_build_dir() / 'hardening-fuzz-artifacts',
)

test('hardening-fuzz', test_hardening_fuzz,
  env : hardening_fuzz_env,
  timeout : 60,
)

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

test_keyprovider_file = executable('test-keyprovider-file',
  'test-keyprovider-file.c',
  dependencies : [wyrelog_dep],
)

test('keyprovider-file', test_keyprovider_file)

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

test_jwt = executable('test-jwt',
  'test-jwt.c',
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : [service_session_private_dep, sodium_dep],
)

test('jwt', test_jwt)

test_totp = executable('test-totp',
  'test-totp.c',
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : [wyrelog_dep, sodium_dep],
)

test('totp', test_totp)

test_service_credential = executable('test-service-credential',
  'test-service-credential.c',
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : [wyrelog_dep, sodium_dep],
)

test('service-credential', test_service_credential)

test_daemon_auth_registry = executable('test-daemon-auth-registry',
  'test-daemon-auth-registry.c',
  '../wyrelog/daemon/auth-registry-private.c',
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  c_args : ['-DWYL_AUTH_REGISTRY_TESTING'],
  dependencies : [wyrelog_dep, sodium_dep, sqlite_dep, libchronoid_dep],
)

test('daemon-auth-registry', test_daemon_auth_registry)

test_service_auth_coordination = executable('test-service-auth-coordination',
  'test-service-auth-coordination.c',
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : [wyrelog_dep, sqlite_dep],
)

test('service-auth-coordination', test_service_auth_coordination,
  is_parallel : host_machine.system() != 'windows',
  timeout : 30,
)

test_service_exchange_intention_store = executable(
  'test-service-exchange-intention-store',
  'test-service-exchange-intention-store.c',
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : [wyrelog_dep, sqlite_dep],
)

test('service-exchange-intention-store', test_service_exchange_intention_store,
  is_parallel : host_machine.system() != 'windows',
  timeout : 120,
)

test('service-exchange-shadow-boundary', python3,
  args : [
    meson.current_source_dir() / 'test-service-exchange-shadow-boundary.py',
    meson.project_source_root() / 'wyrelog' / 'policy' / 'store.c',
  ],
)

test_policy_service_namespace = executable('test-policy-service-namespace',
  'test-policy-service-namespace.c',
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : [wyrelog_dep, sodium_dep, sqlite_dep],
)

test('policy-service-namespace', test_policy_service_namespace)

test_service_principal_domain = executable('test-service-principal-domain',
  'test-service-principal-domain.c',
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : [wyrelog_dep, sodium_dep, sqlite_dep],
)

test('service-principal-domain', test_service_principal_domain,
  is_parallel : host_machine.system() != 'windows',
)

test_service_credential_domain = executable('test-service-credential-domain',
  'test-service-credential-domain.c',
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : [wyrelog_dep, sodium_dep, sqlite_dep],
)

service_credential_domain_timeout = 180

test('service-credential-domain', test_service_credential_domain,
  is_parallel : host_machine.system() != 'windows',
  timeout : service_credential_domain_timeout,
)

test_service_credential_operation_fence = executable('test-service-credential-operation-fence',
  'test-service-credential-operation-fence.c',
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : [wyrelog_dep, sodium_dep, sqlite_dep],
)

service_credential_operation_fence_timeout = 30
if host_machine.system() == 'windows'
  service_credential_operation_fence_timeout = 180
endif

test('service-credential-operation-fence', test_service_credential_operation_fence,
  is_parallel : host_machine.system() != 'windows',
  timeout : service_credential_operation_fence_timeout,
)

test_service_credential_operation_journal_codec = executable('test-service-credential-operation-journal-codec',
  'test-service-credential-operation-journal-codec.c',
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : [wyrelog_dep, sodium_dep, sqlite_dep],
)

test('service-credential-operation-journal-codec',
  test_service_credential_operation_journal_codec)

test_service_credential_operation_coordinator = executable('test-service-credential-operation-coordinator',
  'test-service-credential-operation-coordinator.c',
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : [wyrelog_dep, sodium_dep, sqlite_dep],
)
test('service-credential-operation-coordinator', test_service_credential_operation_coordinator)
test_service_credential_operation_coordinator_journal = executable('test-service-credential-operation-coordinator-journal',
  'test-service-credential-operation-coordinator-journal.c', dependencies : [wyrelog_dep],
  include_directories : [wyrelog_inc, include_directories('../wyrelog')])
test('service-credential-operation-coordinator-journal', test_service_credential_operation_coordinator_journal)

test_service_credential_operation_coordinator_execute_c_args = [
  '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
]
test_service_credential_operation_coordinator_execute_deps = [
  wyrelog_dep,
  sodium_dep,
  sqlite_dep,
]
if get_option('enable_audit').allowed()
  test_service_credential_operation_coordinator_execute_c_args += '-DWYL_HAS_AUDIT'
  test_service_credential_operation_coordinator_execute_deps += duckdb_dep
endif

test_service_credential_operation_coordinator_execute = executable('test-service-credential-operation-coordinator-execute',
  'test-service-credential-operation-coordinator-execute.c',
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : test_service_credential_operation_coordinator_execute_deps,
  c_args : test_service_credential_operation_coordinator_execute_c_args,
)

service_credential_operation_coordinator_execute_timeout = 180

test('service-credential-operation-coordinator-execute',
  test_service_credential_operation_coordinator_execute,
  is_parallel : host_machine.system() != 'windows',
  timeout : service_credential_operation_coordinator_execute_timeout,
)

test_service_credential_operation_storage = executable('test-service-credential-operation-storage',
  'test-service-credential-operation-storage.c',
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : [wyrelog_dep, sodium_dep, sqlite_dep],
)

test('service-credential-operation-storage', test_service_credential_operation_storage)

test_policy_store_service_cvk = executable('test-policy-store-service-cvk',
  'test-policy-store-service-cvk.c',
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : [wyrelog_dep, sodium_dep, sqlite_dep],
)

test('policy-store-service-cvk', test_policy_store_service_cvk,
  timeout : 120,
)

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
  dependencies : [wyrelog_dep, wirelog_dep, sqlite_dep],
)

test('handle-engine-pair', test_handle_engine_pair,
  timeout : 120,
)

test_lobac_partial_delta = executable('test-lobac-partial-delta',
  'test-lobac-partial-delta.c',
  c_args : [
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
  ],
  dependencies : [wyrelog_dep, wirelog_dep],
)

test('lobac-partial-delta', test_lobac_partial_delta)

test_session_id = executable('test-session-id',
  'test-session-id.c',
  dependencies : [wyrelog_dep],
)

test('session-id', test_session_id)

test_service_session_metadata = executable('test-service-session-metadata',
  'test-service-session-metadata.c',
  include_directories : include_directories('../wyrelog'),
  dependencies : [service_session_private_dep],
)

test('service-session-metadata', test_service_session_metadata)

test_service_exchange_audit_codec_sources = files(
  'test-service-exchange-audit-codec.c',
)
test_service_exchange_audit_codec_deps = [
  wyrelog_dep,
  sodium_dep,
  libchronoid_dep,
]
if get_option('enable_audit').allowed()
  test_service_exchange_audit_codec_deps += service_exchange_private_dep
else
  test_service_exchange_audit_codec_sources += files(
    '../wyrelog/auth/service-exchange-audit-private.c',
  )
endif
test_service_exchange_audit_codec = executable(
  'test-service-exchange-audit-codec',
  test_service_exchange_audit_codec_sources,
  include_directories : include_directories('../wyrelog'),
  dependencies : test_service_exchange_audit_codec_deps,
)

test('service-exchange-audit-codec', test_service_exchange_audit_codec)

test('service-exchange-audit-vectors', python3,
  args : files('test-service-exchange-audit-vectors.py'),
)

check_service_exchange_audit_exports = find_program(
  '../tools/check-service-exchange-audit-exports.py',
)

test('check-service-exchange-audit-exports',
  check_service_exchange_audit_exports,
  args : libwyrelog.full_path(),
  depends : libwyrelog,
)

test('check-service-exchange-audit-private-header', python3,
  args : [
    files('test-private-header-not-installed.py'),
    meson.project_build_root(),
    'service-exchange-audit-private.h',
  ],
)

test('check-service-exchange-private-header', python3,
  args : [
    files('test-private-header-not-installed.py'),
    meson.project_build_root(),
    'service-exchange-private.h',
  ],
)

test('check-service-exchange-limiter-private-header', python3,
  args : [
    files('test-private-header-not-installed.py'),
    meson.project_build_root(),
    'service-exchange-limiter-private.h',
  ],
)

test_service_exchange_private_root_include = executable(
  'test-service-exchange-private-root-include',
  'test-service-exchange-private-root-include.c',
  dependencies : [wyrelog_dep],
)

test('service-exchange-private-root-include',
  test_service_exchange_private_root_include)

test('service-exchange-private-root-boundary', python3,
  args : [
    meson.current_source_dir() / 'test-service-exchange-private-root-boundary.py',
    meson.project_source_root() / 'wyrelog' / 'auth' /
      'service-exchange-audit-private.h',
    meson.current_source_dir() / 'meson.build',
  ],
)

test('human-refresh-single-flight-boundary', python3,
  args : [
    files('test-human-refresh-single-flight-boundary.py'),
    meson.project_source_root() / 'wyrelog' / 'daemon' / 'http.c',
    meson.project_source_root() / 'tests' / 'test-daemon-http-decide.c',
  ],
)

check_service_session_private_boundary = find_program(
  '../tools/check-service-session-private-boundary.py',
)
service_session_boundary_cc = meson.get_compiler('c').cmd_array()
service_session_boundary_cc_id = meson.get_compiler('c').get_id()
# The boundary checker invokes the compiler directly for preprocessing.  When
# Meson records an sccache launcher, strip only that wrapper so clang-cl sees
# its normal -E invocation; the build itself remains fully cache-backed.
if service_session_boundary_cc.length() > 1 \
    and service_session_boundary_cc[0].to_lower().contains('cache')
  service_session_boundary_cc = [service_session_boundary_cc[1]]
endif

test('check-service-session-private-boundary',
  check_service_session_private_boundary,
  args : [meson.project_source_root(), '--compiler-id',
    service_session_boundary_cc_id, '--build-root', meson.project_build_root(),
    '--'] + service_session_boundary_cc,
  # Full semantic preprocessing follows every configured TU and can vary
  # substantially with compiler/system-header performance on shared runners.
  is_parallel : false,
  timeout : 900,
)

check_service_session_private_boundary_self_test = find_program(
  'test-service-session-private-boundary.py',
)

test('check-service-session-private-boundary-self-test',
  check_service_session_private_boundary_self_test,
  args : [check_service_session_private_boundary.full_path(), '--',
    service_session_boundary_cc_id] + service_session_boundary_cc,
  is_parallel : false,
  timeout : 120,
)

check_service_session_private_exports = find_program(
  '../tools/check-service-session-private-exports.py',
)

test('check-service-session-private-exports',
  check_service_session_private_exports,
  args : ['--must-not-contain-family', libwyrelog.full_path()],
  depends : libwyrelog,
)

test('check-service-session-private-companion-symbols',
  check_service_session_private_exports,
  args : ['--must-contain', service_session_private_lib.full_path()],
  depends : service_session_private_lib,
)

test('check-service-session-private-exports-self-test',
  check_service_session_private_exports,
  args : ['--self-test'],
)

check_service_handoff_delivery_boundary = find_program(
  '../tools/check-service-handoff-delivery-boundary.py',
)

test('check-service-handoff-delivery-boundary',
  check_service_handoff_delivery_boundary,
  args : [meson.project_source_root(), libwyrelog.full_path()],
  depends : libwyrelog,
)

test('check-service-handoff-delivery-boundary-self-test',
  check_service_handoff_delivery_boundary,
  args : ['--self-test'],
)

test_login_req = executable('test-login-req',
  'test-login-req.c',
  dependencies : [wyrelog_dep],
)

test('login-req', test_login_req)

test_session_username_c_args = [
  '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
  # The two session-username variants share one source file with one
  # main() per variant; helpers irrelevant to the active variant remain
  # defined to keep the source readable.
  '-Wno-unused-function',
]

test_session_username = executable('test-session-username',
  'test-session-username.c',
  c_args : test_session_username_c_args,
  dependencies : [wyrelog_dep, wirelog_dep],
)

test('session-username', test_session_username,
  timeout : 60,
)

test_session_username_lifecycle = executable('test-session-username-lifecycle',
  'test-session-username.c',
  c_args : test_session_username_c_args + '-DWYL_TEST_VARIANT_LIFECYCLE',
  dependencies : [wyrelog_dep, wirelog_dep],
)

test('session-username-lifecycle', test_session_username_lifecycle)

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

test_decide_c_args = [
  '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
]
if get_option('enable_audit').allowed()
  test_decide_c_args += '-DWYL_HAS_AUDIT'
endif

test_decide = executable('test-decide',
  'test-decide.c',
  c_args : test_decide_c_args,
  dependencies : [wyrelog_dep, wirelog_dep] + (get_option('enable_audit').allowed()
      ? [duckdb_dep]
      : []),
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
  c_args : [
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
  ],
  dependencies : [wyrelog_dep],
)

test('session-logout', test_session_logout)

test_session_registry = executable('test-session-registry',
  'test-session-registry.c',
  c_args : [
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
  ],
  dependencies : [wyrelog_dep],
)

test('session-registry', test_session_registry)

test_break_glass_vocab = executable('test-break-glass-vocab',
  'test-break-glass-vocab.c',
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : [wyrelog_dep],
)

test('break-glass-vocab', test_break_glass_vocab)

test_break_glass_arm_c_args = [
  '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
]
if get_option('enable_break_glass')
  test_break_glass_arm_c_args += '-DWYL_HAS_BREAK_GLASS'
endif

test_break_glass_arm = executable('test-break-glass-arm',
  'test-break-glass-arm.c',
  c_args : test_break_glass_arm_c_args,
  dependencies : [wyrelog_dep],
)

test('break-glass-arm', test_break_glass_arm)

if get_option('enable_break_glass') and get_option('enable_audit').allowed()
  test_break_glass_decide = executable('test-break-glass-decide',
    'test-break-glass-decide.c',
    c_args : [
      '-DWYL_HAS_BREAK_GLASS',
      '-DWYL_HAS_AUDIT',
      '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
    ],
    include_directories : [wyrelog_inc, include_directories('../wyrelog')],
    dependencies : [wyrelog_dep, wirelog_dep, duckdb_dep],
  )

  test('break-glass-decide', test_break_glass_decide)
endif

# NOTE: WYL_TEST_TEMPLATE_DIR points at the in-tree source layout
# only. The installed layout (${datadir}/wyrelog/access) — produced
# by install_subdir at the top-level meson.build — is not
# exercised by these tests. Validation of the installed layout is
# tracked as packaging-CI follow-up rather than unit-test concern.
test_engine_c_args = [
  '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
]
if get_option('require_template_manifest')
  test_engine_c_args += '-DWYL_REQUIRE_TEMPLATE_MANIFEST'
endif

test_engine = executable('test-engine',
  'test-engine.c',
  c_args : test_engine_c_args,
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
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'tests' / 'fixtures' / 'engine-io-templates' + '"',
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

test('check-sccache-fallback-workflows', python3,
  args : [meson.project_source_root() / 'tools' / 'check-sccache-fallback.py',
    meson.project_source_root()],
)

check_no_derived_fsm_replay = find_program(
  '../tools/check-no-derived-fsm-replay.sh',
)

test('check-no-derived-fsm-replay', check_no_derived_fsm_replay,
  args : [meson.project_source_root()],
)

check_no_daemon_policy_mutation_lock = find_program(
  '../tools/check-daemon-policy-write-authority.py',
)
daemon_guard_cc = meson.get_compiler('c').cmd_array()
daemon_guard_cc_id = meson.get_compiler('c').get_id()
daemon_guard_args = [meson.project_source_root()]
if build_client
  daemon_guard_args += ['--build-root', meson.project_build_root(),
    '--compiler-id', daemon_guard_cc_id]
else
  daemon_guard_args += ['--raw-only']
endif

test('check-no-daemon-policy-mutation-lock',
  check_no_daemon_policy_mutation_lock,
  args : daemon_guard_args,
)

bearer_resolver_structure_guard = find_program(
  '../tools/check-daemon-bearer-resolver-structure.py')
test('check-daemon-bearer-resolver-structure',
  bearer_resolver_structure_guard,
  args : [meson.project_source_root() / 'wyrelog' / 'daemon' / 'http.c'],
)
test('check-daemon-bearer-resolver-structure-self-test', python3,
  args : [
    meson.current_source_dir() / 'test-daemon-bearer-resolver-structure.py',
    bearer_resolver_structure_guard.full_path(),
  ],
)

bearer_resolver_export_guard = find_program(
  '../tools/check-daemon-bearer-resolver-exports.py')
bearer_resolver_object_format = 'elf'
if host_machine.system() == 'darwin'
  bearer_resolver_object_format = 'macho'
elif host_machine.system() == 'windows'
  bearer_resolver_object_format = 'pe'
endif
test('check-daemon-bearer-resolver-exports',
  bearer_resolver_export_guard,
  args : [bearer_resolver_object_format, wyrelogd_exe.full_path()],
  depends : wyrelogd_exe,
)
test('check-daemon-bearer-resolver-exports-self-test', python3,
  args : [
    meson.current_source_dir() / 'test-daemon-bearer-resolver-exports.py',
    bearer_resolver_export_guard.full_path(),
  ],
)

check_no_daemon_policy_mutation_lock_self_test = find_program(
  'test-daemon-policy-write-authority-guard.py',
)

if build_client
  test('check-no-daemon-policy-mutation-lock-self-test',
    check_no_daemon_policy_mutation_lock_self_test,
    args : [
      check_no_daemon_policy_mutation_lock.full_path(),
      meson.project_source_root(),
      '--build-root', meson.project_build_root(),
      '--compiler-id', daemon_guard_cc_id, '--',
    ] + daemon_guard_cc,
    timeout : 120,
  )
endif

check_supply_chain_pins = find_program(
  '../tools/check-supply-chain-pins.sh',
)

test('supply-chain-pins', check_supply_chain_pins,
  args : [meson.project_source_root()],
)

test('duckdb-source-codegen-boundary', python3,
  args : [files('test-duckdb-source-codegen-boundary.py'),
    meson.project_source_root()])

if host_machine.system() != 'windows'
  valgrind_gate = find_program(
    '../tools/run-valgrind-gate.sh',
  )

  test('valgrind-smoke', valgrind_gate,
    args : [test_smoke.full_path()],
    depends : test_smoke,
    timeout : 120,
  )
endif

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
    include_directories : include_directories('../wyrelog'),
    c_args : [
      '-DWYL_TEST_DUCKDB_SCHEMA_PATH="' + meson.project_source_root() / 'templates' / 'access' / 'duckdb-schema.sql' + '"',
    ],
    dependencies : [service_exchange_private_dep],
  )

  test('audit-conn', test_audit_conn, env : audit_conn_test_env, timeout : 60)

  test_service_exchange_projector = executable(
    'test-service-exchange-projector',
    'test-service-exchange-projector.c',
    c_args : ['-DWYL_HAS_AUDIT'],
    include_directories : [wyrelog_inc, include_directories('../wyrelog')],
    dependencies : [service_exchange_private_dep],
  )
  test('service-exchange-projector', test_service_exchange_projector,
    env : audit_conn_test_env, timeout : 180)

  test_service_exchange_private = executable(
    'test-service-exchange-private',
    'test-service-exchange-private.c',
    '../wyrelog/daemon/auth-registry-private.c',
    c_args : ['-DWYL_HAS_AUDIT'],
    include_directories : [wyrelog_inc, include_directories('../wyrelog')],
    dependencies : [service_exchange_private_dep],
  )
  test('service-exchange-private', test_service_exchange_private,
    env : audit_conn_test_env, timeout : 180)

  test_service_exchange_limiter_private = executable(
    'test-service-exchange-limiter-private',
    'test-service-exchange-limiter-private.c',
    c_args : ['-DWYL_HAS_AUDIT'],
    include_directories : [wyrelog_inc, include_directories('../wyrelog')],
    dependencies : [service_exchange_private_dep],
  )
  test('service-exchange-limiter-private',
    test_service_exchange_limiter_private,
    timeout : 180)

  test('service-exchange-projector-boundary', python3,
    args : [files('test-service-exchange-projector-boundary.py'),
      meson.project_source_root()])

  test_daemon_startup_recovery = executable(
    'test-daemon-startup-recovery',
    'test-daemon-startup-recovery.c',
    c_args : ['-DWYL_HAS_AUDIT'],
    include_directories : [wyrelog_inc, include_directories('../wyrelog')],
    dependencies : [service_exchange_startup_private_dep],
  )
  test('daemon-startup-recovery', test_daemon_startup_recovery,
    env : audit_conn_test_env, timeout : 60)
  test('daemon-startup-recovery-boundary', python3,
    args : [files('test-daemon-startup-recovery-boundary.py'),
      meson.project_source_root()])

  test_audit_emit = executable('test-audit-emit',
    'test-audit-emit.c',
    c_args : [
      '-DWYL_HAS_AUDIT',
      '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
    ],
    dependencies : [wyrelog_dep, duckdb_dep, sqlite_dep],
  )

  test('audit-emit', test_audit_emit,
    env : audit_conn_test_env,
    timeout : 120,
  )

  test_daemon_checks = executable('test-daemon-checks',
    'test-daemon-checks.c',
    '../wyrelog/daemon/checks.c',
    '../wyrelog/daemon/delta.c',
    c_args : [
      '-DWYL_HAS_AUDIT',
      '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
    ],
    include_directories : [wyrelog_inc, include_directories('../wyrelog')],
    dependencies : [wyrelog_dep, duckdb_dep],
  )

  test('daemon-checks', test_daemon_checks, env : audit_conn_test_env)

  test_login_projection = executable('test-login-projection',
    'test-login-projection.c',
    c_args : [
      '-DWYL_HAS_AUDIT',
      '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
    ],
    dependencies : [wyrelog_dep, duckdb_dep, sqlite_dep],
  )

  test('login-projection', test_login_projection, env : audit_conn_test_env)

  test_daemon_delta = executable('test-daemon-delta',
    'test-daemon-delta.c',
    '../wyrelog/daemon/delta.c',
    c_args : [
      '-DWYL_HAS_AUDIT',
      '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
    ],
    include_directories : [wyrelog_inc, include_directories('../wyrelog')],
    dependencies : [wyrelog_dep, duckdb_dep],
  )

  test('daemon-delta', test_daemon_delta, env : audit_conn_test_env)
endif
