fs = import('fs')
python3 = find_program('python3')

# BEGIN duckdb-patch-stack-determinism
test('duckdb-patch-stack-determinism', python3,
  args : [files('test-duckdb-patch-stack-determinism.py'),
    meson.project_source_root()])

test('duckdb-patch-stack-determinism-self-test', python3,
  args : [files('test-duckdb-patch-stack-determinism.py'),
    '--self-test', meson.project_source_root()])

if enable_secure_duckdb_bridge_opt.enabled() and \
    get_option('duckdb_source') == 'subproject'
  if host_machine.system() == 'linux' or \
      host_machine.system() == 'darwin'
    duckdb_patch_tool_name = host_machine.system() == 'darwin' ? 'gpatch' : 'patch'
    duckdb_patch_tool = find_program(duckdb_patch_tool_name, required : true)
    duckdb_patch_archive = meson.project_source_root() / \
      'subprojects/packagecache/libduckdb-src-v1.5.5.zip'
    if not fs.exists(duckdb_patch_archive)
      error('strict DuckDB patch replay requires the resolved pinned archive')
    endif
    test('duckdb-patch-stack-determinism-strict', python3,
      args : [files('test-duckdb-patch-stack-determinism.py'),
        '--strict-apply',
        '--archive', duckdb_patch_archive,
        '--gnu-patch', duckdb_patch_tool.full_path(),
        meson.project_source_root()],
      timeout : 120)
  endif
endif
# END duckdb-patch-stack-determinism

meson_exe = find_program('meson')
# Boundary checkers read repository sources.  Make an encoding-less read a
# hard error so a checker can never silently fall back to the machine
# locale's codec.  This asserts strictness; it does not change the default.
#
# Coverage is deliberately limited to the tests whose Python was audited and
# annotated by the change that introduced this environment.  Other tests that
# drive $PYTHON heredocs (wyrelogd-healthz, wyrelogd-conf-gate, ...) are not
# covered yet; attach this env to one only together with the audit of its
# Python, otherwise a latent encoding-less read turns into a test failure.
#
# Both variables need Python 3.10 or newer, where PYTHONWARNDEFAULTENCODING
# and the EncodingWarning category were introduced.  Below that the pair is
# inert rather than fatal: the unknown variable is ignored outright and the
# unknown warning category prints "Invalid -W option ignored" on stderr
# without failing the run, so the tests keep passing and merely lose the
# assertion.
python_strict_encoding_env = environment()
python_strict_encoding_env.set('PYTHONWARNDEFAULTENCODING', '1')
python_strict_encoding_env.set('PYTHONWARNINGS', 'error::EncodingWarning')

duckdb_linux_link_dependency_wiring_checker = files(
  'test-duckdb-linux-link-dependency-wiring.py',
)
test('duckdb-linux-link-dependency-wiring', python3,
  args : [
    duckdb_linux_link_dependency_wiring_checker,
    meson.project_source_root(),
  ],
  env : python_strict_encoding_env,
)
test('duckdb-linux-link-dependency-wiring-self-test', python3,
  args : [
    duckdb_linux_link_dependency_wiring_checker,
    '--self-test',
    meson.project_source_root(),
  ],
  env : python_strict_encoding_env,
)

if host_machine.system() == 'linux' and \
    get_option('duckdb_source') == 'subproject' and \
    get_option('enable_fact_store').enabled() and \
    not enable_secure_duckdb_bridge_opt.enabled()
  test_duckdb_source_offbridge_c_consumer = executable(
    'test-duckdb-source-offbridge-c-consumer',
    'test-duckdb-source-offbridge-c-consumer.c',
    dependencies : duckdb_dep,
    link_language : 'c',
  )
  test('duckdb-source-offbridge-c-consumer',
    test_duckdb_source_offbridge_c_consumer)
  test('duckdb-linux-link-dependency-wiring-generated',
    python3,
    args : [
      duckdb_linux_link_dependency_wiring_checker,
      '--build-root',
      meson.project_build_root(),
      meson.project_source_root(),
    ],
    depends : test_duckdb_source_offbridge_c_consumer,
    env : python_strict_encoding_env,
  )
endif

test('wirelog-dependency-boundary', python3,
  args : [
    meson.current_source_dir() / 'test-wirelog-dependency-boundary.py',
    meson.project_source_root(),
    meson_exe.full_path(),
  ],
  env : python_strict_encoding_env,
  timeout : 600,
)

comment_alignment_checker = files(
  '../tools/check-comment-alignment.sh',
)
# Asserts uncrustify leaves correctly aligned block-comment continuation stars
# alone (#872).  Skips rather than fails when uncrustify is absent, is not the
# pinned version, or the source tree is not a git worktree -- so a contributor
# without the formatter, and a build from an exported tarball, are not blocked.
# The ledger rule in CLAUDE.md already requires the formatter for anyone
# touching a listed file, and check-format.sh --ledger is the hard gate.
test('check-comment-alignment', comment_alignment_checker)

explicit_encoding_checker = files(
  '../tools/check-explicit-encoding.py',
)
test('check-explicit-encoding', python3,
  args : [
    explicit_encoding_checker,
    meson.project_source_root(),
  ],
  env : python_strict_encoding_env,
)
test('check-explicit-encoding-self-test', python3,
  args : [
    explicit_encoding_checker,
    '--self-test',
  ],
  env : python_strict_encoding_env,
  timeout : 120,
)

posix_errno_capability_pair_checker = files(
  'test-posix-errno-capability-pair.py',
)
test('posix-errno-capability-pair', python3,
  args : [
    posix_errno_capability_pair_checker,
    meson.project_source_root(),
  ],
  env : python_strict_encoding_env,
)
test('posix-errno-capability-pair-self', python3,
  args : [
    posix_errno_capability_pair_checker,
    '--self-test',
  ],
  env : python_strict_encoding_env,
  timeout : 120,
)

if host_machine.system() != 'windows'
  test_fact_graph_locator_darwin_evidence = executable(
    'test-fact-graph-locator-darwin-evidence',
    'test-fact-graph-locator-darwin-evidence.c',
    include_directories : include_directories('../wyrelog'),
    dependencies : [wyrelog_dep],
  )
  test('fact-graph-locator-darwin-evidence',
    test_fact_graph_locator_darwin_evidence)

  test_posix_errno_capability = executable('test-posix-errno-capability',
    'test-posix-errno-capability.c',
    include_directories : include_directories('../wyrelog'),
    dependencies : [glib_dep],
  )

  test('posix-errno-capability', test_posix_errno_capability)
endif

if host_machine.system() == 'darwin'
  test_fact_graph_locator_macos = executable(
    'test-fact-graph-locator-macos',
    'test-fact-graph-locator-macos.c',
    include_directories : include_directories('../wyrelog'),
    dependencies : [wyrelog_dep],
  )
  test('fact-graph-locator-macos', test_fact_graph_locator_macos)
endif

test('engine-session-boundary', python3,
  args : [
    files('../tools/check-engine-session-boundary.py'),
    meson.project_source_root(),
  ],
  env : python_strict_encoding_env,
)
test('engine-session-boundary-reconcile', python3,
  args : [
    files('../tools/check-engine-session-boundary.py'),
    meson.project_source_root(),
    '--build-root', meson.project_build_root(),
  ],
  env : python_strict_encoding_env,
)
test('engine-session-boundary-self-test', python3,
  args : [
    files('../tools/check-engine-session-boundary.py'),
    '--self-test',
  ],
  env : python_strict_encoding_env,
)

handle_test_object_format = 'elf'
if host_machine.system() == 'windows'
  handle_test_object_format = 'pe'
elif host_machine.system() == 'darwin'
  handle_test_object_format = 'macho'
endif
# libwyrelog follows default_library, so the inspector must be told which kind
# it is actually being handed.  Naming it 'shared' unconditionally selects the
# dynamic-export command, and against a static archive that command reports
# nothing -- which the tool correctly refuses as an unusable inspection rather
# than reading as "no seams present".  Every Windows CI configuration is
# static, so the hardcoded value made this gate fail wherever it mattered most.
handle_test_artifact_kind = 'shared'
if get_option('default_library') == 'static'
  handle_test_artifact_kind = 'archive'
endif
test('handle-test-seams-not-shipped', python3,
  args : [
    files('../tools/check-handle-test-seam-exports.py'),
    'absent',
    handle_test_object_format,
    handle_test_artifact_kind,
    libwyrelog.full_path(),
  ],
  depends : libwyrelog,
  env : python_strict_encoding_env,
)

# Frozen service-credential platform evidence matrix (#382 Unit 6). This is a
# STATIC source/doc/config consistency gate: it asserts the four packaged
# service-credential e2e tests stay inside a `host_machine.system() == 'linux'`
# gate, that docs/service-credential-platform-support.md classifies all three
# platforms in agreement with that gating (Linux=runtime, macOS/Windows=
# build-only) and references the #754-gated #380 portion, and that the CI
# workflows provide each platform's runner + named native gates. Registered
# UNCONDITIONALLY (no platform/build gate) so drift is caught on every runner.
test('service-credential-platform-matrix', python3,
  args : [
    meson.current_source_dir() / 'check-service-credential-platform-matrix.py',
    meson.current_source_dir() / 'meson.build',
    meson.project_source_root() / 'docs' / 'service-credential-platform-support.md',
    meson.project_source_root() / '.github' / 'workflows' / 'ci-main.yml',
    meson.project_source_root() / '.github' / 'workflows' / 'ci-pr.yml',
    meson.current_source_dir()
      / 'test-service-credential-operation-coordinator-execute.c',
  ],
)

if host_machine.system() == 'windows'
  advapi32_dep = meson.get_compiler('c').find_library('Advapi32',
    required : true)
endif
fact_test_support_deps = []
fact_test_support_c_args = []
if host_machine.system() == 'windows'
  fact_test_support_deps += advapi32_dep
  fact_test_support_c_args += '-D_WIN32_WINNT=0x0602'
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
      env : python_strict_encoding_env,
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
        env : python_strict_encoding_env,
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
  test_daemon_http_decide_uses_shared_wyrelog = (
    get_option('default_library') == 'shared'
  )
  if get_option('default_library') == 'both'
    # Meson 1.1-1.5 always selects the shared library from a both_library().
    # Since 1.6, only an explicit static selection changes that default; auto
    # and shared continue to select the shared library.
    test_daemon_http_decide_uses_shared_wyrelog = true
    if meson.version().version_compare('>=1.6.0')
      test_daemon_http_decide_uses_shared_wyrelog = (
        get_option('default_both_libraries') != 'static'
      )
    endif
  endif
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
    sqlite_dep,
    sodium_dep,
    service_session_private_dep,
  ]
  if get_option('enable_fact_store').allowed()
    test_daemon_http_decide_c_args += '-DWYL_HAS_FACT_STORE'
    test_daemon_http_decide_deps += duckdb_dep
    if (host_machine.system() == 'windows' or
        not test_daemon_http_decide_uses_shared_wyrelog)
      # Windows and static selections keep the existing in-executable test
      # friend.  A shared POSIX selection uses the isolated seed helper DSO.
      test_daemon_http_decide_c_args += [
        '-DWYL_SERVICE_CREDENTIAL_OPERATION_TEST_FRIENDS',
      ]
    else
      test_daemon_http_decide_c_args += [
        '-DWYL_TEST_DAEMON_HTTP_SEED_HELPER_DSO',
      ]
    endif
  endif
  test_daemon_http_decide_audit_enabled = get_option('enable_audit').allowed()
  test_daemon_http_decide_audit_mode = (
    test_daemon_http_decide_audit_enabled ? 'enabled' : 'disabled'
  )
  if test_daemon_http_decide_audit_enabled
    test_daemon_http_decide_c_args += '-DWYL_HAS_AUDIT'
    test_daemon_http_decide_deps += duckdb_dep
    test_daemon_http_decide_deps += service_exchange_private_dep
  endif
  test_daemon_http_decide_deps += daemon_http_private_dep
  test_daemon_http_decide_link_with = []
  test_daemon_http_decide_targets = []
  if (host_machine.system() != 'windows' and
      get_option('enable_fact_store').allowed() and
      test_daemon_http_decide_uses_shared_wyrelog)
    test_daemon_http_decide_seed_wyrelog = libwyrelog
    if get_option('default_library') == 'both'
      test_daemon_http_decide_seed_wyrelog = libwyrelog.get_shared_lib()
    endif
    test_daemon_http_decide_seed_helper = shared_library(
      'test-daemon-http-decide-seed-helper',
      'test-daemon-http-decide-seed-helper.c',
      '../wyrelog/auth/service-credential-operation-coordinator-journal-private.c',
      '../wyrelog/auth/service-credential-operation-coordinator-storage-private.c',
      '../wyrelog/auth/service-credential-operation-storage-private.c',
      include_directories : [wyrelog_inc, include_directories('../wyrelog')],
      dependencies : wyrelog_deps,
      link_with : test_daemon_http_decide_seed_wyrelog,
      c_args : wyrelog_c_args + [
        '-DWYL_SERVICE_CREDENTIAL_OPERATION_TEST_FRIENDS',
      ],
      gnu_symbol_visibility : 'hidden',
      build_by_default : false,
      install : false,
    )
    test_daemon_http_decide_link_with += [
      test_daemon_http_decide_seed_helper,
    ]
  endif
  test_daemon_http_decide = executable('test-daemon-http-decide',
    'test-daemon-http-decide.c',
    '../wyrelog/daemon/auth-registry-private.c',
    '../wyrelog/daemon/http.c',
    '../wyrelog/daemon/delta.c',
    '../wyrelog/daemon/fact-status.c',
    '../wyrelog/daemon/service-credential-handoff-private.c',
    c_args : test_daemon_http_decide_c_args,
    include_directories : [wyrelog_inc, include_directories('../wyrelog')],
    dependencies : test_daemon_http_decide_deps,
    link_with : test_daemon_http_decide_link_with,
  )
  test_daemon_http_decide_targets += [test_daemon_http_decide]

  test('daemon-http-decide', test_daemon_http_decide, timeout : 240)

  test_daemon_http_decide_refresh = executable('test-daemon-http-decide-refresh',
    'test-daemon-http-decide.c',
    '../wyrelog/daemon/auth-registry-private.c',
    '../wyrelog/daemon/http.c',
    '../wyrelog/daemon/delta.c',
    '../wyrelog/daemon/fact-status.c',
    '../wyrelog/daemon/service-credential-handoff-private.c',
    c_args : test_daemon_http_decide_c_args + '-DWYL_TEST_VARIANT_REFRESH',
    include_directories : [wyrelog_inc, include_directories('../wyrelog')],
    dependencies : test_daemon_http_decide_deps,
    link_with : test_daemon_http_decide_link_with,
  )
  test_daemon_http_decide_targets += [test_daemon_http_decide_refresh]

  test('daemon-http-decide-refresh', test_daemon_http_decide_refresh,
    timeout : 960,
  )

  test_daemon_http_decide_service = executable('test-daemon-http-decide-service',
    'test-daemon-http-decide.c',
    '../wyrelog/daemon/auth-registry-private.c',
    '../wyrelog/daemon/http.c',
    '../wyrelog/daemon/delta.c',
    '../wyrelog/daemon/fact-status.c',
    '../wyrelog/daemon/service-credential-handoff-private.c',
    c_args : test_daemon_http_decide_c_args + '-DWYL_TEST_VARIANT_SERVICE',
    include_directories : [wyrelog_inc, include_directories('../wyrelog')],
    dependencies : test_daemon_http_decide_deps,
    link_with : test_daemon_http_decide_link_with,
  )
  test_daemon_http_decide_targets += [test_daemon_http_decide_service]

  test('daemon-http-decide-service', test_daemon_http_decide_service,
    timeout : 240,
  )

  if test_daemon_http_decide_audit_enabled
    test_daemon_http_decide_audit = executable('test-daemon-http-decide-audit',
      'test-daemon-http-decide.c',
      '../wyrelog/daemon/auth-registry-private.c',
      '../wyrelog/daemon/http.c',
      '../wyrelog/daemon/delta.c',
      '../wyrelog/daemon/fact-status.c',
      '../wyrelog/daemon/service-credential-handoff-private.c',
      c_args : test_daemon_http_decide_c_args + '-DWYL_TEST_VARIANT_AUDIT',
      include_directories : [wyrelog_inc, include_directories('../wyrelog')],
      dependencies : test_daemon_http_decide_deps,
      link_with : test_daemon_http_decide_link_with,
    )
    test_daemon_http_decide_targets += [test_daemon_http_decide_audit]

    test('daemon-http-decide-audit', test_daemon_http_decide_audit,
      timeout : 240,
    )
  endif

  test('daemon-http-decide-private-companion-boundary', python3,
    args : [
      meson.current_source_dir() / 'test-daemon-http-decide-private-companion-boundary.py',
      meson.current_source_dir() / 'meson.build',
      meson.current_source_dir() / 'test-daemon-http-decide-seed-helper.c',
      meson.current_source_dir() / 'test-daemon-http-decide-seed-helper.h',
      meson.current_source_dir() / 'test-daemon-http-decide.c',
      meson.project_source_root() / '.github' / 'workflows' / 'ci-pr.yml',
      meson.project_source_root() / '.github' / 'workflows' / 'ci-main.yml',
    ],
  )

  if host_machine.system() != 'windows'
    check_daemon_http_decide_private_symbols = find_program(
      '../tools/check-daemon-http-decide-private-symbols.py',
    )
    test('daemon-http-decide-private-symbols-self-test',
      check_daemon_http_decide_private_symbols,
      args : ['--self-test'],
    )
    if (get_option('enable_fact_store').allowed() and
        test_daemon_http_decide_uses_shared_wyrelog)
      test_daemon_http_decide_target_paths = []
      foreach target : test_daemon_http_decide_targets
        test_daemon_http_decide_target_paths += [target.full_path()]
      endforeach
      test('daemon-http-decide-private-symbols',
        check_daemon_http_decide_private_symbols,
        args : [
          '--audit-mode',
          test_daemon_http_decide_audit_mode,
          meson.project_build_root() / 'meson-info' / 'intro-installed.json',
          test_daemon_http_decide_seed_helper.full_path(),
          meson.current_source_dir() / 'test-daemon-http-decide-seed-helper.h',
          libwyrelog.full_path(),
        ] + test_daemon_http_decide_target_paths,
        depends : [
          test_daemon_http_decide_seed_helper,
          libwyrelog,
        ] + test_daemon_http_decide_targets,
      )
    endif
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

  test('session-state-atomic-accessor-structure', python3,
    args : [
      meson.current_source_dir()
        / 'test-session-state-atomic-accessor-structure.py',
      meson.project_source_root(),
    ],
  )

  check_daemon_http_route_registrations = find_program(
    '../tools/check-daemon-http-route-registrations.py',
  )
  daemon_http_route_guard_cc = meson.get_compiler('c').cmd_array()
  test('daemon-http-route-registrations-self-test',
    check_daemon_http_route_registrations,
    args : [
      '--self-test',
      '--compiler-id', meson.get_compiler('c').get_id(),
      '--',
    ] + daemon_http_route_guard_cc,
    timeout : 180,
  )
  test('daemon-http-route-registrations',
    check_daemon_http_route_registrations,
    args : [
      meson.project_source_root(),
      '--build-root', meson.project_build_root(),
      '--compiler-id', meson.get_compiler('c').get_id(),
    ],
    timeout : 180,
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
    '../wyrelog/daemon/service-credential-handoff-private.c',
    c_args : test_daemon_http_mfa_c_args,
    include_directories : [wyrelog_inc, include_directories('../wyrelog')],
    dependencies : test_daemon_http_mfa_deps,
  )

  test('daemon-http-mfa', test_daemon_http_mfa, timeout : 60)

  test_daemon_http_profile_events_c_args = [
    '-DWYL_HAS_DAEMON_HTTP',
    '-DWYL_TEST_DAEMON_HTTP',
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
  ]
  test_daemon_http_profile_events_deps = [
    wyrelog_dep,
    wyrelog_client_dep,
    libsoup_dep,
    sodium_dep,
    sqlite_dep,
    service_session_private_dep,
  ]
  if get_option('enable_fact_store').allowed()
    test_daemon_http_profile_events_c_args += '-DWYL_HAS_FACT_STORE'
    test_daemon_http_profile_events_deps += duckdb_dep
  endif
  if get_option('enable_audit').allowed()
    test_daemon_http_profile_events_c_args += '-DWYL_HAS_AUDIT'
    test_daemon_http_profile_events_deps += duckdb_dep
    test_daemon_http_profile_events_deps += service_exchange_private_dep
  endif
  test_daemon_http_profile_events_deps += daemon_http_private_dep
  test_daemon_http_profile_events = executable('test-daemon-http-profile-events',
    'test-daemon-http-profile-events.c',
    '../wyrelog/daemon/auth-registry-private.c',
    '../wyrelog/daemon/http.c',
    '../wyrelog/daemon/delta.c',
    '../wyrelog/daemon/fact-status.c',
    '../wyrelog/daemon/service-credential-handoff-private.c',
    c_args : test_daemon_http_profile_events_c_args,
    include_directories : [wyrelog_inc, include_directories('../wyrelog')],
    dependencies : test_daemon_http_profile_events_deps,
  )

  test('daemon-http-profile-events', test_daemon_http_profile_events,
    timeout : 60)

  if get_option('enable_fact_store').allowed()
    test_daemon_http_facts_c_args = [
      '-DWYL_HAS_DAEMON_HTTP',
      '-DWYL_TEST_DAEMON_HTTP',
      '-DWYL_HAS_FACT_STORE',
      '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
    ]
    test_daemon_http_facts_c_args += fact_test_support_c_args
    test_daemon_http_facts_deps = [
      wyrelog_dep,
      wyrelog_client_dep,
      libsoup_dep,
      sodium_dep,
      duckdb_dep,
      sqlite_dep,
      service_session_private_dep,
    ]
    test_daemon_http_facts_deps += fact_test_support_deps
    if get_option('enable_audit').allowed()
      test_daemon_http_facts_c_args += '-DWYL_HAS_AUDIT'
      test_daemon_http_facts_deps += duckdb_dep
      test_daemon_http_facts_deps += service_exchange_private_dep
    endif
    if get_option('enable_secure_duckdb_bridge').enabled()
      test_daemon_http_facts_c_args += '-DWYL_HAS_SECURE_DUCKDB_BRIDGE'
    endif
    test_daemon_http_facts_deps += daemon_http_private_dep
    test_daemon_http_facts = executable('test-daemon-http-facts',
      'test-daemon-http-facts.c',
      'fact-test-support.c',
      '../wyrelog/daemon/auth-registry-private.c',
      '../wyrelog/daemon/http.c',
      '../wyrelog/daemon/delta.c',
      '../wyrelog/daemon/fact-status.c',
      c_args : test_daemon_http_facts_c_args,
      include_directories : [wyrelog_inc, include_directories('../wyrelog')],
      dependencies : test_daemon_http_facts_deps,
    )

    test_daemon_http_facts_env = environment()
    if host_machine.system() == 'windows'
      test_daemon_http_facts_env.set(
        'G_MESSAGES_DEBUG',
        'wyrelog-fact-http-store wyrelog-fact-resolver',
      )
    endif
    test('daemon-http-facts', test_daemon_http_facts,
      env : test_daemon_http_facts_env,
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
    include_directories : [include_directories('../wyrelog'),
      include_directories('../wyrelog/wyctl')],
    dependencies : [wyrelog_dep, sodium_dep, publication_private_dep],
  )

  test('wyctl-publication', test_wyctl_publication)

  # The whole enclosing block is already `host_machine.system() != 'windows'`,
  # so the POSIX publication test lives here directly. The Windows variant is
  # built in its own `system() == 'windows'` block below (issue #559).
  test_wyctl_publication_posix = executable('test-wyctl-publication-posix',
    'test-wyctl-publication-posix.c',
    include_directories : [include_directories('../wyrelog'),
      include_directories('../wyrelog/wyctl')],
    dependencies : [wyrelog_dep, sodium_dep, publication_private_dep],
  )

  test('wyctl-publication-posix', test_wyctl_publication_posix)

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

  test_wyctl_service_credential = executable('test-wyctl-service-credential',
    'test-wyctl-service-credential.c',
    c_args : [
      '-DWYL_TEST_WYCTL_PATH="' + wyctl_exe.full_path() + '"',
    ],
    dependencies : [glib_dep, gio_dep],
  )

  test('wyctl-service-credential', test_wyctl_service_credential,
    depends : [wyctl_exe, wyctl_gschemas_compiled],
    env : wyctl_gsettings_test_env,
    timeout : 60,
  )

  test_wyctl_service_principal = executable('test-wyctl-service-principal',
    'test-wyctl-service-principal.c',
    c_args : [
      '-DWYL_TEST_WYCTL_PATH="' + wyctl_exe.full_path() + '"',
    ],
    dependencies : [glib_dep, gio_dep, libsoup_dep],
  )

  test('wyctl-service-principal', test_wyctl_service_principal,
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

  test('wyctl-option-ownership-runtime', python3,
    args : [
      files('test-wyctl-option-ownership.py'),
      wyctl_exe.full_path(),
    ],
    depends : wyctl_exe,
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

  # End-to-end: drives `wyctl service-credential issue` against an in-process
  # daemon to prove the CLI -> client -> daemon -> auth chain and the rc->exit
  # mapping. With an authorized operator but no escrow roots the handler passes
  # auth and returns 503 (exit 5); an ungranted operator is denied (exit 4/6).
  # The delta proves the bearer token is accepted and authorization enforced.
  # The delivered=yes escrow receipt is covered by the daemon-http contract and
  # client smoke, which this harness cannot reproduce (no CVK sealing).
  test_wyctl_service_credential_daemon_c_args = [
    '-DWYL_HAS_DAEMON_HTTP',
    # The bearer session must be bound to a real (alphanumeric) tenant so the
    # service subject svc:<tenant>:worker is legal, which login cannot express;
    # the human session/token seeding seams that give such a token are gated
    # behind WYL_TEST_DAEMON_HTTP.
    '-DWYL_TEST_DAEMON_HTTP',
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
    '-DWYL_TEST_WYCTL_PATH="' + wyctl_exe.full_path() + '"',
  ]
  test_wyctl_service_credential_daemon_deps = [
    wyrelog_dep,
    wyrelog_client_dep,
    libsoup_dep,
    sodium_dep,
    service_session_private_dep,
  ]
  if get_option('enable_fact_store').allowed()
    test_wyctl_service_credential_daemon_c_args += '-DWYL_HAS_FACT_STORE'
    test_wyctl_service_credential_daemon_deps += duckdb_dep
  endif
  test_wyctl_service_credential_daemon_deps += daemon_http_private_dep
  test_wyctl_service_credential_daemon = executable(
    'test-wyctl-service-credential-daemon',
    'test-wyctl-service-credential-daemon.c',
    '../wyrelog/daemon/auth-registry-private.c',
    '../wyrelog/daemon/http.c',
    '../wyrelog/daemon/delta.c',
    '../wyrelog/daemon/fact-status.c',
    c_args : test_wyctl_service_credential_daemon_c_args,
    include_directories : [wyrelog_inc, include_directories('../wyrelog')],
    dependencies : test_wyctl_service_credential_daemon_deps,
  )

  test('wyctl-service-credential-daemon', test_wyctl_service_credential_daemon,
    depends : wyctl_exe,
  )
endif

if build_client and host_machine.system() == 'windows'
  # The backend translation unit is compiled directly into the test (rather
  # than linked from publication_private_dep) so the
  # WYL_TEST_WYCTL_PUBLICATION_WINDOWS-gated owner-only predicate hook is
  # available, mirroring how the daemon-http tests pull in http.c. Linking
  # publication_private_dep as well would duplicate the backend symbols.
  test_wyctl_publication_windows = executable('test-wyctl-publication-windows',
    'test-wyctl-publication-windows.c',
    '../wyrelog/wyctl/wyctl-publication-windows-private.c',
    '../wyrelog/wyctl/wyctl-publication-private.c',
    c_args : ['-DWYL_TEST_WYCTL_PUBLICATION_WINDOWS'],
    include_directories : [include_directories('../wyrelog'),
      include_directories('../wyrelog/wyctl')],
    dependencies : [wyrelog_dep, sodium_dep, advapi32_dep],
  )

  test('wyctl-publication-windows', test_wyctl_publication_windows)
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

  # The offline flow provisions an encrypted store via a production daemon,
  # which requires the fact store to be built in.
  if get_option('enable_fact_store').allowed()
    # Offline service-permission-closure operator flow. The seed helper opens the
    # encrypted store under its KeyProvider to inject an unsafe closure and to
    # read back closure/receipt counts, which the shell harness cannot do against
    # an encrypted store with sqlite3 directly.
    check_service_permission_closure_seed = executable(
      'check-service-permission-closure-seed',
      'check-service-permission-closure-seed.c',
      include_directories : include_directories('../wyrelog'),
      dependencies : [wyrelog_dep, sqlite_dep, duckdb_dep],
    )

    # Opens the STOPPED encrypted policy store under its file KeyProvider to
    # print one credential's authoritative NON-SECRET fields (state, generation,
    # verifier, salt) for the packaged service-credential lifecycle e2e harness,
    # which cannot read encrypted store rows with sqlite3 directly.
    check_service_credential_store_inspect = executable(
      'check-service-credential-store-inspect',
      'check-service-credential-store-inspect.c',
      include_directories : include_directories('../wyrelog'),
      dependencies : [wyrelog_dep, sqlite_dep, duckdb_dep],
    )

    # Build-guaranteed reader for the packaged service-credential rotation e2e:
    # counts durable audit_events rows for an (action, decision) pair by linking
    # the project's own DuckDB dependency, so the acceptance gate never silently
    # skips on a host that happens to lack a system duckdb CLI.
    check_audit_events_query = executable(
      'check-audit-events-query',
      'check-audit-events-query.c',
      include_directories : include_directories('../wyrelog'),
      dependencies : [wyrelog_dep, sqlite_dep, duckdb_dep],
    )

    test('service-permission-closure', sh,
      args : [
        meson.current_source_dir() / 'check-service-permission-closure.sh',
        wyctl_exe.full_path(),
        wyrelogd_exe.full_path(),
        check_service_permission_closure_seed.full_path(),
        python3.full_path(),
      ],
      depends : [
        wyctl_exe, wyrelogd_exe, check_service_permission_closure_seed,
      ],
      is_parallel : false,
      timeout : 120,
    )

    # Packaged, encrypted, end-to-end service-credential lifecycle runtime proof
    # (#382 Unit 1a): bootstrap -> real-TOTP admin -> self-arm -> tenant/principal
    # -> issue -> exchange -> /decide deny -> grant -> /decide allow. The audit
    # sink is exercised end-to-end, so it is additionally gated on enable_audit.
    #
    # Linux is the sole PACKAGED-RUNTIME platform for the service-credential
    # lifecycle e2e suite (#382 Unit 6, docs/service-credential-platform-support.md):
    # macOS and Windows are BUILD-ONLY for these gates. macOS packaged-runtime is
    # not asserted because of documented runtime flakiness (handoff-e2e SIGABRT
    # re-run-passes); the daemon/shell e2e harness is already POSIX-only. The
    # helper exes above stay built (a macOS/Windows-eligible build gate); only the
    # runtime test() registrations below are Linux-only. This gate is enforced by
    # tests/check-service-credential-platform-matrix.py -- do not broaden it (for
    # example back to != 'windows') without updating the frozen matrix doc.
    if host_machine.system() == 'linux' and get_option('enable_audit').allowed()
      test('service-credential-lifecycle-e2e', sh,
        args : [
          meson.current_source_dir() / 'check-service-credential-lifecycle-e2e.sh',
          wyrelogd_exe.full_path(),
          wyctl_exe.full_path(),
          check_service_credential_store_inspect.full_path(),
          meson.project_source_root() / 'templates' / 'access',
          python3.full_path(),
          meson.current_source_dir() / 'wyrelog_sc_e2e.py',
        ],
        depends : [
          wyrelogd_exe, wyctl_exe, check_service_credential_store_inspect,
        ],
        is_parallel : false,
        timeout : 300,
      )

      # Packaged, encrypted, end-to-end ZERO-SURVIVOR + NO-REFRESH runtime proof
      # (#382 Unit 2): credential revoke / principal disable / tenant seal each
      # leave zero usable or pending service tokens (fresh exchange fails; an
      # already-minted token stops resolving), and a service token has no
      # refresh/renewal path. Same gating as the lifecycle driver.
      test('service-credential-zero-survivor-e2e', sh,
        args : [
          meson.current_source_dir()
            / 'check-service-credential-zero-survivor-e2e.sh',
          wyrelogd_exe.full_path(),
          wyctl_exe.full_path(),
          check_service_credential_store_inspect.full_path(),
          meson.project_source_root() / 'templates' / 'access',
          python3.full_path(),
          meson.current_source_dir() / 'wyrelog_sc_e2e.py',
        ],
        depends : [
          wyrelogd_exe, wyctl_exe, check_service_credential_store_inspect,
        ],
        is_parallel : false,
        timeout : 300,
      )

      # Packaged, encrypted, end-to-end KEYPROVIDER ROOT ROTATION + CREDENTIAL
      # ROTATION + RESTART + AUDIT runtime proof (#382 Unit 3). This is the first
      # test to `wyctl key rotate` a store that CONTAINS a live credential: it
      # proves the populated CVK envelope + credential row survive byte-for-byte,
      # then that `wyctl service-credential rotate` retires A and stands up B
      # across real daemon restarts, with a durable sanitized audit. The audit
      # DuckDB is read with the build-guaranteed check-audit-events-query helper
      # (never a system duckdb CLI), so the gate cannot silently skip. Real TOTP
      # + several daemon boots -> 360s.
      test('service-credential-rotation-e2e', sh,
        args : [
          meson.current_source_dir()
            / 'check-service-credential-rotation-e2e.sh',
          wyrelogd_exe.full_path(),
          wyctl_exe.full_path(),
          check_service_credential_store_inspect.full_path(),
          meson.project_source_root() / 'templates' / 'access',
          python3.full_path(),
          meson.current_source_dir() / 'wyrelog_sc_e2e.py',
          check_audit_events_query.full_path(),
        ],
        depends : [
          wyrelogd_exe, wyctl_exe, check_service_credential_store_inspect,
          check_audit_events_query,
        ],
        is_parallel : false,
        timeout : 360,
      )

      # Packaged, encrypted, end-to-end LEAK SCAN (#382 Unit 5). Runs the full
      # lifecycle prefix (issue -> exchange -> grant -> decide -> rotate),
      # captures a per-run UNIQUE canary for every sensitive value the test can
      # observe (issued + rotated secret, service JWT, bearer header, session
      # id, jti, an injected request-body marker, the admin TOTP seed) and, via
      # store-inspect, the authoritative verifier/salt, then asserts each canary
      # is ABSENT (raw+base64+hex) from EVERY forbidden sink -- facts, audit,
      # recovery records, daemon logs, and all CLI/HTTP capture files -- while
      # confirming the encrypted policy store exposes no plaintext verifier/salt.
      # A single hit is a real secret leak: the scan FAILS LOUD.
      test('service-credential-leak-scan-e2e', sh,
        args : [
          meson.current_source_dir()
            / 'check-service-credential-leak-scan-e2e.sh',
          wyrelogd_exe.full_path(),
          wyctl_exe.full_path(),
          check_service_credential_store_inspect.full_path(),
          meson.project_source_root() / 'templates' / 'access',
          python3.full_path(),
          meson.current_source_dir() / 'wyrelog_sc_e2e.py',
        ],
        depends : [
          wyrelogd_exe, wyctl_exe, check_service_credential_store_inspect,
        ],
        is_parallel : false,
        timeout : 300,
      )

      # Packaged, encrypted, end-to-end LOCAL-PUBLICATION-FAULT + ORPHAN-RECOVERY
      # runtime proof (#382 Unit 4; the #380 orphan-window contract). Arms the
      # compile-gated single-shot #754 seam via --fault-inject-sc-publication-once
      # so a service-credential SERVER-COMMIT succeeds but the post-commit LOCAL
      # publication fails once, then proves NO secret on disk + a
      # restart-surviving, recoverable/revocable orphan keyed by the request id.
      # The daemon runs WITH --production (a real encrypted daemon: the CVK the
      # SC issue needs is wired only under --production). This is registered ONLY
      # when enable_fault_injection is set -- the seam and its flag do not exist
      # in a release build -- ADDITIONALLY to the linux + enable_audit gating of
      # the other SC e2e drivers. Honest status: the packaged SC e2e suite is a
      # documented LOCAL/manual gate today -- the CI --suite wyrelog job does not
      # yet build enable_client/enable_fact_store/enable_fault_injection, so none
      # of these packaged tests run in CI. Wiring them into a Linux CI job is a
      # tracked follow-up; the platform-matrix checker does NOT assert CI enables
      # the option, so it stays honest.
      if get_option('enable_fault_injection').allowed()
        test('service-credential-publication-fault-e2e', sh,
          args : [
            meson.current_source_dir()
              / 'check-service-credential-publication-fault-e2e.sh',
            wyrelogd_exe.full_path(),
            wyctl_exe.full_path(),
            check_service_credential_store_inspect.full_path(),
            meson.project_source_root() / 'templates' / 'access',
            python3.full_path(),
            meson.current_source_dir() / 'wyrelog_sc_e2e.py',
          ],
          depends : [
            wyrelogd_exe, wyctl_exe, check_service_credential_store_inspect,
          ],
          is_parallel : false,
          timeout : 300,
        )
      endif
    endif
  endif

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
  'fact-test-support.c',
  c_args : [
    '-DWYL_TEST_SQLITE_SCHEMA_PATH="' + meson.project_source_root() / 'templates' / 'access' / 'sqlite-schema.sql' + '"',
  ] + fact_test_support_c_args,
  dependencies : [wyrelog_dep, sqlite_dep] + fact_test_support_deps,
)

test('policy-store', test_policy_store,
  timeout : 90,
)

test_policy_graph_authority = executable('test-policy-graph-authority',
  'test-policy-graph-authority.c',
  include_directories : include_directories('../wyrelog'),
  dependencies : [wyrelog_dep, sqlite_dep, sodium_dep],
)

test('policy-graph-authority', test_policy_graph_authority,
  timeout : 90,
)

test_fact_graph_locator = executable('test-fact-graph-locator',
  'test-fact-graph-locator.c',
  include_directories : include_directories('../wyrelog'),
  dependencies : [wyrelog_dep],
)

test('fact-graph-locator', test_fact_graph_locator)

test_fact_artifact_transition_names = executable(
  'test-fact-artifact-transition-names',
  'test-fact-artifact-transition-names.c',
  include_directories : include_directories('../wyrelog'),
  dependencies : [wyrelog_dep],
)
test('fact-artifact-transition-names', test_fact_artifact_transition_names)

test_fact_artifact_transition_driver = executable(
  'test-fact-artifact-transition-driver',
  'test-fact-artifact-transition-driver.c',
  'fact-artifact-transition-driver-fixture.c',
  include_directories : include_directories('../wyrelog'),
  dependencies : [wyrelog_dep],
)
test('fact-artifact-transition-driver', test_fact_artifact_transition_driver)
test('fact-artifact-transition-driver-wiring', python3,
  args : [
    meson.current_source_dir() / 'test-fact-artifact-transition-driver-wiring.py',
    meson.project_source_root(),
  ],
  timeout : 120,
)
test('fact-artifact-transition-driver-wiring-self', python3,
  args : [
    meson.current_source_dir() / 'test-fact-artifact-transition-driver-wiring.py',
    '--self-test',
    meson.project_source_root(),
  ],
  timeout : 300,
)

if host_machine.system() != 'windows'
  test_fact_artifact_transition_posix = executable(
    'test-fact-artifact-transition-posix',
    'test-fact-artifact-transition-posix.c',
    'fact-artifact-transition-driver-fixture.c',
    'fact-test-support.c',
    include_directories : include_directories('../wyrelog'),
    c_args : fact_test_support_c_args,
    dependencies : [wyrelog_dep] + fact_test_support_deps,
  )
  test('fact-artifact-transition-posix', test_fact_artifact_transition_posix)
endif

if host_machine.system() == 'windows'
  test_fact_artifact_transition_windows = executable(
    'test-fact-artifact-transition-windows',
    'test-fact-artifact-transition-windows.c',
    'fact-artifact-transition-driver-fixture.c',
    'fact-test-support.c',
    include_directories : include_directories('../wyrelog'),
    c_args : fact_test_support_c_args,
    dependencies : [wyrelog_handle_test_seams_dep] + fact_test_support_deps,
  )
  test('fact-artifact-transition-windows', test_fact_artifact_transition_windows)
endif

test_fact_artifact_main_transition = executable(
  'test-fact-artifact-main-transition',
  'test-fact-artifact-main-transition.c',
  include_directories : include_directories('../wyrelog'),
  dependencies : [wyrelog_dep],
)
test('fact-artifact-main-transition', test_fact_artifact_main_transition)

test_fact_artifact_durability = executable('test-fact-artifact-durability',
  'test-fact-artifact-durability.c',
  include_directories : include_directories('../wyrelog'),
  dependencies : [wyrelog_dep],
)
test('fact-artifact-durability-contract', test_fact_artifact_durability)

test_fact_artifact_durability_journal_codec = executable(
  'test-fact-artifact-durability-journal-codec',
  'test-fact-artifact-durability-journal-codec.c',
  include_directories : include_directories('../wyrelog'),
  dependencies : [wyrelog_dep],
)
test('fact-artifact-durability-journal-codec',
  test_fact_artifact_durability_journal_codec)

test_fact_artifact_inventory = executable('test-fact-artifact-inventory',
  'test-fact-artifact-inventory.c',
  include_directories : include_directories('../wyrelog'),
  dependencies : [wyrelog_dep],
)
test('fact-artifact-inventory-contract', test_fact_artifact_inventory)

test_fact_artifact_inventory_consumers = executable(
  'test-fact-artifact-inventory-consumers',
  'test-fact-artifact-inventory-consumers.c',
  include_directories : include_directories('../wyrelog'),
  dependencies : [wyrelog_dep],
)
test('fact-artifact-inventory-consumer-contract',
  test_fact_artifact_inventory_consumers)

test('fact-artifact-inventory-consumer-wiring', python3,
  args : [
    meson.current_source_dir() / 'test-fact-artifact-inventory-consumer-wiring.py',
    meson.project_source_root(),
  ],
)
test('fact-artifact-inventory-consumer-wiring-self', python3,
  args : [
    meson.current_source_dir() / 'test-fact-artifact-inventory-consumer-wiring.py',
    '--self-test',
    meson.project_source_root(),
  ],
  timeout : 120,
)

test_fact_artifact_namespace = executable('test-fact-artifact-namespace',
  'test-fact-artifact-namespace.c',
  include_directories : include_directories('../wyrelog'),
  dependencies : [wyrelog_handle_test_seams_dep],
)
test('fact-artifact-namespace', test_fact_artifact_namespace)
if host_machine.system() != 'windows'
  test('fact-artifact-namespace-inventory', test_fact_artifact_namespace,
    args : ['-p', '/fact-artifact-namespace/inventory-provider'],
  )
endif
if host_machine.system() == 'windows' and win_artifact_test_hooks_opt.allowed()
  # This is intentionally separate from test-fact-artifact-namespace: that
  # historical POSIX test is compiled out on Windows and cannot prove native
  # HANDLE ownership or runtime behavior.
  #
  # It also requires enable_windows_artifact_test_hooks (#741): every case in
  # this binary runs through the WinFaultGuard fixture, which disarms every
  # native artifact fault family between cases.
  #
  # To support both default_library=static and default_library=shared on
  # Windows without exporting private test-only symbols from libwyrelog.dll,
  # this binary links against wyrelog_handle_test_seams_dep (#654).
  # fact-test-support.c is compiled in rather than linked: it defines only
  # wyl_test_* helpers and calls no private wyrelog symbol, so it does not
  # disturb the wyrelog_handle_test_seams_dep linkage above.  The pair cases
  # need its wyl_test_make_secure_fact_root to get a resolver-acceptable root.
  test_fact_artifact_namespace_windows = executable(
    'test-fact-artifact-namespace-windows',
    'test-fact-artifact-namespace-windows.c',
    'fact-test-support.c',
    c_args : fact_test_support_c_args,
    include_directories : include_directories('../wyrelog'),
    dependencies : [wyrelog_handle_test_seams_dep] + fact_test_support_deps,
  )
  windows_appverifier_probe_dll = shared_module(
    'test-windows-appverifier-probe-dll',
    'windows-appverifier-probe-dll.c',
    name_prefix : '',
  )
  windows_appverifier_probe = executable(
    'test-windows-appverifier-probe',
    'windows-appverifier-probe.c',
  )
  test('fact-artifact-namespace-windows',
    test_fact_artifact_namespace_windows,
    timeout : 120,
  )
  # Keep the long lifecycle subjects independently observable.  Each filtered
  # invocation is a separate process, so a fatal assertion in one subject
  # cannot suppress the remaining coverage in the CI matrix.
  foreach lifecycle_case : [
    ['main-sidecar', '/fact/artifact-namespace/windows/namespace/main-sidecar'],
    ['sidecar-replacement-isolated', '/fact/artifact-namespace/windows/sidecar/replacement-isolated'],
    ['temp-binding-replacement-isolated', '/fact/artifact-namespace/windows/temp-binding/replacement-isolated'],
    ['lock-entry-replacement-isolated', '/fact/artifact-namespace/windows/namespace/lock-entry-replacement-isolated'],
    ['temp-token-real-crash-recovery', '/fact/artifact-namespace/windows/namespace/temp-token-real-crash-recovery'],
    ['cross-process', '/fact/artifact-namespace/windows/lock-domain/cross-process'],
    ['temp-root-spill-child-capabilities', '/fact/artifact-namespace/windows/temp-root/spill-child-capabilities'],
    ['temp-root-wrapper-ownership', '/fact/artifact-namespace/windows/temp-root/wrapper-ownership'],
    ['mutation-handle-lifetime', '/fact/artifact-namespace/windows/mutation-handle-lifetime'],
    ['inventory', '/fact/artifact-namespace/windows/inventory'],
  ]
    test('fact-artifact-namespace-windows-' + lifecycle_case[0],
      test_fact_artifact_namespace_windows,
      args : ['-p', lifecycle_case[1]],
      is_parallel : false,
      timeout : 120,
    )
  endforeach
endif

subprocess_test_env = environment()
if host_machine.system() == 'windows'
  glib_genmarshal = glib_dep.get_variable(
    pkgconfig : 'glib_genmarshal',
    default_value : '',
  )
  if glib_genmarshal != '' and fs.is_absolute(glib_genmarshal)
    subprocess_test_env.prepend('PATH',
      fs.parent(glib_genmarshal),
      separator : ';',
    )
  endif
endif

fact_root_writer_lease_c_args = fact_test_support_c_args
fact_root_writer_lease_depends = []
fact_root_writer_lease_deps = [wyrelog_dep, glib_dep, gio_dep, sqlite_dep]
if get_option('enable_fact_store').allowed()
  fact_root_writer_lease_c_args += [
    '-DWYL_HAS_FACT_STORE',
    '-DWYL_TEST_WYRELOGD_PATH="' + wyrelogd_exe.full_path() + '"',
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
  ]
  fact_root_writer_lease_depends += wyrelogd_exe
  fact_root_writer_lease_deps += duckdb_dep
endif

test_fact_root_writer_lease = executable('test-fact-root-writer-lease',
  'test-fact-root-writer-lease.c',
  'fact-test-support.c',
  c_args : fact_root_writer_lease_c_args,
  include_directories : include_directories('../wyrelog'),
  dependencies : fact_root_writer_lease_deps + fact_test_support_deps,
)

test('fact-root-writer-lease', test_fact_root_writer_lease,
  depends : fact_root_writer_lease_depends,
  env : subprocess_test_env,
  timeout : 60,
)

test('fact-root-writer-lease-boundary', python3,
  args : [files('test-fact-root-writer-lease-boundary.py'),
    meson.project_source_root()],
  env : python_strict_encoding_env,
)

test_fact_reconcile_move = executable('test-fact-reconcile-move',
  'test-fact-reconcile-move.c',
  'fact-test-support.c',
  c_args : fact_test_support_c_args,
  include_directories : include_directories('../wyrelog'),
  dependencies : [wyrelog_dep, glib_dep, gio_dep, sqlite_dep]
    + fact_test_support_deps,
)

test('fact-reconcile-move', test_fact_reconcile_move,
  timeout : 120,
)

if host_machine.system() == 'windows'
  fact_graph_locator_windows_env = environment()
  fact_graph_locator_windows_env.set(
    'G_MESSAGES_DEBUG',
    'wyrelog-fact-resolver',
  )

  test_fact_graph_locator_windows = executable(
    'test-fact-graph-locator-windows',
    'test-fact-graph-locator-windows.c',
    include_directories : include_directories('../wyrelog'),
    dependencies : [wyrelog_dep, advapi32_dep],
  )

  test('fact-graph-locator-windows', test_fact_graph_locator_windows,
    env : fact_graph_locator_windows_env,
    timeout : 90,
  )
endif

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

test_service_permission_receipt = executable('test-service-permission-receipt',
  'test-service-permission-receipt.c',
  include_directories : include_directories('../wyrelog'),
  dependencies : [wyrelog_dep, sqlite_dep, duckdb_dep],
)

test('service-permission-receipt', test_service_permission_receipt,
  timeout : 90,
)

test_service_permission_manifest = executable('test-service-permission-manifest',
  'test-service-permission-manifest.c',
  include_directories : include_directories('../wyrelog'),
  dependencies : [wyrelog_dep, sqlite_dep],
)

test('service-permission-manifest', test_service_permission_manifest,
  timeout : 90,
)

test_service_permission_maintenance = executable('test-service-permission-maintenance',
  'test-service-permission-maintenance.c',
  include_directories : include_directories('../wyrelog'),
  dependencies : [wyrelog_dep, sqlite_dep, duckdb_dep],
)

test('service-permission-maintenance', test_service_permission_maintenance,
  timeout : 90,
)

test_fact_schema = executable('test-fact-schema',
  'test-fact-schema.c',
  'fact-test-support.c',
  c_args : fact_test_support_c_args,
  include_directories : include_directories('../wyrelog'),
  dependencies : [wyrelog_dep, sqlite_dep] + fact_test_support_deps,
)

test('fact-schema', test_fact_schema)

if get_option('enable_fact_store').allowed()
  test_fact_provisioning = executable('test-fact-provisioning',
    'test-fact-provisioning.c',
    'fact-test-support.c',
    c_args : fact_test_support_c_args,
    include_directories : include_directories('../wyrelog'),
    # provisioning-private.h includes the DuckDB-backed store identity
    # contract.  Link the configured DuckDB dependency explicitly so the
    # header's include path is available on Windows as well as POSIX.
    dependencies : [wyrelog_dep, sqlite_dep, duckdb_dep]
      + fact_test_support_deps,
  )
  test('fact-provisioning', test_fact_provisioning)

  test_fact_store_identity_core = executable('test-fact-store-identity-core',
    'test-fact-store-identity-core.c',
    '../wyrelog/fact/store-identity-private.c',
    include_directories : include_directories('..', '../wyrelog'),
    dependencies : [glib_dep, duckdb_dep],
  )
  test('fact-store-identity-core', test_fact_store_identity_core)

  test_fact_reconcile = executable('test-fact-reconcile',
    'test-fact-reconcile.c',
    include_directories : include_directories('../wyrelog'),
    dependencies : [wyrelog_dep, sqlite_dep],
  )
  test('fact-reconcile', test_fact_reconcile)

  test_fact_store = executable('test-fact-store',
    'test-fact-store.c',
    include_directories : include_directories('../wyrelog'),
    dependencies : [wyrelog_dep, wirelog_dep, duckdb_dep, sqlite_dep],
  )

  test('fact-store', test_fact_store,
    timeout : 60,
  )

  test_fact_store_duckdb_hardening = executable(
    'test-fact-store-duckdb-hardening',
    'test-fact-store-duckdb-hardening.c',
    c_args : ['-DWYL_TEST_HANDLE_SEAMS'],
    include_directories : include_directories('../wyrelog'),
    dependencies : [wyrelog_handle_test_seams_dep, duckdb_dep, sqlite_dep],
  )

  test('fact-store-duckdb-hardening', test_fact_store_duckdb_hardening,
    timeout : 60,
  )
  test('fact-store-duckdb-autoload-runtime', python3,
    args : [
      files('test-fact-store-duckdb-autoload-runtime.py'),
      test_fact_store_duckdb_hardening,
    ],
    timeout : 60,
  )
  test('fact-store-duckdb-autoload-runtime-self-test', python3,
    args : [
      files('test-fact-store-duckdb-autoload-runtime.py'),
      '--self-test',
    ],
  )
  test('fact-store-duckdb-hardening-boundary', python3,
    args : [
      files('test-fact-store-duckdb-hardening-boundary.py'),
      meson.project_source_root(),
    ],
  )
  test('fact-store-duckdb-hardening-boundary-self-test', python3,
    args : [
      files('test-fact-store-duckdb-hardening-boundary.py'),
      '--self-test',
      meson.project_source_root(),
    ],
  )

  test_fact_store_forget_transaction = executable(
    'test-fact-store-forget-transaction',
    'test-fact-store-forget-transaction.c',
    c_args : ['-DWYL_TEST_HANDLE_SEAMS'],
    include_directories : include_directories('../wyrelog'),
    dependencies : [wyrelog_handle_test_seams_dep, duckdb_dep],
  )

  if host_machine.system() != 'windows'
    test('fact-store-forget-transaction',
      test_fact_store_forget_transaction,
      timeout : 60,
    )
  endif

  test_fact_compound = executable('test-fact-compound',
    'test-fact-compound.c',
    c_args : [
      '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
    ],
    include_directories : include_directories('../wyrelog'),
    dependencies : [wyrelog_dep, wirelog_dep, duckdb_dep, sqlite_dep],
  )

  test('fact-compound', test_fact_compound)

  test_fact_replay = executable('test-fact-replay',
    'test-fact-replay.c',
    'fact-test-support.c',
    '../wyrelog/daemon/fact-status.c',
    # Keep this consumer audit-macro-unaware to cover cross-TU layout stability.
    c_args : ['-DWYL_HAS_FACT_STORE'] + fact_test_support_c_args,
    include_directories : include_directories('../wyrelog'),
    dependencies : [wyrelog_dep, duckdb_dep, sqlite_dep]
        + fact_test_support_deps,
  )

  # Raised from 60 for issue #546: the new concurrent isolation case runs two
  # mutation workers plus a status observer.  ~14s here, but this suite is
  # also run under ASan/UBSan, where that multiplies past 60.
  test('fact-replay', test_fact_replay, timeout : 120)

  test_fact_runtime = executable('test-fact-runtime',
    'test-fact-runtime.c',
    include_directories : include_directories('../wyrelog'),
    dependencies : [wyrelog_dep, wirelog_dep],
  )

  test('fact-runtime', test_fact_runtime, timeout : 60)
endif

if get_option('enable_secure_duckdb_bridge').enabled()
  if host_machine.system() == 'darwin'
    test_fact_darwin_provisioned_pair = executable(
      'test-fact-darwin-provisioned-pair',
      'test-fact-darwin-provisioned-pair.c',
      include_directories : include_directories('../wyrelog'),
      dependencies : [wyrelog_handle_test_seams_dep, duckdb_dep],
    )
    test('fact-darwin-provisioned-pair',
      test_fact_darwin_provisioned_pair,
      timeout : 120,
    )
  endif
  test_secure_duckdb_artifact_contract = executable(
    'test-secure-duckdb-artifact-contract',
    'test-secure-duckdb-artifact-contract.cc',
    include_directories : include_directories('../wyrelog'),
    dependencies : [wyrelog_dep],
  )
  test('secure-duckdb-artifact-contract',
    test_secure_duckdb_artifact_contract)
  test_secure_duckdb_bridge = executable('test-secure-duckdb-bridge',
    'test-secure-duckdb-bridge.c',
    include_directories : include_directories('../wyrelog'),
    dependencies : [wyrelog_dep, duckdb_dep],
  )
  test('secure-duckdb-bridge', test_secure_duckdb_bridge)
  test_secure_duckdb_recording_filesystem = executable(
    'test-secure-duckdb-recording-filesystem',
    'test-secure-duckdb-recording-filesystem.cc',
    cpp_args : ['-DWYL_DUCKDB_SOURCE_BUILD=1'],
    dependencies : [glib_dep, gio_dep, duckdb_dep],
    override_options : ['cpp_std=c++17'],
  )
  test('secure-duckdb-recording-filesystem',
    test_secure_duckdb_recording_filesystem)
  test_fact_provisioning_construct = executable(
    'test-fact-provisioning-construct',
    'test-fact-provisioning-construct.c',
    'fact-test-support.c',
    c_args : fact_test_support_c_args,
    include_directories : include_directories('../wyrelog'),
    dependencies : [wyrelog_dep, sqlite_dep, duckdb_dep]
      + fact_test_support_deps,
  )
  test('fact-provisioning-construct', test_fact_provisioning_construct,
    timeout : 60,
  )
  if host_machine.system() == 'windows' and win_artifact_test_hooks_opt.allowed()
    # Exact provisioned-pair -> native namespace -> production secure
    # filesystem route. Link only the full-source test-seam archive so this
    # executable has one private implementation and no shipped-library twin.
    test_secure_duckdb_temp_child_windows = executable(
      'test-secure-duckdb-temp-child-windows',
      'test-secure-duckdb-temp-child-windows.cc',
      'fact-test-support.c',
      c_args : fact_test_support_c_args,
      include_directories : include_directories('../wyrelog'),
      dependencies : [wyrelog_handle_test_seams_dep, duckdb_dep]
        + fact_test_support_deps,
      override_options : ['cpp_std=c++17'],
    )
    test('secure-duckdb-temp-child-windows',
      test_secure_duckdb_temp_child_windows,
      timeout : 120,
    )
  endif
  test_secure_duckdb_filesystem = executable(
    'test-secure-duckdb-filesystem',
    'test-secure-duckdb-filesystem.cc',
    'fact-test-support.c',
    c_args : fact_test_support_c_args,
    include_directories : include_directories('../wyrelog'),
    dependencies : [wyrelog_dep, duckdb_dep] + fact_test_support_deps,
    override_options : ['cpp_std=c++17'],
  )
  # The suite's fixture calls wyl_fact_artifact_namespace_open, which the
  # Windows arm still answers WYRELOG_E_POLICY unconditionally, so every
  # case would fail in the constructor. Keep building the target there --
  # that is what proves the port compiles -- but only run it where the
  # authority it exercises is implemented.
  #
  # That is not the only thing standing between this suite and Windows.
  # ProvisionedPairFixture builds stage_path from the stage basename that
  # wyl_fact_graph_stage_publish_with_evidence then renames away, so the
  # cases that stat or unlink it are asserting against a name Windows does
  # not keep. Whoever implements the namespace arm has that to fix too (#816).
  if host_machine.system() != 'windows'
    test('secure-duckdb-filesystem', test_secure_duckdb_filesystem,
      timeout : 120,
    )
  endif
  test_fact_provisioning_run_wyrelog_dep = wyrelog_dep
  if host_machine.system() == 'darwin'
    test_fact_provisioning_run_wyrelog_dep = wyrelog_handle_test_seams_dep
  endif
  test_fact_provisioning_run = executable(
    'test-fact-provisioning-run',
    'test-fact-provisioning-run.c',
    'fact-test-support.c',
    c_args : fact_test_support_c_args,
    include_directories : include_directories('../wyrelog'),
    dependencies : [test_fact_provisioning_run_wyrelog_dep, sqlite_dep, duckdb_dep]
      + fact_test_support_deps,
  )
  # Linux asserts the retained hard-link pair; Darwin asserts a direct final
  # bound to durable operation evidence. Windows has no durable provisioning
  # evidence home yet (#816).
  if host_machine.system() != 'windows'
    test('fact-provisioning-run', test_fact_provisioning_run,
      timeout : host_machine.system() == 'darwin' ? 300 : 60,
    )
  endif
  test_fact_store_provisioned = executable(
    'test-fact-store-provisioned',
    'test-fact-store-provisioned.c',
    'fact-test-support.c',
    c_args : fact_test_support_c_args + ['-DWYL_HAS_SECURE_DUCKDB_BRIDGE'],
    include_directories : include_directories('../wyrelog'),
    dependencies : [wyrelog_dep, sqlite_dep, duckdb_dep]
      + fact_test_support_deps,
  )
  # Linux retains the stage/final hard-link pair; Darwin opens its direct final
  # through durable policy-owned operation evidence. Windows remains compile
  # only until its provisioning evidence has a durable authority home (#816).
  if host_machine.system() != 'windows'
    test('fact-store-provisioned', test_fact_store_provisioned,
      timeout : host_machine.system() == 'darwin' ? 300 : 60,
    )
  endif

  if host_machine.system() != 'windows'
    test_fact_store_forget_transaction_provision_helper = executable(
      'test-fact-store-forget-transaction-provision-helper',
      'test-fact-store-forget-transaction-provision-helper.c',
      'fact-test-support.c',
      c_args : fact_test_support_c_args,
      include_directories : include_directories('../wyrelog'),
      dependencies : [wyrelog_dep, sqlite_dep, duckdb_dep]
        + fact_test_support_deps,
    )

    test_fact_store_forget_transaction_provisioned = executable(
      'test-fact-store-forget-transaction-provisioned',
      'test-fact-store-forget-transaction-provisioned.c',
      c_args : ['-DWYL_HAS_SECURE_DUCKDB_BRIDGE', '-DWYL_TEST_HANDLE_SEAMS'],
      include_directories : include_directories('../wyrelog'),
      dependencies : [wyrelog_handle_test_seams_dep, sqlite_dep, duckdb_dep],
    )
    # Exercise the real policy-backed open path on both retained-pair Linux and
    # evidence-backed direct-final Darwin.
    if host_machine.system() != 'windows'
      test('fact-store-forget-transaction-provisioned',
        test_fact_store_forget_transaction_provisioned,
        args : [test_fact_store_forget_transaction_provision_helper.full_path()],
        depends : test_fact_store_forget_transaction_provision_helper,
        timeout : host_machine.system() == 'darwin' ? 300 : 60,
      )
    endif
  endif
  test_duckdb_after_walstart = executable(
    'test-duckdb-after-walstart',
    'test-secure-duckdb-recording-filesystem.cc',
    cpp_args : ['-DWYL_DUCKDB_SOURCE_BUILD=1'],
    dependencies : [glib_dep, gio_dep, duckdb_test_seam_dep],
    override_options : ['cpp_std=c++17'],
    build_by_default : false,
  )
  test('duckdb-after-walstart-no-wal', test_duckdb_after_walstart,
    args : [
      '-p',
      '/secure-duckdb-bridge/recording-filesystem/after-wal-start-no-wal',
    ],
    timeout : 30,
  )
  test('duckdb-after-walstart-rendezvous', test_duckdb_after_walstart,
    args : [
      '-p',
      '/secure-duckdb-bridge/recording-filesystem/after-wal-start-rendezvous',
    ],
    timeout : 30,
  )
  test('duckdb-valid-commit-failure', test_duckdb_after_walstart,
    args : [
      '-p',
      '/secure-duckdb-bridge/recording-filesystem/valid-commit-failure',
    ],
    timeout : 30,
  )
  test('duckdb-valid-rollback-failure', test_duckdb_after_walstart,
    args : [
      '-p',
      '/secure-duckdb-bridge/recording-filesystem/valid-rollback-failure',
    ],
    timeout : 30,
  )
  test('duckdb-fixed-wal-successful-checkpoint',
    test_duckdb_after_walstart,
    args : [
      '-p',
      '/secure-duckdb-bridge/recording-filesystem/concurrent-checkpoint-move',
    ],
    timeout : 30,
  )
  test('duckdb-fixed-wal-pre-move-abort-reopen',
    test_duckdb_after_walstart,
    args : [
      '-p',
      '/secure-duckdb-bridge/recording-filesystem/completed-checkpoint-recovery-move',
    ],
    timeout : 30,
  )
  test('duckdb-fixed-wal-interrupted-recovery',
    test_duckdb_after_walstart,
    args : [
      '-p',
      '/secure-duckdb-bridge/recording-filesystem/incomplete-checkpoint-recovery-move',
    ],
    timeout : 30,
  )
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

test('policy-store-lease', test_policy_store_lease,
  env : subprocess_test_env,
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

# #746: seam-enabled coverage for the MFA lockout / auto-unlock publication
# path. Links the full-source test-seams archive so the test can observe the
# rebuilt engine projection, inspect pair readiness/poison, and inject a
# deterministic post-commit rebuild fault. The always-on daemon-mfa-validator
# target above stays free of WYL_TEST_HANDLE_SEAMS.
test_daemon_mfa_validator_seams = executable('test-daemon-mfa-validator-seams',
  'test-daemon-mfa-validator-seams.c',
  c_args : [
    '-DWYL_TEST_HANDLE_SEAMS',
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
  ],
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : [wyrelog_handle_test_seams_dep, wirelog_dep, sqlite_dep,
    sodium_dep],
)

test('daemon-mfa-validator-seams', test_daemon_mfa_validator_seams)

# #751: shared-handle multi-threaded barrier race proving exactly-once TOTP
# proof consumption + MFA_OK publication under N concurrent same-step requests.
test_daemon_mfa_validator_race = executable('test-daemon-mfa-validator-race',
  'test-daemon-mfa-validator-race.c',
  c_args : [
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
  ],
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : [wyrelog_dep, sqlite_dep, sodium_dep, dependency('threads')],
)

test('daemon-mfa-validator-race', test_daemon_mfa_validator_race,
  timeout : 120)

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
  dependencies : [wyrelog_handle_test_seams_dep, wirelog_dep],
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

test_service_decision_authority = executable('test-service-decision-authority',
  'test-service-decision-authority.c',
  c_args : [
    '-DWYL_TEST_HANDLE_SEAMS',
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
  ],
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : [wyrelog_handle_test_seams_dep, wirelog_dep],
)

test('service-decision-authority', test_service_decision_authority,
  timeout : 60,
)

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

test('service-auth-registry-capability-boundary', python3,
  args : [meson.current_source_dir() /
    'test-service-auth-registry-capability-boundary.py'],
)

test('retirement-replay-boundary', python3,
  args : [meson.current_source_dir() /
    'test-retirement-replay-boundary.py'],
)

test_service_auth_coordination = executable('test-service-auth-coordination',
  'test-service-auth-coordination.c',
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : [wyrelog_dep, sqlite_dep],
)

test('service-auth-coordination', test_service_auth_coordination,
  is_parallel : host_machine.system() != 'windows',
  timeout : 30,
)

test_session_liveness_race = executable('test-session-liveness-race',
  'test-session-liveness-race.c',
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : [wirelog_dep, service_session_private_dep],
)

test('session-liveness-race', test_session_liveness_race,
  timeout : 60,
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
  [
    'test-service-principal-domain.c',
    '../wyrelog/daemon/auth-registry-private.c',
  ],
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  c_args : [
    '-DWYL_AUTH_REGISTRY_TESTING',
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
  ],
  dependencies : [wyrelog_dep, sodium_dep, sqlite_dep],
)

test('service-principal-domain', test_service_principal_domain,
  is_parallel : host_machine.system() != 'windows',
)

test_service_credential_domain_c_args = []
test_service_credential_domain_deps = [wyrelog_dep, sodium_dep, sqlite_dep]
service_exchange_audit_private_source = files(
  '../wyrelog/auth/service-exchange-audit-private.c',
)

# Non-installed companion for focused tests of hidden policy authority cores.
# It is needed in every feature configuration because remediation stays private
# to libwyrelog's dynamic symbol table.  Audit-enabled builds additionally link
# the one service-exchange private compilation context below, avoiding a second
# compilation of its audit codec in that configuration.
test_policy_store_private_companion_sources = files(
  '../wyrelog/policy/store.c',
  '../wyrelog/auth/service-credential-domain.c',
  '../wyrelog/auth/service-credential-handoff-delivery-private.c',
  '../wyrelog/auth/service-credential-operation-coordinator-auth-private.c',
  '../wyrelog/auth/service-credential-operation-coordinator-proof-private.c',
  '../wyrelog/auth/service-credential-operation-coordinator-cancel-private.c',
  '../wyrelog/auth/service-credential-operation-coordinator-retirement-private.c',
)
if not get_option('enable_audit').allowed()
  # The policy store uses the feature-independent audit codec even when the
  # service-exchange audit subsystem is disabled. Supply its implementation
  # here because service_exchange_private_dep does not exist.
  test_policy_store_private_companion_sources += \
    service_exchange_audit_private_source
endif

test_policy_store_private_companion = static_library(
  'test-policy-store-private-companion',
  test_policy_store_private_companion_sources,
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : wyrelog_deps,
  c_args : wyrelog_c_args,
  install : false,
  build_by_default : false,
)
test_service_credential_domain_link_with = [
  test_policy_store_private_companion,
]

if get_option('enable_audit').allowed()
  test_service_credential_domain_c_args += \
    '-DWYL_TEST_HAS_HANDOFF_MAINTENANCE_CORE'
  test_service_credential_domain_c_args += \
    '-DWYL_TEST_HAS_HANDOFF_CANCELLATION'
  test_service_credential_domain_deps += service_exchange_private_dep
endif
test_service_credential_domain_c_args += '-DWYL_AUTH_REGISTRY_TESTING'

test_service_credential_domain = executable('test-service-credential-domain',
  [
    'test-service-credential-domain.c',
    '../wyrelog/auth/service-credential-operation-coordinator-journal-private.c',
    '../wyrelog/auth/service-credential-operation-coordinator-storage-private.c',
    '../wyrelog/auth/service-credential-operation-storage-private.c',
    '../wyrelog/auth/service-credential-operation-storage-windows-private.c',
    '../wyrelog/daemon/auth-registry-private.c',
  ],
  c_args : test_service_credential_domain_c_args,
  link_with : test_service_credential_domain_link_with,
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : test_service_credential_domain_deps,
)

service_credential_domain_timeout = 180

test('service-credential-domain', test_service_credential_domain,
  is_parallel : host_machine.system() != 'windows',
  timeout : service_credential_domain_timeout,
)

test_service_credential_operation_fence = executable('test-service-credential-operation-fence',
  [
    'test-service-credential-operation-fence.c',
    '../wyrelog/auth/service-credential-operation-coordinator-journal-private.c',
    '../wyrelog/auth/service-credential-operation-coordinator-storage-private.c',
    '../wyrelog/auth/service-credential-operation-storage-private.c',
    '../wyrelog/auth/service-credential-operation-storage-windows-private.c',
  ],
  c_args : ['-DWYL_SERVICE_CREDENTIAL_OPERATION_TEST_FRIENDS'],
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
  [
    'test-service-credential-operation-coordinator-journal.c',
    '../wyrelog/auth/service-credential-operation-coordinator-journal-private.c',
    '../wyrelog/auth/service-credential-operation-coordinator-storage-private.c',
    '../wyrelog/auth/service-credential-operation-storage-private.c',
    '../wyrelog/auth/service-credential-operation-storage-windows-private.c',
  ],
  c_args : ['-DWYL_SERVICE_CREDENTIAL_OPERATION_TEST_FRIENDS'],
  dependencies : [wyrelog_dep, sodium_dep],
  include_directories : [wyrelog_inc, include_directories('../wyrelog')])
test('service-credential-operation-coordinator-journal', test_service_credential_operation_coordinator_journal)

test_service_credential_operation_coordinator_retirement = executable(
  'test-service-credential-operation-coordinator-retirement',
  [
    'test-service-credential-operation-coordinator-retirement.c',
    '../wyrelog/auth/service-credential-operation-coordinator-journal-private.c',
    '../wyrelog/auth/service-credential-operation-coordinator-storage-private.c',
    '../wyrelog/auth/service-credential-operation-storage-private.c',
    '../wyrelog/auth/service-credential-operation-storage-windows-private.c',
  ],
  c_args : ['-DWYL_SERVICE_CREDENTIAL_OPERATION_TEST_FRIENDS'],
  link_with : test_policy_store_private_companion,
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : test_service_credential_domain_deps,
)

test('service-credential-operation-coordinator-retirement',
  test_service_credential_operation_coordinator_retirement,
  is_parallel : host_machine.system() != 'windows',
  timeout : 180,
)

test_service_credential_operation_coordinator_execute_c_args = [
  '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
  '-DWYL_SERVICE_CREDENTIAL_OPERATION_TEST_FRIENDS',
]
test_service_credential_operation_coordinator_execute_deps = [
  wyrelog_dep,
  sodium_dep,
  sqlite_dep,
]
if get_option('enable_audit').allowed()
  test_service_credential_operation_coordinator_execute_c_args += '-DWYL_HAS_AUDIT'
  test_service_credential_operation_coordinator_execute_deps += [
    duckdb_dep,
    service_exchange_private_dep,
  ]
endif

test_service_credential_operation_coordinator_execute = executable('test-service-credential-operation-coordinator-execute',
  [
    'test-service-credential-operation-coordinator-execute.c',
    '../wyrelog/auth/service-credential-operation-coordinator-journal-private.c',
    '../wyrelog/auth/service-credential-operation-coordinator-storage-private.c',
    '../wyrelog/auth/service-credential-operation-storage-private.c',
    '../wyrelog/auth/service-credential-operation-storage-windows-private.c',
  ],
  link_with : test_policy_store_private_companion,
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

test_service_credential_operation_coordinator_handoff = executable('test-service-credential-operation-coordinator-handoff',
  [
    'test-service-credential-operation-coordinator-handoff.c',
    '../wyrelog/auth/service-credential-operation-coordinator-journal-private.c',
    '../wyrelog/auth/service-credential-operation-coordinator-storage-private.c',
    '../wyrelog/auth/service-credential-operation-storage-private.c',
    '../wyrelog/auth/service-credential-operation-storage-windows-private.c',
  ],
  link_with : test_policy_store_private_companion,
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : test_service_credential_operation_coordinator_execute_deps,
  c_args : test_service_credential_operation_coordinator_execute_c_args,
)

test('service-credential-operation-coordinator-handoff',
  test_service_credential_operation_coordinator_handoff,
  is_parallel : host_machine.system() != 'windows',
  timeout : service_credential_operation_coordinator_execute_timeout,
)

# The real-publication case stamps the fixture's publication root with a
# protected owner-only DACL on Windows, which needs the advapi32 security APIs.
test_daemon_service_credential_handoff_deps = (
  test_service_credential_operation_coordinator_execute_deps
  + [publication_private_dep])
if host_machine.system() == 'windows'
  test_daemon_service_credential_handoff_deps += advapi32_dep
endif
test_daemon_service_credential_handoff = executable('test-daemon-service-credential-handoff',
  [
    'test-daemon-service-credential-handoff.c',
    '../wyrelog/daemon/service-credential-handoff-private.c',
  ],
  include_directories : [wyrelog_inc, include_directories('../wyrelog'),
    include_directories('../wyrelog/wyctl')],
  dependencies : test_daemon_service_credential_handoff_deps,
  c_args : test_service_credential_operation_coordinator_execute_c_args
    + ['-DWYL_TEST_DAEMON_HTTP'],
)

test('daemon-service-credential-handoff',
  test_daemon_service_credential_handoff,
  is_parallel : host_machine.system() != 'windows',
  timeout : service_credential_operation_coordinator_execute_timeout,
)

if get_option('enable_audit').allowed()
  test_service_credential_operation_coordinator_cancel = executable(
    'test-service-credential-operation-coordinator-cancel',
    [
      'test-service-credential-operation-coordinator-cancel.c',
      '../wyrelog/auth/service-credential-operation-coordinator-journal-private.c',
      '../wyrelog/auth/service-credential-operation-coordinator-storage-private.c',
      '../wyrelog/auth/service-credential-operation-storage-private.c',
      '../wyrelog/auth/service-credential-operation-storage-windows-private.c',
    ],
    link_with : test_policy_store_private_companion,
    include_directories : [wyrelog_inc, include_directories('../wyrelog')],
    dependencies : test_service_credential_domain_deps,
    c_args : test_service_credential_operation_coordinator_execute_c_args,
  )

  test('service-credential-operation-coordinator-cancel',
    test_service_credential_operation_coordinator_cancel,
    is_parallel : host_machine.system() != 'windows',
    timeout : service_credential_operation_coordinator_execute_timeout,
  )

  test_service_credential_operation_coordinator_remediate = executable(
    'test-service-credential-operation-coordinator-remediate',
    'test-service-credential-operation-coordinator-remediate.c',
    '../wyrelog/auth/service-credential-operation-coordinator-remediate-private.c',
    '../wyrelog/auth/service-credential-operation-coordinator-storage-private.c',
    '../wyrelog/auth/service-credential-operation-coordinator-journal-private.c',
    '../wyrelog/auth/service-credential-operation-storage-private.c',
    '../wyrelog/auth/service-credential-operation-storage-windows-private.c',
    link_with : test_policy_store_private_companion,
    include_directories : [wyrelog_inc, include_directories('../wyrelog')],
    dependencies : test_service_credential_domain_deps,
    c_args : test_service_credential_operation_coordinator_execute_c_args,
  )

  test('service-credential-operation-coordinator-remediate',
    test_service_credential_operation_coordinator_remediate,
    is_parallel : host_machine.system() != 'windows',
    timeout : service_credential_operation_coordinator_execute_timeout,
  )
endif

# The storage test fault hooks (#775) are compiled here and nowhere else. This
# target builds the two storage translation units itself and calls
# wyl_win_child_* directly, so arming a hook and running the operation under
# test both resolve to this target's own copy. Defining the macro as a
# per-target c_arg rather than a project argument means libwyrelog is never
# given it in any configuration, so a shipped library cannot contain the hooks
# at all -- two of which would otherwise be a call-arbitrary-function-pointer
# site inside the credential publication path.
test_service_credential_operation_storage = executable('test-service-credential-operation-storage',
  [
    'test-service-credential-operation-storage.c',
    '../wyrelog/auth/service-credential-operation-storage-private.c',
    '../wyrelog/auth/service-credential-operation-storage-windows-private.c',
  ],
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  c_args : ['-DWYL_ENABLE_SERVICE_CREDENTIAL_STORAGE_TEST_HOOKS'],
  dependencies : [wyrelog_dep, sodium_dep, sqlite_dep],
)

test('service-credential-operation-storage', test_service_credential_operation_storage)

test_service_credential_operation_storage_enumerate = executable('test-service-credential-operation-storage-enumerate',
  [
    'test-service-credential-operation-storage-enumerate.c',
    '../wyrelog/auth/service-credential-operation-storage-private.c',
    '../wyrelog/auth/service-credential-operation-storage-windows-private.c',
  ],
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : [wyrelog_dep, sodium_dep, sqlite_dep],
)

test('service-credential-operation-storage-enumerate', test_service_credential_operation_storage_enumerate)

test_service_credential_operation_coordinator_status = executable('test-service-credential-operation-coordinator-status',
  [
    'test-service-credential-operation-coordinator-status.c',
    '../wyrelog/auth/service-credential-operation-coordinator-status-private.c',
    '../wyrelog/auth/service-credential-operation-coordinator-journal-private.c',
    '../wyrelog/auth/service-credential-operation-coordinator-storage-private.c',
    '../wyrelog/auth/service-credential-operation-storage-private.c',
    '../wyrelog/auth/service-credential-operation-storage-windows-private.c',
  ],
  c_args : ['-DWYL_SERVICE_CREDENTIAL_OPERATION_TEST_FRIENDS'],
  include_directories : [wyrelog_inc, include_directories('../wyrelog')],
  dependencies : [wyrelog_dep, sodium_dep, sqlite_dep],
)

test('service-credential-operation-coordinator-status',
  test_service_credential_operation_coordinator_status,
  is_parallel : host_machine.system() != 'windows',
  timeout : 30,
)

# Production OS-dispatch publication backend vtable adapter. Kept outside the
# `build_client and host_machine.system() != 'windows'` guard on purpose: the
# wyctl publication tests are off on Windows (and the windows variant sits in an
# unreachable else-branch), so the daemon-facing adapter would otherwise have
# zero Windows coverage. The adapter selects the concrete backend per OS
# internally, so the same test drives the real backend on both platforms.
test_publication_backend_deps = [wyrelog_dep, sodium_dep,
  publication_private_dep]
if host_machine.system() == 'windows'
  test_publication_backend_deps += advapi32_dep
endif
test_publication_backend = executable('test-publication-backend',
  'test-publication-backend.c',
  include_directories : [include_directories('../wyrelog'),
    include_directories('../wyrelog/wyctl')],
  dependencies : test_publication_backend_deps,
)

test('publication-backend', test_publication_backend)

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
    '-DWYL_TEST_HANDLE_SEAMS',
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
  ],
  dependencies : [wyrelog_handle_test_seams_dep, wirelog_dep, sqlite_dep],
)

test('handle-engine-pair', test_handle_engine_pair,
  timeout : 120,
)

test_lobac_partial_delta = executable('test-lobac-partial-delta',
  'test-lobac-partial-delta.c',
  c_args : [
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
  ],
  dependencies : [wyrelog_handle_test_seams_dep, wirelog_dep],
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
  test_service_exchange_audit_codec_sources += \
    service_exchange_audit_private_source
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

service_session_boundary_args = [meson.project_source_root(), '--compiler-id',
  service_session_boundary_cc_id, '--build-root', meson.project_build_root()]
if get_option('enable_audit').disabled()
  service_session_boundary_args += [
    '--allow-uncompiled-owner',
    'wyrelog/auth/service-exchange-private.c',
    '--allow-uncompiled-owner',
    'tests/test-service-exchange-private.c',
  ]
endif

test('check-service-session-private-boundary',
  check_service_session_private_boundary,
  args : service_session_boundary_args + ['--'] + service_session_boundary_cc,
  # Full semantic preprocessing follows every configured TU and can vary
  # substantially with compiler/system-header performance on shared runners.
  is_parallel : false,
  timeout : 1500,
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

check_wyctl_operation_delegation = find_program(
  '../tools/check-wyctl-operation-delegation.py',
)

test('check-wyctl-operation-delegation',
  check_wyctl_operation_delegation,
  args : [meson.project_source_root() / 'wyrelog' / 'wyctl' / 'wyctl.c'],
)

test('check-wyctl-operation-delegation-self-test',
  check_wyctl_operation_delegation,
  args : ['--self-test'],
)

check_wyctl_option_ownership = find_program(
  '../tools/check-wyctl-option-ownership.py',
)

test('check-wyctl-option-ownership',
  check_wyctl_option_ownership,
  args : [meson.project_source_root() / 'wyrelog' / 'wyctl' / 'wyctl.c'],
)

test('check-wyctl-option-ownership-self-test',
  check_wyctl_option_ownership,
  args : ['--self-test'],
)

check_service_credential_escrow_issuer = find_program(
  '../tools/check-service-credential-escrow-issuer.py',
)

test('check-service-credential-escrow-issuer',
  check_service_credential_escrow_issuer,
  args : [meson.project_source_root()],
)

test('check-service-credential-escrow-issuer-self-test',
  check_service_credential_escrow_issuer,
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
  dependencies : [wyrelog_handle_test_seams_dep, wirelog_dep,
    service_session_private_dep],
)

test('session-username', test_session_username,
  timeout : 60,
)

test_session_username_lifecycle = executable('test-session-username-lifecycle',
  'test-session-username.c',
  c_args : test_session_username_c_args + '-DWYL_TEST_VARIANT_LIFECYCLE',
  dependencies : [wyrelog_handle_test_seams_dep, wirelog_dep,
    service_session_private_dep],
)

session_username_lifecycle_progress_env = environment()
session_username_lifecycle_progress_env.set(
  'WYL_TEST_SESSION_USERNAME_LIFECYCLE_PROGRESS', '1')

test('session-username-lifecycle', test_session_username_lifecycle,
  env : session_username_lifecycle_progress_env,
  timeout : 60,
)

check_session_username_lifecycle = find_program(
  '../tools/check-session-username-lifecycle.py',
)

test('check-session-username-lifecycle-self-test',
  check_session_username_lifecycle,
  args : ['--self-test'],
  env : python_strict_encoding_env,
)

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
  dependencies : [wyrelog_handle_test_seams_dep, wirelog_dep] + (get_option('enable_audit').allowed()
      ? [duckdb_dep]
      : []),
)

test('decide', test_decide)

test_perm = executable('test-perm',
  'test-perm.c',
  c_args : [
    '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
  ],
  dependencies : [wyrelog_handle_test_seams_dep, wirelog_dep],
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
    dependencies : [wyrelog_handle_test_seams_dep, wirelog_dep, duckdb_dep],
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

test('ci-hosted-runner-contract', python3,
  args : [files('test-ci-hosted-runner-contract.py'),
    meson.project_source_root()],
  env : python_strict_encoding_env,
)

test('ci-hosted-runner-contract-self-test', python3,
  args : [files('test-ci-hosted-runner-contract.py'),
    '--self-test', meson.project_source_root()],
  env : python_strict_encoding_env,
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

service_auth_write_terminal_owners_guard = find_program(
  '../tools/check-service-auth-write-terminal-owners.py')
test('check-service-auth-write-terminal-owners',
  service_auth_write_terminal_owners_guard,
  args : [meson.project_source_root()],
)
test('check-service-auth-write-terminal-owners-self-test', python3,
  args : [
    meson.current_source_dir() / 'test-service-auth-write-terminal-owners.py',
    service_auth_write_terminal_owners_guard.full_path(),
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
    timeout : 300,
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

test('duckdb-after-walstart-boundary', python3,
  args : [files('test-duckdb-after-walstart-boundary.py'),
    meson.project_source_root()])

test('duckdb-transaction-control-boundary', python3,
  args : [files('test-duckdb-transaction-control-boundary.py'),
    meson.project_source_root()])

test('fact-store-forget-transaction-boundary', python3,
  args : [files('test-fact-store-forget-transaction-boundary.py'),
    meson.project_source_root()])

test('fact-store-forget-transaction-boundary-self', python3,
  args : [files('test-fact-store-forget-transaction-boundary.py'),
    '--self-test', meson.project_source_root()])

test('duckdb-test-seam-wiring', python3,
  args : [files('test-duckdb-test-seam-wiring.py'),
    meson.project_source_root()])

# Registered unconditionally: the gate it enforces is a property of the source
# tree, so a POSIX-only build must fail on a Windows hook that escapes it.
test('windows-artifact-test-hook-wiring', python3,
  args : [files('test-windows-artifact-test-hook-wiring.py'),
    meson.project_source_root()])

# Unconditional for the same reason.
test('service-credential-storage-test-hook-wiring', python3,
  args : [files('test-service-credential-storage-test-hook-wiring.py'),
    meson.project_source_root()])

test('duckdb-fixed-wal-lifecycle-boundary', python3,
  args : [files('test-duckdb-fixed-wal-lifecycle-boundary.py'),
    meson.project_source_root()])

test('secure-duckdb-ci-wiring', python3,
  args : [files('test-secure-duckdb-ci-wiring.py'),
    meson.project_source_root()])

test('windows-ci-timeout-boundary', python3,
  args : [files('test-windows-ci-timeout-boundary.py'),
    meson.project_source_root()])

test('windows-appverifier-wiring', python3,
  args : [files('test-windows-appverifier-wiring.py'),
    meson.project_source_root()])

test('windows-artifact-handle-lifetime-boundary', python3,
  args : [files('test-windows-artifact-handle-lifetime-boundary.py'),
    meson.project_source_root()])

test('windows-artifact-handle-lifetime-boundary-self-test', python3,
  args : [files('test-windows-artifact-handle-lifetime-boundary.py'),
    '--self-test', meson.project_source_root()])

test('windows-temp-child-ownership-boundary', python3,
  args : [files('test-windows-temp-child-ownership-boundary.py'),
    meson.project_source_root()])

test('windows-temp-child-ownership-boundary-self-test', python3,
  args : [files('test-windows-temp-child-ownership-boundary.py'),
    '--self-test', meson.project_source_root()])

if host_machine.system() == 'linux'
  test('duckdb-compile-swap', python3,
    args : [files('test-duckdb-compile-swap.py'),
      meson.project_source_root()])
endif

test('fact-store-pinned-boundary', python3,
  args : [files('test-fact-store-pinned-boundary.py'),
    meson.project_source_root()],
  env : python_strict_encoding_env)

if host_machine.system() != 'windows'
  test('duckdb-numeric-boundary', python3,
    args : [files('test-secure-duckdb-numeric-boundary.py'),
      meson.project_source_root()])

  valgrind_gate = find_program(
    '../tools/run-valgrind-gate.sh',
  )

  test('valgrind-smoke', valgrind_gate,
    args : [test_smoke.full_path()],
    depends : test_smoke,
    timeout : 120,
  )
endif

if get_option('enable_audit').disabled()
  test_daemon_checks_noaudit = executable('test-daemon-checks-noaudit',
    'test-daemon-checks-noaudit.c',
    '../wyrelog/daemon/checks.c',
    '../wyrelog/daemon/delta.c',
    c_args : [
      '-DWYL_TEST_DAEMON_CHECKS',
      '-DWYL_TEST_HANDLE_SEAMS',
      '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
    ],
    include_directories : [wyrelog_inc, include_directories('../wyrelog')],
    dependencies : [wyrelog_handle_test_seams_dep, wirelog_dep, sqlite_dep],
  )

  test('daemon-checks-noaudit', test_daemon_checks_noaudit, timeout : 120)

  if host_machine.system() != 'windows'
    readiness_persistent_has_fact = '0'
    if get_option('enable_fact_store').allowed()
      readiness_persistent_has_fact = '1'
    endif
    test('wyrelogd-readiness-persistent', find_program('sh'),
      args : [
        meson.current_source_dir() / 'check-wyrelogd-readiness-persistent.sh',
        wyrelogd_readiness_persistent_test_exe.full_path(),
        meson.project_source_root() / 'templates' / 'access',
        python3.full_path(),
        readiness_persistent_has_fact,
      ],
      depends : wyrelogd_readiness_persistent_test_exe,
      timeout : 120,
    )
  endif
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

  test_audit_conn_duckdb_hardening = executable(
    'test-audit-conn-duckdb-hardening',
    'test-audit-conn-duckdb-hardening.c',
    c_args : ['-DWYL_TEST_HANDLE_SEAMS'],
    include_directories : include_directories('../wyrelog'),
    dependencies : [wyrelog_handle_test_seams_dep, duckdb_dep, sqlite_dep],
  )

  # Issue #920: DuckDB 1.5.5 compares 64-bit CountZeros results with
  # 32-bit unsigned-long builtins under clang-cl/LLP64.  Until #920 fixes
  # those assertion oracles, positive/effective source-Windows runtime is
  # temporarily waived.  The retained child and structural gates below are
  # not equivalent positive-open or effective-settings evidence.
  audit_duckdb_hardening_source_windows_waived = \
    host_machine.system() == 'windows' and \
    cc.get_id() == 'clang-cl' and \
    get_option('duckdb_source') == 'subproject'
  if not audit_duckdb_hardening_source_windows_waived
    test('audit-conn-duckdb-hardening',
      test_audit_conn_duckdb_hardening,
      env : audit_conn_test_env,
      timeout : 60,
    )
  endif
  test('audit-conn-duckdb-autoload-clean-runtime', python3,
    args : [
      files('test-audit-conn-duckdb-autoload-runtime.py'),
      '--mode', 'clean',
      test_audit_conn_duckdb_hardening,
    ],
    env : audit_conn_test_env,
    timeout : 60,
  )
  test('audit-conn-duckdb-autoload-ambient-runtime', python3,
    args : [
      files('test-audit-conn-duckdb-autoload-runtime.py'),
      '--mode', 'ambient',
      test_audit_conn_duckdb_hardening,
    ],
    env : audit_conn_test_env,
    timeout : 60,
  )
  test('audit-conn-duckdb-autoload-runtime-self-test', python3,
    args : [
      files('test-audit-conn-duckdb-autoload-runtime.py'),
      '--self-test',
    ],
    env : audit_conn_test_env,
  )
  test('audit-conn-duckdb-hardening-boundary', python3,
    args : [
      files('test-audit-conn-duckdb-hardening-boundary.py'),
      meson.project_source_root(),
    ],
    env : audit_conn_test_env,
  )
  test('audit-conn-duckdb-hardening-boundary-self-test', python3,
    args : [
      files('test-audit-conn-duckdb-hardening-boundary.py'),
      '--self-test',
      meson.project_source_root(),
    ],
    env : audit_conn_test_env,
  )

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
    c_args : ['-DWYL_HAS_AUDIT', '-DWYL_AUTH_REGISTRY_TESTING'],
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
      meson.project_source_root()],
    env : python_strict_encoding_env)

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
      meson.project_source_root()],
    env : python_strict_encoding_env)

  test_audit_emit = executable('test-audit-emit',
    'test-audit-emit.c',
    c_args : [
      '-DWYL_HAS_AUDIT',
      '-DWYL_TEST_HANDLE_SEAMS',
      '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
    ],
    dependencies : [wyrelog_handle_test_seams_dep, duckdb_dep, sqlite_dep],
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
    dependencies : [wyrelog_handle_test_seams_dep, duckdb_dep, sqlite_dep],
  )

  test('daemon-checks', test_daemon_checks, env : audit_conn_test_env)

  test_login_projection = executable('test-login-projection',
    'test-login-projection.c',
    c_args : [
      '-DWYL_HAS_AUDIT',
      '-DWYL_TEST_TEMPLATE_DIR="' + meson.project_source_root() / 'templates' / 'access' + '"',
    ],
    dependencies : [wyrelog_handle_test_seams_dep, duckdb_dep, sqlite_dep],
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
    dependencies : [wyrelog_handle_test_seams_dep, duckdb_dep],
  )

  test('daemon-delta', test_daemon_delta, env : audit_conn_test_env)
endif
