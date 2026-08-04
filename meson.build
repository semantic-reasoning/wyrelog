project('wyrelog', 'c',
  version : '0.1.0',
  license : 'GPL-3.0-or-later',
  meson_version : '>= 1.1.0',
  default_options : [
    'c_std=c17',
    'warning_level=2',
  ],
)

glib_dep = dependency('glib-2.0', required : true)
gio_dep = dependency('gio-2.0', required : true)
libsoup_dep = dependency('libsoup-3.0',
  version : '>= 3.0',
  required : get_option('enable_client'),
)
sodium_dep = dependency('libsodium', required : true)
sqlite_dep = dependency('sqlite3', required : true)
cc = meson.get_compiler('c')
if not cc.has_function('sqlite3_deserialize', dependencies : sqlite_dep) or \
    not cc.has_function('sqlite3_serialize', dependencies : sqlite_dep)
  error('SQLite must provide sqlite3_deserialize/sqlite3_serialize for encrypted policy stores')
endif
tss2_esys_dep = dependency('tss2-esys', required : get_option('enable_tpm'))
enable_audit_opt = get_option('enable_audit')
enable_fact_store_opt = get_option('enable_fact_store')
enable_break_glass_opt = get_option('enable_break_glass')
enable_secure_duckdb_bridge_opt = get_option('enable_secure_duckdb_bridge')
duckdb_test_seam_dep = disabler()
if enable_secure_duckdb_bridge_opt.enabled()
  if not enable_fact_store_opt.enabled()
    error('enable_secure_duckdb_bridge requires enable_fact_store=enabled')
  endif
  if get_option('duckdb_source') != 'subproject'
    error('enable_secure_duckdb_bridge requires duckdb_source=subproject (pinned DuckDB 1.5.5 source)')
  endif
  # This is a C++ API contract on every supported host.  In particular, do
  # not let the Windows C-only bridge target silently resolve a prebuilt DLL:
  # the source subproject is the provenance boundary there too.
  add_languages('cpp', required : true, native : false)
endif
if enable_break_glass_opt and not enable_audit_opt.allowed()
  # The break-glass override path emits an audit event with a stable
  # reason code on every arming and every override decision. Without
  # the audit subsystem there is no place to record those events, so
  # break-glass would silently bypass policy with no audit trail.
  # Refuse the configuration at meson-setup time rather than ship a
  # build that violates the meson.options:84-86 contract.
  error('enable_break_glass=true requires enable_audit to be enabled '
      + '(auto or enabled); the override path needs a durable audit '
      + 'sink for reason-code emission.')
endif
if enable_audit_opt.allowed() or enable_fact_store_opt.allowed()
  duckdb_source = get_option('duckdb_source')
  if duckdb_source == 'prebuilt'
    if host_machine.system() == 'linux'
      duckdb_dep = dependency('duckdb-prebuilt-linux',
        fallback : ['duckdb-prebuilt-linux', 'duckdb_dep'])
    elif host_machine.system() == 'darwin'
      duckdb_dep = dependency('duckdb-prebuilt-osx',
        fallback : ['duckdb-prebuilt-osx', 'duckdb_dep'])
    elif host_machine.system() == 'windows'
      duckdb_dep = dependency('duckdb-prebuilt-windows',
        fallback : ['duckdb-prebuilt-windows', 'duckdb_dep'])
    else
      error('duckdb_source=prebuilt is not supported on host system: '
          + host_machine.system())
    endif
  else
    # From-source build of the upstream DuckDB amalgamated single-TU
    # release. Slow (multi-minute single-TU C++ compile) but uses the
    # same source layout the upstream project ships and exercises the
    # full link path. Intended for main-branch CI to validate that
    # wyrelog still links cleanly against a freshly built libduckdb.
    if enable_secure_duckdb_bridge_opt.enabled()
      # The secure bridge is coupled to the pinned DuckDB C++ API.  Bypass
      # generic dependency discovery so it can only use this exact source
      # subproject (currently v1.5.5), never a system lookalike.
      duckdb_subproject = subproject('duckdb-amalgamated', required : true)
      duckdb_dep = duckdb_subproject.get_variable('duckdb_dep')
      if host_machine.system() != 'windows'
        duckdb_test_seam_dep = duckdb_subproject.get_variable(
          'duckdb_test_seam_dep')
      endif
      # Meson 1.1 lacks SubprojectHolder.project_version(); the declared
      # subproject dependency carries that same project version.
      if duckdb_dep.version() != '1.5.5'
        error('enable_secure_duckdb_bridge requires DuckDB source subproject version 1.5.5')
      endif
    else
      duckdb_dep = dependency('duckdb-amalgamated',
        fallback : ['duckdb-amalgamated', 'duckdb_dep'])
    endif
  endif
else
  duckdb_dep = disabler()
endif

wirelog_version = '>= 0.53.0'
libchronoid_version = '>= 1.0.2'
force_fallback_for = get_option('force_fallback_for')
wrap_mode = get_option('wrap_mode')

wirelog_force_fallback = wrap_mode == 'forcefallback' or 'wirelog' in force_fallback_for
wirelog_dep = disabler()
if not wirelog_force_fallback
  wirelog_dep = dependency('wirelog',
    version : wirelog_version,
    required : false,
    allow_fallback : false,
  )
endif
if not wirelog_dep.found()
  if wrap_mode == 'nofallback'
    error(('Dependency wirelog @0@ was not found and --wrap-mode=nofallback '
        + 'disables subproject fallback.').format(wirelog_version))
  endif
  wirelog_proj = subproject(
    'wirelog',
    version : wirelog_version,
    default_options : ['tests=false', 'documentation=false'],
  )
  wirelog_consumer_args = []
  if host_machine.system() == 'windows'
    wirelog_consumer_args += ['-DWIRELOG_BUILDING']
  endif
  wirelog_dep = declare_dependency(
    link_with : wirelog_proj.get_variable('wirelog_lib'),
    include_directories : [
      wirelog_proj.get_variable('wirelog_inc'),
      wirelog_proj.get_variable('wirelog_src_inc'),
    ],
    compile_args : wirelog_consumer_args,
  )
endif

libchronoid_force_fallback = wrap_mode == 'forcefallback' or 'libchronoid' in force_fallback_for
libchronoid_dep = disabler()
if not libchronoid_force_fallback
  libchronoid_dep = dependency('libchronoid',
    version : libchronoid_version,
    required : false,
    allow_fallback : false,
  )
endif
if not libchronoid_dep.found()
  if wrap_mode == 'nofallback'
    error(('Dependency libchronoid @0@ was not found and --wrap-mode=nofallback '
        + 'disables subproject fallback.').format(libchronoid_version))
  endif
  libchronoid_proj = subproject(
    'libchronoid',
    version : libchronoid_version,
    default_options : ['tests=false', 'cli=false'],
  )
  libchronoid_dep = declare_dependency(
    link_with : libchronoid_proj.get_variable('chronoid_lib'),
    include_directories : libchronoid_proj.get_variable('inc'),
  )
endif

# Test-only, single-shot service-credential publication fault-injection seam
# (#754). Compile-gated OFF by default: when the option is not enabled the
# WYL_ENABLE_FAULT_INJECTION macro is undefined project-wide, so the seam, its
# daemon flag, and the focused unit subtest are not compiled at all -- a release
# daemon is byte-identical to today and can never be armed. A project argument
# (not a per-target c_arg) is used so libwyrelog, wyrelogd, and every test that
# compiles the affected translation units see the same definition uniformly.
enable_fault_injection_opt = get_option('enable_fault_injection')
if enable_fault_injection_opt.allowed()
  add_project_arguments('-DWYL_ENABLE_FAULT_INJECTION', language : 'c')
endif

# Test-only fault hooks of the native Windows graph-artifact modules (#741).
# Compile-gated OFF by default on the same terms as the seam above: when the
# option is not enabled the WYL_ENABLE_WINDOWS_ARTIFACT_TEST_HOOKS macro is
# undefined project-wide, so neither hook pair is declared or defined and each
# consumption site compiles down to the unhooked native call. A shipped library
# therefore cannot be armed and does not pay the interlocked read the armed
# form costs on every directory flush. A project argument (not a per-target
# c_arg) is used so libwyrelog and every test that compiles or links the
# affected translation units see the same definition uniformly.
win_artifact_test_hooks_opt = get_option('enable_windows_artifact_test_hooks')
if win_artifact_test_hooks_opt.allowed()
  add_project_arguments('-DWYL_ENABLE_WINDOWS_ARTIFACT_TEST_HOOKS',
      language : 'c')
endif

subdir('wyrelog')
subdir('tests')

# Install the access-control .dl template tree as a single subdir under
# ${datadir}/wyrelog/access. install_subdir mirrors the source layout
# (including the fsm/ subdirectory) and picks up future additions
# without requiring a meson.build edit per template.
install_subdir(
  'templates/access',
  install_dir : join_paths(get_option('datadir'), 'wyrelog'),
)
install_data(
  'tools/verify-template-release.sh',
  install_dir : join_paths(get_option('datadir'), 'wyrelog', 'tools'),
  install_mode : 'rwxr-xr-x',
)

install_data(
  'packaging/systemd/wyrelog.service',
  'packaging/systemd/wyrelog-system.service',
  'packaging/systemd/wyrelog-service.service',
  install_dir : join_paths(get_option('prefix'), 'lib', 'systemd', 'system'),
)
install_data(
  'packaging/sysusers.d/wyrelog.conf',
  install_dir : join_paths(get_option('prefix'), 'lib', 'sysusers.d'),
)
install_data(
  'packaging/tmpfiles.d/wyrelog.conf',
  install_dir : join_paths(get_option('prefix'), 'lib', 'tmpfiles.d'),
)
install_data(
  'packaging/wyrelogd.env',
  'packaging/system.env',
  'packaging/service.env',
  install_dir : join_paths(get_option('sysconfdir'), 'wyrelog'),
)
# Documentation-only wyrelogd.conf examples for each profile. Installed
# under ${datadir}/wyrelog/examples/ (NOT /etc/) so the operator must
# explicitly copy and chmod 0640 before wyrelogd will load the file;
# shipping into /etc/ would risk silently overriding a site config or
# leaving world-readable secrets-adjacent settings on disk.
install_data(
  'packaging/wyrelog/examples/wyrelogd-system.conf.example',
  'packaging/wyrelog/examples/wyrelogd-service.conf.example',
  install_dir : join_paths(get_option('datadir'), 'wyrelog', 'examples'),
)

# Activate the committed hook through a worktree-relative hooksPath. Source
# archives and unpacked sources nested below another repository deliberately
# skip this developer setup.
git_program = find_program('git', required : false)
if build_machine.system() != 'windows' and git_program.found()
  posix_sh = find_program('sh')
  git_toplevel = run_command(
    git_program,
    '-C', meson.project_source_root(),
    'rev-parse', '--show-toplevel',
    check : false,
  )
  physical_source_root = run_command(
    posix_sh,
    '-c', 'CDPATH= cd "$1" && pwd -P',
    'sh', meson.project_source_root(),
    check : false,
  )
  if git_toplevel.returncode() == 0 and \
      physical_source_root.returncode() == 0
    physical_git_toplevel = run_command(
      posix_sh,
      '-c', 'CDPATH= cd "$1" && pwd -P',
      'sh', git_toplevel.stdout().strip(),
      check : false,
    )
    if physical_git_toplevel.returncode() == 0 and \
        physical_git_toplevel.stdout().strip() == \
        physical_source_root.stdout().strip()
      git_hook_setup = find_program('tools/setup-git-hooks.sh')
      message('Activating committed git hooks')
      run_command(git_hook_setup, check : true)
    endif
  endif
endif
