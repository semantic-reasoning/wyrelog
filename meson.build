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
tss2_esys_dep = dependency('tss2-esys', required : get_option('enable_tpm'))
enable_audit_opt = get_option('enable_audit')
enable_break_glass_opt = get_option('enable_break_glass')
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
if enable_audit_opt.allowed()
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
    duckdb_dep = dependency('duckdb-amalgamated',
      fallback : ['duckdb-amalgamated', 'duckdb_dep'])
  endif
else
  duckdb_dep = disabler()
endif

wirelog_proj = subproject(
  'wirelog',
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

libchronoid_proj = subproject(
  'libchronoid',
  default_options : ['tests=false', 'cli=false'],
)
libchronoid_dep = declare_dependency(
  link_with : libchronoid_proj.get_variable('chronoid_lib'),
  include_directories : libchronoid_proj.get_variable('inc'),
)

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

# Install git pre-commit hook for code style checking
git_hook_script = find_program('hooks/pre-commit.hook')
git_dir = join_paths(meson.project_source_root(), '.git')
if run_command('test', '-d', git_dir, check : false).returncode() == 0
  message('Installing git pre-commit hook')
  run_command('cp', '-f',
    join_paths(meson.project_source_root(), 'hooks', 'pre-commit.hook'),
    join_paths(git_dir, 'hooks', 'pre-commit'),
    check : true,
  )
endif
