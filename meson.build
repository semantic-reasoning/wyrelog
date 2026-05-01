project('wyrelog', 'c',
  version : '0.1.0',
  license : 'GPL-3.0-or-later',
  meson_version : '>= 0.62.0',
  default_options : [
    'c_std=c17',
    'warning_level=2',
  ],
)

glib_dep = dependency('glib-2.0', required : true)
gio_dep = dependency('gio-2.0', required : true)
libsoup_dep = dependency('libsoup-3.0', version : '>= 3.0', required : true)
duckdb_dep = dependency('duckdb', fallback : ['duckdb', 'duckdb_dep'])

wirelog_proj = subproject(
  'wirelog',
  default_options : ['tests=false', 'documentation=false'],
)
wirelog_dep = declare_dependency(
  link_with : wirelog_proj.get_variable('wirelog_lib'),
  include_directories : [
    wirelog_proj.get_variable('wirelog_inc'),
    wirelog_proj.get_variable('wirelog_src_inc'),
  ],
)

install_data(
  'templates/access/bootstrap.dl',
  install_dir : join_paths(get_option('datadir'), 'wyrelog', 'access'),
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
