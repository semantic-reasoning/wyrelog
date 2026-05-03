project('duckdb-prebuilt-osx', 'c',
  version : '1.5.1',
  license : 'MIT',
)

cc = meson.get_compiler('c')

duckdb_lib = cc.find_library('duckdb',
  dirs : meson.current_source_dir(),
  required : true,
)

duckdb_dep = declare_dependency(
  dependencies : duckdb_lib,
  include_directories : include_directories('.'),
)
