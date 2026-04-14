project('duckdb', 'cpp',
  version : '1.5.1',
  license : 'MIT',
  default_options : [
    'cpp_std=c++17',
    'warning_level=0',
  ],
)

cpp = meson.get_compiler('cpp')

duckdb_deps = []

if host_machine.system() == 'linux'
  duckdb_deps += cpp.find_library('pthread', required : true)
  duckdb_deps += cpp.find_library('dl', required : true)
endif

duckdb_lib = library('duckdb',
  'duckdb.cpp',
  dependencies : duckdb_deps,
  include_directories : include_directories('.'),
  gnu_symbol_visibility : 'hidden',
  install : true,
)

duckdb_dep = declare_dependency(
  link_with : duckdb_lib,
  include_directories : include_directories('.'),
)

install_headers('duckdb.h')
