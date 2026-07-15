project('duckdb-amalgamated', 'cpp',
  version : '1.5.2',
  license : 'MIT',
  default_options : [
    # Keep the source fallback on a release-like optimization profile even
    # when the parent wyrelog build is debug. The DuckDB amalgamation is a
    # large single translation unit, and inheriting O0 from the root build
    # makes the fact/audit tests miss their runtime envelope on high-core
    # hosts.
    'buildtype=release',
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
  install : true,
)

duckdb_dep = declare_dependency(
  link_with : duckdb_lib,
  include_directories : include_directories('.'),
)

install_headers('duckdb.h')
