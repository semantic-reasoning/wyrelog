project('duckdb-prebuilt-windows', 'c',
  version : '1.5.1',
  license : 'MIT',
)

cc = meson.get_compiler('c')

duckdb_lib = cc.find_library('duckdb',
  dirs : meson.current_source_dir(),
  required : true,
)

# Copy duckdb.dll into the build root so test executables can locate it
# at runtime via the Windows loader's same-directory search rule.
fs = import('fs')
duckdb_runtime_dll = fs.copyfile('duckdb.dll', install : false)

duckdb_dep = declare_dependency(
  dependencies : duckdb_lib,
  sources : duckdb_runtime_dll,
  include_directories : include_directories('.'),
)
