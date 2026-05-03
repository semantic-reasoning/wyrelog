project('duckdb-prebuilt-windows', 'c',
  version : '1.5.1',
  license : 'MIT',
)

cc = meson.get_compiler('c')

duckdb_lib = cc.find_library('duckdb',
  dirs : meson.current_source_dir(),
  required : true,
)

# duckdb.dll lives next to the import library duckdb.lib found above.
# Tests need the DLL on the loader search path at run time; the
# wrapping consumer (wyrelog/meson.build) is responsible for staging
# it next to the test executables. We deliberately do NOT add the
# DLL to declare_dependency's sources because that would feed it
# into the consumer's lib.exe / link.exe input list and break the
# static archive build on MSVC.
duckdb_dep = declare_dependency(
  dependencies : duckdb_lib,
  include_directories : include_directories('.'),
)

