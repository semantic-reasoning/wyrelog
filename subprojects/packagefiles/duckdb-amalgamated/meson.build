project('duckdb-amalgamated', 'cpp',
  version : '1.5.5',
  license : 'MIT',
  default_options : [
    'cpp_std=gnu++17',
    'warning_level=0',
  ],
)

cpp = meson.get_compiler('cpp')

duckdb_deps = []
duckdb_compile_args = []
duckdb_ext_deps = []
duckdb_link_args = []

if host_machine.system() == 'linux'
  duckdb_deps += cpp.find_library('pthread', required : true)
  duckdb_deps += cpp.find_library('dl', required : true)
elif host_machine.system() == 'windows'
  # DuckDB's upstream Windows build is static. Without this definition the
  # amalgamation marks its own declarations dllimport while compiling them.
  duckdb_compile_args += ['-DDUCKDB_STATIC_BUILD']
  # The pinned amalgamation uses the Windows Restart Manager API when
  # removing files.  A static library cannot carry this import library on
  # its own, so make it a public dependency of the exported DuckDB target.
  duckdb_deps += cpp.find_library('rstrtmgr', required : true)
  if cpp.get_id() == 'gcc'
    duckdb_ext_deps += cpp.find_library('stdc++', required : true)
  endif
endif

# The source-pinned secure bridge is a static-ABI boundary.  In particular,
# DuckDB's public Windows headers select dllimport unless every consumer and
# the amalgamation agree on DUCKDB_STATIC_BUILD.  `library()` follows the
# parent's default_library and could therefore create a DLL while this
# dependency advertises the static ABI.  Make the artifact itself static so
# the target kind and exported compile contract cannot diverge.
duckdb_lib = static_library('duckdb',
  'duckdb.cpp',
  # Keep the source fallback on optimized, symbol-free codegen even when
  # the parent wyrelog build is debug. The DuckDB amalgamation is a large
  # single translation unit, and inheriting O0 from the root build makes
  # the fact/audit tests miss their runtime envelope (issue #386). The pin
  # must live on the target: per-subproject core options via project() or
  # caller default_options are silently ignored by older meson (measured
  # inert on 1.3.2, the ubuntu-latest apt version).
  override_options : ['optimization=2', 'debug=false', 'b_lto=false'],
  dependencies : duckdb_deps,
  cpp_args : duckdb_compile_args,
  include_directories : include_directories('.'),
  install : true,
)

duckdb_dep = declare_dependency(
  link_with : duckdb_lib,
  dependencies : [duckdb_deps, duckdb_ext_deps],
  include_directories : include_directories('.'),
  # The public C API defaults to dllimport on Windows.  The source
  # amalgamation above is deliberately static, so every target that includes
  # duckdb.h must receive the same static-link contract as duckdb_lib.
  compile_args : duckdb_compile_args,
  link_args : host_machine.system() == 'windows' and cpp.get_id() == 'gcc' ? ['-Wl,--whole-archive', duckdb_lib.full_path(), '-Wl,--no-whole-archive', '-lstdc++'] : [],
)

install_headers('duckdb.h')
