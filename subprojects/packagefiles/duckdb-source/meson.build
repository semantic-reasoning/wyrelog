project('duckdb-source', 'cpp',
  version : '2.0.0',
  license : 'MIT',
  default_options : [
    'cpp_std=c++17',
    'warning_level=0',
  ],
)

cpp = meson.get_compiler('cpp')
fs = import('fs')

# DuckDB 2.0 publishes no amalgamation, so this compiles the upstream tree.
# sources.txt, includes.txt, unity/ and the extension loader are generated
# from upstream's scripts/package_build.py by
# tools/generate-duckdb-source-overlay.py; regenerate them with the pin.
duckdb_sources = []
foreach source : fs.read('sources.txt').strip().split('\n')
  duckdb_sources += files(source)
endforeach
duckdb_include_dirs = ['.']
foreach include : fs.read('includes.txt').strip().split('\n')
  duckdb_include_dirs += include
endforeach
duckdb_includes = include_directories(duckdb_include_dirs)
# Consumers get only the directories DuckDB's public headers reach, not the
# thirty the library compiles with: every root is searched for every
# include, so the full list made each consumer translation unit resolve its
# own headers across DuckDB's third-party tree.  They see those headers as
# system headers, so wyrelog's warning flags do not report DuckDB's own
# unused parameters and the like.
duckdb_consumer_includes = include_directories(
  fs.read('consumer-includes.txt').strip().split('\n'),
  is_system : true)

duckdb_deps = []
# The source tree carries no version stamp: CMake and package_build both
# inject it.  Consumers need DUCKDB_VERSION too, so it is part of the
# exported compile contract.
#
# Meson leaves NDEBUG undefined, so the 1.5.5 amalgamation ran DuckDB's
# assertions.  In 2.0 that combination no longer compiles: helpers that only
# assertions use are declared under D_ASSERT_IS_ENABLED, which plain assert()
# does not set.  DUCKDB_FORCE_ASSERT is upstream's supported way to keep
# assertions on in an optimized build, and it sets that macro.  It is exported
# too, so the D_ASSERTs inlined from DuckDB headers into consumers such as the
# secure bridge expand exactly as they do inside the library.  It also enables
# upstream's D_ASSERT_IS_ENABLED verification code and makes a failed D_ASSERT
# throw an InternalException rather than abort, so a source build does more
# work per query than the prebuilt library.
duckdb_compile_args = [
  '-DDUCKDB_FORCE_ASSERT',
  '-DDUCKDB_VERSION="v' + meson.project_version() + '"',
  '-DDUCKDB_SOURCE_ID="d54cbbe3df"',
  '-DDUCKDB_MAJOR_VERSION=' + meson.project_version().split('.')[0],
  '-DDUCKDB_MINOR_VERSION=' + meson.project_version().split('.')[1],
  '-DDUCKDB_PATCH_VERSION="' + meson.project_version().split('.')[2] + '"',
]
duckdb_library_args = []
duckdb_link_args = []

if host_machine.system() == 'linux'
  duckdb_deps += cpp.find_library('pthread', required : true)
  duckdb_deps += cpp.find_library('dl', required : true)

  # libduckdb is a static C++ archive exported to pure-C targets.  Probe the
  # configured preprocessing environment instead of inferring its ABI from
  # the compiler id: Clang can use either libstdc++ or libc++, and native or
  # cross-file arguments may select a sysroot and standard library.
  duckdb_cpp_headers_available = cpp.compiles(
    '''
#include <cstddef>
int main(void) { return 0; }
''',
    name : 'configured C++ standard-library headers',
  )
  if not duckdb_cpp_headers_available
    error('DuckDB source configured C++ preprocessing environment cannot include <cstddef>')
  endif

  duckdb_uses_libstdcxx = cpp.compiles(
    '''
#include <cstddef>
#ifndef __GLIBCXX__
#error configured C++ standard library is not libstdc++
#endif
int main(void) { return 0; }
''',
    name : 'configured C++ standard library defines __GLIBCXX__',
  )
  duckdb_uses_libcxx = cpp.compiles(
    '''
#include <cstddef>
#ifndef _LIBCPP_VERSION
#error configured C++ standard library is not libc++
#endif
int main(void) { return 0; }
''',
    name : 'configured C++ standard library defines _LIBCPP_VERSION',
  )

  if duckdb_uses_libstdcxx and duckdb_uses_libcxx
    error('DuckDB source on Linux found both __GLIBCXX__ and _LIBCPP_VERSION; the configured C++ standard-library ABI is ambiguous')
  elif duckdb_uses_libcxx
    error('DuckDB source on Linux does not support libc++; use GCC/libstdc++ or Clang with -stdlib=libstdc++')
  elif not duckdb_uses_libstdcxx
    error('DuckDB source on Linux found neither __GLIBCXX__ nor _LIBCPP_VERSION; configure GCC/libstdc++ or Clang with -stdlib=libstdc++')
  endif

  # The C linker driver does not add either library implicitly.  Keep these
  # independent and public so regular and test-seam consumers inherit the
  # complete closure after the static DuckDB archive.
  duckdb_deps += cpp.find_library('m', required : true)
  duckdb_deps += cpp.find_library('stdc++', required : true)
  # CMake probes for fdatasync and defines this; every supported Linux has it.
  duckdb_library_args += ['-DDUCKDB_HAVE_FDATASYNC=1']
elif host_machine.system() == 'darwin'
  # libduckdb is a static C++ archive (static_library below) that gets linked
  # into the pure-C wyrelog targets (libwyrelog, wyrelogd, and the fact/audit
  # test binaries). When one of those is linked with the C compiler driver it
  # does not pull the C++ runtime, so libduckdb's references to the C++
  # standard library (std::to_string, typeinfo/vtable for duckdb::Exception,
  # __cxa_guard_*) are left undefined and the link fails -- observed as a
  # macOS-only CI link failure. Windows (below) already carries libstdc++ for
  # the same reason; macOS needs libc++. duckdb_deps is reused as the exported
  # dependency's dependencies, so every consumer picks it up; macOS ld64 is
  # link-order agnostic.
  duckdb_deps += cpp.find_library('c++', required : true)
elif host_machine.system() == 'windows'
  # DuckDB's upstream Windows build is static. Without this definition the
  # library marks its own declarations dllimport while compiling them.
  duckdb_compile_args += ['-DDUCKDB_STATIC_BUILD']
  # The pinned source uses the Windows Restart Manager API when
  # removing files.  A static library cannot carry this import library on
  # its own, so make it a public dependency of the exported DuckDB target.
  duckdb_deps += cpp.find_library('rstrtmgr', required : true)
  if cpp.get_id() == 'gcc'
    duckdb_deps += cpp.find_library('stdc++', required : true)
  endif
endif

# The source-pinned secure bridge is a static-ABI boundary.  In particular,
# DuckDB's public Windows headers select dllimport unless every consumer and
# the library agree on DUCKDB_STATIC_BUILD.  `library()` follows the
# parent's default_library and could therefore create a DLL while this
# dependency advertises the static ABI.  Make the artifact itself static so
# the target kind and exported compile contract cannot diverge.
duckdb_lib = static_library('duckdb',
  duckdb_sources,
  # Keep the source fallback on optimized, symbol-free codegen even when
  # the parent wyrelog build is debug. DuckDB is several hundred large
  # unity translation units, and inheriting O0 from the root build makes
  # the fact/audit tests miss their runtime envelope (issue #386). The pin
  # must live on the target: per-subproject core options via project() or
  # caller default_options are silently ignored by older meson (measured
  # inert on 1.3.2, the ubuntu-latest apt version).
  # clang-cl (the only Windows CI toolchain this subproject builds with)
  # exposes the MSVC-style cpp_std values only -- 'gnu++17' is not among
  # them and fails meson's option validation before the compiler is ever
  # invoked. The GNU dialect is safe to keep everywhere else (native
  # gcc/clang), so pin it back on per-target rather than in project().
  override_options : ['optimization=2', 'debug=false', 'b_lto=false']
    + (host_machine.system() != 'windows' ? ['cpp_std=gnu++17'] : []),
  dependencies : duckdb_deps,
  cpp_args : duckdb_compile_args + duckdb_library_args,
  include_directories : duckdb_includes,
  install : true,
)

duckdb_dep = declare_dependency(
  link_with : duckdb_lib,
  dependencies : duckdb_deps,
  include_directories : duckdb_consumer_includes,
  # The public C API defaults to dllimport on Windows.  The source
  # library above is deliberately static, so every target that includes
  # duckdb.h must receive the same static-link contract as duckdb_lib.
  compile_args : duckdb_compile_args,
  link_args : host_machine.system() == 'windows' and cpp.get_id() == 'gcc' ? ['-Wl,--whole-archive', duckdb_lib.full_path(), '-Wl,--no-whole-archive', '-lstdc++'] : [],
)

duckdb_test_seam_dep = disabler()
if true
  # Compile the pinned rendezvous as a separate, test-only DuckDB variant.
  # duckdb_lib above deliberately receives neither this macro nor this
  # dependency, so the installed/production library keeps its original ABI,
  # symbol surface, and checkpoint path.
  duckdb_test_seam_compile_args = duckdb_compile_args + [
    '-DWYL_DUCKDB_TEST_AFTER_WAL_START=1',
    '-DWYL_DUCKDB_TEST_TRANSACTION_CONTROL=1',
  ]
  duckdb_test_seam_optimization = host_machine.system() == 'linux' ? '0' : '2'
  duckdb_test_seam_lib = static_library('duckdb-test-after-wal-start',
    duckdb_sources,
    override_options : [
      'optimization=' + duckdb_test_seam_optimization,
      'debug=false',
      'b_lto=false',
      'cpp_std=' + (host_machine.system() == 'windows' ? 'c++17' : 'gnu++17'),
    ],
    dependencies : duckdb_deps,
    cpp_args : duckdb_test_seam_compile_args + duckdb_library_args,
    include_directories : duckdb_includes,
    install : false,
    build_by_default : false,
  )
  duckdb_test_seam_dep = declare_dependency(
    link_with : duckdb_test_seam_lib,
    dependencies : duckdb_deps,
    include_directories : duckdb_consumer_includes,
    compile_args : duckdb_test_seam_compile_args,
  )
endif

install_headers('src/include/duckdb.h')
