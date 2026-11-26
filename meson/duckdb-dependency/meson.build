# Select the DuckDB library for duckdb_source=prebuilt: an installed DuckDB
# 2.0.x when one passes every check below, otherwise the pinned upstream
# prebuilt subproject.  duckdb_source=subproject and the secure bridge never
# reach this file: they always build the pinned source.
#
# Inputs: cc, force_fallback_for, wrap_mode, product_install.
# Outputs: duckdb_dep, and duckdb_provider ('system' or 'prebuilt').

# The release series an installed DuckDB must belong to.  Wyrelog is written
# against 2.0.x: some 1.x/2.0 API differences compile silently, so a version
# outside this series is never used, it falls back.
duckdb_system_minimum = '2.0.0'
duckdb_system_limit = '2.1.0'

if host_machine.system() == 'linux'
  duckdb_prebuilt_name = 'duckdb-prebuilt-linux'
elif host_machine.system() == 'darwin'
  duckdb_prebuilt_name = 'duckdb-prebuilt-osx'
elif host_machine.system() == 'windows'
  duckdb_prebuilt_name = 'duckdb-prebuilt-windows'
else
  error('duckdb_source=prebuilt is not supported on host system: '
      + host_machine.system())
endif

# Every 1.x duckdb.h, and 2.0's too, report DUCKDB_API_VERSION 1.5.x, so the
# header is told apart by an error code that DuckDB 2.0 added.
duckdb_header_probe = '''
#include <duckdb.h>
int
main(void)
{
  duckdb_error_type resource_in_use = DUCKDB_ERROR_RESOURCE_IN_USE;
  return resource_in_use == DUCKDB_ERROR_INVALID ? 1 : 0;
}
'''

duckdb_link_probe = '''
#include <duckdb.h>
int
main(void)
{
  return duckdb_library_version () == 0;
}
'''

# The library itself reports its version, so a header and a library from
# different releases, or metadata that misdescribes them, are both caught.
duckdb_version_probe = '''
#include <stdio.h>
#include <duckdb.h>
int
main(void)
{
  const char *version = duckdb_library_version ();
  if (version == 0)
    return 1;
  printf ("%s\n", version);
  return 0;
}
'''

duckdb_nofallback_error = (
  '--wrap-mode=nofallback refuses the pinned DuckDB prebuilt fallback; '
  + 'install DuckDB ' + duckdb_system_minimum + ' or a later 2.0.x release.'
)

duckdb_force_fallback = (
  wrap_mode == 'forcefallback' or product_install
      or 'duckdb' in force_fallback_for
      or duckdb_prebuilt_name in force_fallback_for
)
duckdb_dep = disabler()
duckdb_provider = 'prebuilt'
duckdb_system_rejections = []

if not duckdb_force_fallback
  foreach duckdb_method : ['pkg-config', 'cmake']
    if duckdb_dep.found()
      break
    endif
    if duckdb_method == 'pkg-config'
      duckdb_candidate = dependency('duckdb',
        method : 'pkg-config',
        required : false,
        allow_fallback : false,
      )
    else
      duckdb_candidate = dependency('DuckDB',
        method : 'cmake',
        modules : ['duckdb'],
        required : false,
        allow_fallback : false,
      )
    endif
    duckdb_label = 'System DuckDB (' + duckdb_method + ')'
    if not duckdb_candidate.found()
      duckdb_system_rejections += [duckdb_label + ' was not found.']
      continue
    endif

    # DuckDB's CMake package reported versions as vX.Y.Z before 2.0.  Accept
    # only a plain X.Y.Z release: a range check alone admits 2.0.1-dev5.
    duckdb_candidate_version = duckdb_candidate.version().strip('v')
    duckdb_version_parts = duckdb_candidate_version.split('.')
    duckdb_release_version = duckdb_version_parts.length() == 3
    foreach duckdb_version_part : duckdb_version_parts
      if duckdb_version_part == '' or \
          duckdb_version_part.strip('0123456789') != ''
        duckdb_release_version = false
      endif
    endforeach
    if not duckdb_release_version or \
        not duckdb_candidate_version.version_compare(
          '>=' + duckdb_system_minimum) or \
        not duckdb_candidate_version.version_compare(
          '<' + duckdb_system_limit)
      duckdb_system_rejections += [duckdb_label + ' '
          + duckdb_candidate.version() + ' is not a DuckDB '
          + duckdb_system_minimum + ' or later 2.0.x release.']
      continue
    endif

    # The CMake target carries no include directory; DuckDB exports it as a
    # package variable.  Without it the probes and the build would read
    # whichever duckdb.h is on the default include path.
    if duckdb_method == 'cmake'
      duckdb_candidate_include = duckdb_candidate.get_variable(
        cmake : 'DuckDB_INCLUDE_DIRS', default_value : '')
      if duckdb_candidate_include == ''
        duckdb_system_rejections += [duckdb_label
            + ' does not name its include directory.']
        continue
      endif
      duckdb_candidate = declare_dependency(
        dependencies : duckdb_candidate,
        include_directories : include_directories(duckdb_candidate_include,
          is_system : true),
        version : duckdb_candidate_version,
      )
    endif

    if not cc.compiles(duckdb_header_probe,
        dependencies : duckdb_candidate,
        name : duckdb_label + ' 2.0 header')
      duckdb_system_rejections += [duckdb_label
          + ' header is not a DuckDB 2.0 header.']
      continue
    endif
    if not cc.links(duckdb_link_probe,
        dependencies : duckdb_candidate,
        name : duckdb_label + ' link')
      duckdb_system_rejections += [duckdb_label + ' cannot be linked.']
      continue
    endif
    if not meson.can_run_host_binaries()
      duckdb_system_rejections += [duckdb_label
          + ' cannot be run to check its library version.']
      continue
    endif
    duckdb_version_run = cc.run(duckdb_version_probe,
      dependencies : duckdb_candidate,
      name : duckdb_label + ' library version')
    if not duckdb_version_run.compiled() or \
        duckdb_version_run.returncode() != 0
      duckdb_system_rejections += [duckdb_label
          + ' library could not be run to report its version.']
      continue
    endif
    if duckdb_version_run.stdout().strip() != 'v' + duckdb_candidate_version
      duckdb_system_rejections += [duckdb_label + ' library does not report v'
          + duckdb_candidate_version + '.']
      continue
    endif

    duckdb_dep = duckdb_candidate
    duckdb_provider = 'system'
    duckdb_system_selection = (duckdb_label + ' ' + duckdb_candidate_version
        + ' is used.')
  endforeach

  foreach duckdb_rejection : duckdb_system_rejections
    message(duckdb_rejection)
  endforeach
  if duckdb_dep.found()
    message(duckdb_system_selection)
  endif
endif

if not duckdb_dep.found()
  if wrap_mode == 'nofallback'
    error(' '.join(duckdb_system_rejections) + ' ' + duckdb_nofallback_error)
  endif
  message('The pinned DuckDB prebuilt (' + duckdb_prebuilt_name
      + ') is used.')
  duckdb_dep = dependency(duckdb_prebuilt_name,
    fallback : [duckdb_prebuilt_name, 'duckdb_dep'])
endif
