# Validate the public parser API that Wyrelog consumes instead of accepting a
# version string that may describe an older, incompatible Wirelog interface.
wirelog_signature_probe = '''
#include <stdbool.h>
#include <wirelog/wirelog-parser.h>

_Static_assert(
  _Generic(&wirelog_program_relation_has_input,
    bool (*)(const wirelog_program_t *, const char *): 1,
    default: 0),
  "wirelog_program_relation_has_input has an incompatible signature");

int
main(void)
{
  return 0;
}
'''

wirelog_link_probe = '''
#include <stdbool.h>
#include <wirelog/wirelog-parser.h>

_Static_assert(
  _Generic(&wirelog_program_relation_has_input,
    bool (*)(const wirelog_program_t *, const char *): 1,
    default: 0),
  "wirelog_program_relation_has_input has an incompatible signature");

int
main(void)
{
  return wirelog_program_relation_has_input(
      (const wirelog_program_t *) 0, "probe") ? 0 : 1;
}
'''

# The version string alone cannot distinguish pre/post source-inspection
# 0.70 builds. Validate the feature contract and every consumed easy symbol.
wirelog_source_declarations = '''
#include <stdbool.h>
#include <stdint.h>
#include <wirelog/wirelog-easy.h>
#if !defined(WIRELOG_SOURCE_QUERY_VERSION) || WIRELOG_SOURCE_QUERY_VERSION < 1
#error Wirelog source-query v1 is required
#endif
_Static_assert(_Generic(&wirelog_easy_source_count,
    wirelog_source_query_status_t (*)(wirelog_easy_session_t *, const char *,
      const int64_t *, uint32_t, uint64_t, uint64_t *): 1, default: 0),
    "incompatible source count signature");
_Static_assert(_Generic(&wirelog_easy_source_key_exists,
    wirelog_source_query_status_t (*)(wirelog_easy_session_t *, const char *,
      int64_t, uint64_t, bool *): 1, default: 0),
    "incompatible source key signature");
_Static_assert(_Generic(&wirelog_easy_source_validate,
    wirelog_source_query_status_t (*)(wirelog_easy_session_t *, const char *,
      uint32_t): 1, default: 0), "incompatible source validate signature");
_Static_assert(_Generic(&wirelog_easy_lookup_symbol,
    wirelog_source_query_status_t (*)(wirelog_easy_session_t *, const char *,
      int64_t *, bool *): 1, default: 0), "incompatible symbol lookup signature");
'''
wirelog_source_signature_probe = wirelog_source_declarations + '''
int main(void) { return 0; }
'''
wirelog_source_link_probe = wirelog_source_declarations + '''
int main(void) {
  uint64_t count = 0;
  int64_t id = 0;
  bool found = false;
  int result = wirelog_easy_source_count(0, "probe", &id, 1, 1, &count);
  result += wirelog_easy_source_key_exists(0, "probe", id, 1, &found);
  result += wirelog_easy_source_validate(0, "probe", 1);
  result += wirelog_easy_lookup_symbol(0, "probe", &id, &found);
  return result;
}
'''
# Same-version providers can still expose successful partial snapshots.
wirelog_snapshot_probe = '''
#include <wirelog/wirelog-easy.h>
#if !defined(WIRELOG_EASY_SNAPSHOT_COMPLETENESS_VERSION) || WIRELOG_EASY_SNAPSHOT_COMPLETENESS_VERSION < 1
#error Wirelog easy snapshot completeness v1 is required
#endif
int main(void) { return 0; }
'''
wirelog_snapshot_system_error = 'System Wirelog candidate lacks easy snapshot completeness v1.'
wirelog_snapshot_fallback_error = 'Pinned Wirelog fallback lacks easy snapshot completeness v1; apply package diffs.'

wirelog_source_signature_error = 'System Wirelog candidate lacks source-query v1 signatures.'
wirelog_source_link_error = 'System Wirelog candidate cannot link source-query v1 functions.'
wirelog_source_fallback_error = 'Pinned Wirelog fallback lacks source-query v1 signatures.'

wirelog_system_signature_error = (
  'System Wirelog candidate lacks required public API signature '
  + 'wirelog_program_relation_has_input from '
  + '<wirelog/wirelog-parser.h>.'
)
wirelog_system_link_error = (
  'System Wirelog candidate has the required declaration but cannot link '
  + 'public API wirelog_program_relation_has_input.'
)
wirelog_system_missing_error = (
  'System Wirelog candidate was not found; required public API '
  + 'wirelog_program_relation_has_input could not be validated.'
)
wirelog_fallback_signature_error = (
  'Pinned Wirelog fallback lacks required public API signature '
  + 'wirelog_program_relation_has_input from '
  + '<wirelog/wirelog-parser.h>.'
)
wirelog_nofallback_error = (
  '--wrap-mode=nofallback refuses the pinned Wirelog fallback required '
  + 'to satisfy wirelog_program_relation_has_input, source-query v1 and easy snapshot completeness v1.'
)

wirelog_force_fallback = (
  wrap_mode == 'forcefallback' or 'wirelog' in force_fallback_for
      or get_option('product_install')
)
wirelog_dep = disabler()
wirelog_system_rejection = ''

if not wirelog_force_fallback
  wirelog_system_candidate = dependency('wirelog',
    version : wirelog_version,
    required : false,
    allow_fallback : false,
  )
  if wirelog_system_candidate.found()
    if not cc.compiles(wirelog_signature_probe,
        dependencies : wirelog_system_candidate,
        name : 'system Wirelog required API signature')
      wirelog_system_rejection = wirelog_system_signature_error
    elif not cc.links(wirelog_link_probe,
        dependencies : wirelog_system_candidate,
        name : 'system Wirelog required API link')
      wirelog_system_rejection = wirelog_system_link_error
    elif not cc.compiles(wirelog_source_signature_probe,
        dependencies : wirelog_system_candidate,
        name : 'system Wirelog source-query v1 signatures')
      wirelog_system_rejection = wirelog_source_signature_error
    elif not cc.links(wirelog_source_link_probe,
        dependencies : wirelog_system_candidate,
        name : 'system Wirelog source-query v1 link')
      wirelog_system_rejection = wirelog_source_link_error
    elif not cc.compiles(wirelog_snapshot_probe,
        dependencies : wirelog_system_candidate,
        name : 'system Wirelog easy snapshot completeness v1')
      wirelog_system_rejection = wirelog_snapshot_system_error
    else
      wirelog_dep = wirelog_system_candidate
    endif
  else
    wirelog_system_rejection = wirelog_system_missing_error
  endif

  if wirelog_system_rejection != ''
    message(wirelog_system_rejection)
  endif
endif

if not wirelog_dep.found()
  if wrap_mode == 'nofallback'
    error(wirelog_system_rejection + ' ' + wirelog_nofallback_error)
  endif

  wirelog_proj = subproject('wirelog',
    version : wirelog_version,
    default_options : ['tests=false', 'documentation=false', 'benchmarks=false'],
  )
  wirelog_consumer_args = []
  if host_machine.system() == 'windows'
    wirelog_consumer_args += ['-DWIRELOG_BUILDING']
  endif
  wirelog_inc = wirelog_proj.get_variable('wirelog_inc')
  wirelog_src_inc = wirelog_proj.get_variable('wirelog_src_inc')

  # A source-subproject target does not exist yet at configure time, so Meson
  # cannot link-probe it here.  This proves the declaration and exact type;
  # every real or fixture consumer subsequently proves the definition by
  # linking the constructed wirelog_lib target.
  if not cc.compiles(wirelog_signature_probe,
      args : wirelog_consumer_args,
      include_directories : [wirelog_inc, wirelog_src_inc],
      name : 'pinned Wirelog fallback required API signature')
    wirelog_fallback_error = wirelog_fallback_signature_error
    if wirelog_system_rejection != ''
      wirelog_fallback_error += (
        ' Prior system rejection: ' + wirelog_system_rejection
      )
    endif
    error(wirelog_fallback_error)
  endif

  if not cc.compiles(wirelog_source_signature_probe,
      args : wirelog_consumer_args,
      include_directories : [wirelog_inc, wirelog_src_inc],
      name : 'pinned Wirelog source-query v1 signatures')
    error(wirelog_source_fallback_error)
  endif

  if not cc.compiles(wirelog_snapshot_probe,
      args : wirelog_consumer_args,
      include_directories : [wirelog_inc, wirelog_src_inc],
      name : 'pinned Wirelog easy snapshot completeness v1')
    error(wirelog_snapshot_fallback_error)
  endif

  wirelog_dep = declare_dependency(
    link_with : wirelog_proj.get_variable('wirelog_lib'),
    include_directories : [wirelog_inc, wirelog_src_inc],
    compile_args : wirelog_consumer_args,
  )
endif
