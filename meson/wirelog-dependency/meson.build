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
  + 'to satisfy wirelog_program_relation_has_input.'
)

wirelog_force_fallback = (
  wrap_mode == 'forcefallback' or 'wirelog' in force_fallback_for
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
    default_options : ['tests=false', 'documentation=false'],
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

  wirelog_dep = declare_dependency(
    link_with : wirelog_proj.get_variable('wirelog_lib'),
    include_directories : [wirelog_inc, wirelog_src_inc],
    compile_args : wirelog_consumer_args,
  )
endif
