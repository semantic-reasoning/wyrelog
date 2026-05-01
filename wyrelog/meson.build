wyrelog_inc = include_directories('..')

wyrelog_public_headers = files(
  'error.h',
)

wyrelog_sources = files(
  'wyl-boot.c',
  'wyl-error.c',
)

libwyrelog = library('wyrelog',
  wyrelog_sources,
  include_directories : wyrelog_inc,
  dependencies : [glib_dep],
  install : true,
  soversion : '0',
)

install_headers(wyrelog_public_headers, subdir : 'wyrelog')

wyrelog_dep = declare_dependency(
  link_with : libwyrelog,
  include_directories : wyrelog_inc,
)
