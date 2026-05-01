test_smoke = executable('test-smoke',
  'test-smoke.c',
  dependencies : [wyrelog_dep],
)

test('smoke', test_smoke)

test_boot_smoke = executable('test-boot-smoke',
  'test-boot-smoke.c',
  dependencies : [wyrelog_dep],
)

test('boot-smoke', test_boot_smoke)

test_client_smoke = executable('test-client-smoke',
  'test-client-smoke.c',
  dependencies : [wyrelog_client_dep],
)

test('client-smoke', test_client_smoke)
