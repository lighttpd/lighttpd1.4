executable('fcgi-responder',
	sources: 'fcgi-responder.c',
	dependencies: common_flags,
)

executable('scgi-responder',
	sources: 'scgi-responder.c',
	dependencies: common_flags,
)

env = environment()
env.set('srcdir', meson.current_source_dir())
env.set('top_builddir', meson.build_root())

tests = [
	'request.t',
	'core-condition.t',
	'mod-fastcgi.t',
	'mod-scgi.t',
]

# just hope it will run the tests in the given order
test('prepare', find_program('./prepare.sh'), env: env, is_parallel: false)
foreach t: tests
	test(t, find_program('./' + t), env: env, is_parallel: false)
endforeach
test('cleanup', find_program('./cleanup.sh'), env: env, is_parallel: false)
