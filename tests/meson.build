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
	'cachable.t',
	'core-404-handler.t',
	'core-condition.t',
	'core-keepalive.t',
	'core-request.t',
	'core-response.t',
	'core-var-include.t',
	'lowercase.t',
	'mod-auth.t',
	'mod-cgi.t',
	'mod-deflate.t',
	'mod-extforward.t',
	'mod-fastcgi.t',
	'mod-proxy.t',
	'mod-secdownload.t',
	'mod-setenv.t',
	'mod-ssi.t',
	'request.t',
	'symlink.t',
]

# just hope it will run the tests in the given order
test('prepare', find_program('./prepare.sh'), env: env, is_parallel: false)
foreach t: tests
	test(t, find_program('./' + t), env: env, is_parallel: false)
endforeach
test('cleanup', find_program('./cleanup.sh'), env: env, is_parallel: false)
