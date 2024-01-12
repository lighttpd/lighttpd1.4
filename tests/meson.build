compiler = meson.get_compiler('c')
socket_libs = []
if target_machine.system() == 'windows'
	socket_libs = [ compiler.find_library('ws2_32') ]
endif
if target_machine.system() == 'sunos'
	socket_libs = [ compiler.find_library('socket')
	              , compiler.find_library('nsl')
	              ]
elif target_machine.system() == 'haiku'
	socket_libs = [ compiler.find_library('network') ]
endif

executable('fcgi-responder',
	sources: 'fcgi-responder.c',
	dependencies: [ common_flags, socket_libs ]
)

executable('scgi-responder',
	sources: 'scgi-responder.c',
	dependencies: [ common_flags, socket_libs ]
)

# tests/* do not run under native Windows; not written for Windows paths
if target_machine.system() != 'windows'

env = environment()
env.set('srcdir', meson.current_source_dir())
env.set('top_builddir', meson.current_build_dir() + '/..')

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

endif # (target_machine.system() != 'windows')
