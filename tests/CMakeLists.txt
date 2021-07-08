add_executable(fcgi-responder fcgi-responder.c)
add_executable(scgi-responder scgi-responder.c)

set(T_FILES
	prepare.sh
	request.t
	core-condition.t
	mod-fastcgi.t
	mod-scgi.t
	cleanup.sh
)

foreach(it ${T_FILES})
	add_test(NAME ${it} COMMAND "${lighttpd_SOURCE_DIR}/tests/wrapper.sh"
		"${lighttpd_SOURCE_DIR}/tests"
		"${lighttpd_BINARY_DIR}"
		"${lighttpd_SOURCE_DIR}/tests/${it}")
endforeach()
