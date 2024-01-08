add_executable(fcgi-responder fcgi-responder.c)
add_executable(scgi-responder scgi-responder.c)
if(WIN32)
  set(SOCKLIBS ws2_32)
endif()
if(CMAKE_SYSTEM_NAME MATCHES "SunOS")
  set(SOCKLIBS socket nsl)
elseif(CMAKE_SYSTEM_NAME MATCHES "Haiku")
  set(SOCKLIBS network)
endif()
if(SOCKLIBS)
  target_link_libraries(fcgi-responder ${SOCKLIBS})
  target_link_libraries(scgi-responder ${SOCKLIBS})
endif()

# tests/* do not run under native Windows; not written for Windows paths
if(NOT WIN32)

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

endif() # (NOT WIN32)
