## our modules are without the "lib" prefix

MACRO(ADD_AND_INSTALL_LIBRARY LIBNAME SRCFILES)
  IF(BUILD_STATIC)
    ADD_LIBRARY(${LIBNAME} STATIC ${SRCFILES})
    TARGET_LINK_LIBRARIES(lighttpd ${LIBNAME})
  ELSE(BUILD_STATIC)
    ADD_LIBRARY(${LIBNAME} SHARED ${SRCFILES})
    SET(L_INSTALL_TARGETS ${L_INSTALL_TARGETS} ${LIBNAME})
    ## Windows likes to link it this way back to app!
    IF(WIN32)
        SET_TARGET_PROPERTIES(${LIBNAME} PROPERTIES LINK_FLAGS lighttpd.lib)
    ENDIF(WIN32)

    IF(APPLE)
        SET_TARGET_PROPERTIES(${LIBNAME} PROPERTIES LINK_FLAGS "-flat_namespace -undefined suppress")
    ENDIF(APPLE)
  ENDIF(BUILD_STATIC)
ENDMACRO(ADD_AND_INSTALL_LIBRARY)

MACRO(LEMON_PARSER SRCFILE)
  GET_FILENAME_COMPONENT(SRCBASE ${SRCFILE} NAME_WE)
  ADD_CUSTOM_COMMAND(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${SRCBASE}.c ${CMAKE_CURRENT_BINARY_DIR}/${SRCBASE}.h
  COMMAND ${CMAKE_BINARY_DIR}/build/lemon
  ARGS -q ${CMAKE_CURRENT_SOURCE_DIR}/${SRCFILE} ${CMAKE_SOURCE_DIR}/src/lempar.c
    DEPENDS ${CMAKE_BINARY_DIR}/build/lemon ${CMAKE_CURRENT_SOURCE_DIR}/${SRCFILE} ${CMAKE_SOURCE_DIR}/src/lempar.c
  COMMENT "Generating ${SRCBASE}.c from ${SRCFILE}"
)
ENDMACRO(LEMON_PARSER)

MACRO(ADD_TARGET_PROPERTIES _target _name)
  SET(_properties)
  FOREACH(_prop ${ARGN})
    SET(_properties "${_properties} ${_prop}")
  ENDFOREACH(_prop)
  GET_TARGET_PROPERTY(_old_properties ${_target} ${_name})
  MESSAGE("adding property to ${_target} ${_name}:" ${_properties})
  IF(NOT _old_properties)
    # in case it's NOTFOUND
    SET(_old_properties)
  ENDIF(NOT _old_properties)
  SET_TARGET_PROPERTIES(${_target} PROPERTIES ${_name} "${_old_properties} ${_properties}")
ENDMACRO(ADD_TARGET_PROPERTIES)
