cmake_minimum_required(VERSION 3.7.0 FATAL_ERROR)

project(lighttpd VERSION 1.4.75 LANGUAGES C)

# use C11 with CMake >= 3.1
set(CMAKE_C_STANDARD 11)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/scripts/cmake)

include(CTest)

enable_testing()

set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/COPYING")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README")
set(CPACK_PACKAGE_VENDOR "jan@kneschke.de")

set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_IGNORE_FILES "/\\\\.;~$;/_;build/;CMakeFiles/;CMakeCache;gz$;Makefile\\\\.;trace;Testing/;foo;autom4te;cmake_install;CPack;\\\\.pem;ltmain.sh;configure;libtool;/config\\\\.;missing;autogen.sh;install-sh;Dart;aclocal;log$;Makefile$")

include(CPack)

include(GNUInstallDirs)

add_subdirectory(src build)
add_subdirectory(doc)
add_subdirectory(tests)
