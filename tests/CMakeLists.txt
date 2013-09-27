include_directories("${PROJECT_SOURCE_DIR}/include")
link_directories("${liballium_BINARY_DIR}/src")

add_executable(ptcfg_test ptcfg_test.c)
target_link_libraries(ptcfg_test allium)

