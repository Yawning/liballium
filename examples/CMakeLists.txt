include_directories("${PROJECT_SOURCE_DIR}/include")
link_directories("${liballium_BINARY_DIR}/src")

add_executable(ptcfg_example ptcfg_example.c)
target_link_libraries(ptcfg_example allium)

