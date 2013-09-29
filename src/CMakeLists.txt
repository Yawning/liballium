include_directories("${PROJECT_SOURCE_DIR}/include")

set(liballium_SRCS
	bstrlib.c
	allium_ptcfg.c
	allium_util.c
)

add_library(allium ${liballium_SRCS})

