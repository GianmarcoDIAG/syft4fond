add_subdirectory(parser)
add_subdirectory(synthesis)

include_directories(${PARSER_INCLUDE_PATH} ${SYNTHESIS_INCLUDE_PATH} ${EXT_INCLUDE_PATH})
add_executable(syft4fond syft4fond.cpp)
add_executable(pddl2dfa pddl2dfa.cpp)

target_link_libraries(syft4fond ${PARSER_LIB_NAME} ${SYNTHESIS_LIB_NAME})
target_link_libraries(pddl2dfa ${PARSER_LIB_NAME} ${SYNTHESIS_LIB_NAME})

INSTALL (
  DIRECTORY ${CMAKE_SOURCE_DIR}/src/
    DESTINATION include
    FILES_MATCHING PATTERN "*.h*")
