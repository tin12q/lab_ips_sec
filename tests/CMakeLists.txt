add_executable(test_decoder test_decoder.cpp)

target_link_libraries(test_decoder
  PRIVATE
    minisnort_decoder
    Catch2::Catch2WithMain
)

add_executable(test_parser
  test_parser.cpp
  ../src/rules/parser.cpp
  ../src/rules/rule_store.cpp
  ../src/util/config.cpp
)

add_executable(test_matcher
  test_matcher.cpp
  ../src/detection/http_parser.cpp
  ../src/detection/matcher.cpp
)

add_executable(test_threshold
  test_threshold.cpp
  ../src/detection/threshold.cpp
)

add_executable(test_engine
  test_engine.cpp
  ../src/detection/engine.cpp
  ../src/detection/threshold.cpp
  ../src/detection/http_parser.cpp
  ../src/detection/matcher.cpp
  ../src/rules/rule_store.cpp
  ../src/flow/flow_table.cpp
  ../src/flow/tcp_state.cpp
)

add_executable(test_flow
  test_flow.cpp
  ../src/detection/engine.cpp
  ../src/detection/threshold.cpp
  ../src/detection/http_parser.cpp
  ../src/detection/matcher.cpp
  ../src/rules/rule_store.cpp
  ../src/flow/flow_table.cpp
  ../src/flow/tcp_state.cpp
)

add_executable(test_alert_fast
  test_alert_fast.cpp
  ../src/logger/alert_fast.cpp
)

target_include_directories(test_parser PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_include_directories(test_matcher PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_include_directories(test_threshold PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_include_directories(test_engine PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_include_directories(test_flow PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_include_directories(test_alert_fast PRIVATE ${CMAKE_SOURCE_DIR}/src)

target_link_libraries(test_parser
  PRIVATE
    Catch2::Catch2WithMain
)

target_link_libraries(test_matcher
  PRIVATE
    Catch2::Catch2WithMain
)

target_link_libraries(test_threshold
  PRIVATE
    Catch2::Catch2WithMain
)

target_link_libraries(test_engine
  PRIVATE
    Catch2::Catch2WithMain
)

target_link_libraries(test_flow
  PRIVATE
    Catch2::Catch2WithMain
)

target_link_libraries(test_alert_fast
  PRIVATE
    Catch2::Catch2WithMain
    spdlog::spdlog
)

include(CTest)
include(Catch)
catch_discover_tests(test_decoder)
catch_discover_tests(test_parser)
catch_discover_tests(test_matcher)
catch_discover_tests(test_threshold)
catch_discover_tests(test_engine)
catch_discover_tests(test_flow)
catch_discover_tests(test_alert_fast)
