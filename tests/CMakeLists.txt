add_executable(test_decoder test_decoder.cpp)

target_link_libraries(test_decoder
  PRIVATE
    minisnort_decoder
    Catch2::Catch2WithMain
)

include(CTest)
include(Catch)
catch_discover_tests(test_decoder)
