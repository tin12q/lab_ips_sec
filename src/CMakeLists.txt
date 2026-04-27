add_library(minisnort_decoder
  decoder/decoder.cpp
  decoder/ethernet.cpp
  decoder/ipv4.cpp
  decoder/tcp.cpp
  decoder/udp.cpp
  decoder/icmp.cpp
)

target_include_directories(minisnort_decoder PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(minisnort_decoder
  PUBLIC
    nlohmann_json::nlohmann_json
)

if(TARGET spdlog::spdlog)
  target_link_libraries(minisnort_decoder PUBLIC spdlog::spdlog)
  target_compile_definitions(minisnort_decoder PUBLIC MINISNORT_HAS_SPDLOG=1)
endif()

add_executable(minisnort
  main.cpp
  daq/pcap_daq.cpp
  daq/nfq_daq.cpp
  detection/engine.cpp
  detection/threshold.cpp
  detection/http_parser.cpp
  detection/matcher.cpp
  flow/flow_table.cpp
  flow/tcp_state.cpp
  rules/parser.cpp
  rules/rule_store.cpp
  util/config.cpp
  logger/alert_fast.cpp
)

target_include_directories(minisnort PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(minisnort
  PRIVATE
    minisnort_decoder
    pcap
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_link_libraries(minisnort PRIVATE netfilter_queue)
endif()
