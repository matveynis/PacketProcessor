cmake_minimum_required(VERSION 3.15)
project(PacketProcessor)

set(CMAKE_CXX_STANDARD 17)  

# Настройки для Windows
if(WIN32)
    set(PCAP_INCLUDE_DIR "C:/Program Files/Npcap/Include")
    set(PCAP_LIBRARY_DIR "C:/Program Files/Npcap/Lib/x64")  
    set(PCAP_LIBRARY wpcap)
    set(EXTRA_LIBS ws2_32)
else()
    # Настройки для Linux
    set(PCAP_INCLUDE_DIR "/usr/include")
    set(PCAP_LIBRARY "/usr/lib/x86_64-linux-gnu/libpcap.so") 
    set(EXTRA_LIBS "")
endif()

add_executable(PacketProcessor main.cpp PacketProcessor.cpp)
target_include_directories(PacketProcessor PRIVATE ${PCAP_INCLUDE_DIR})
target_link_directories(PacketProcessor PRIVATE ${PCAP_LIBRARY_DIR})
target_link_libraries(PacketProcessor ${PCAP_LIBRARY} ${EXTRA_LIBS})