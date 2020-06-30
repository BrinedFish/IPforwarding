cmake_minimum_required(VERSION 3.16)
project(ipforwarding)

set(CMAKE_CXX_STANDARD 14)

add_executable(ipforwarding main.cpp ForwardingTable.h ForwardingTable.cpp PacketQueue.h PacketQueue.cpp HeaderAnalysis.h PortIn.cpp PortIn.h PortOut.cpp PortOut.h)
target_link_libraries(ipforwarding pcap)