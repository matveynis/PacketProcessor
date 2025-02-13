#ifndef PACKETPROCESSOR_H
#define PACKETPROCESSOR_H

#include <iostream>
#include <string>
#include <unordered_map>
#include <fstream>
#include <chrono>
#include <pcap.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#endif

struct EthernetHeader {
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t ether_type;
};

struct IPHeader {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t tlen;
    uint16_t id;
    uint16_t flags_fo;
    uint8_t ttl;
    uint8_t proto;
    uint16_t crc;
    uint32_t saddr;
    uint32_t daddr;
};

struct TCPHeader {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t offset_res;
    uint8_t flags;
    uint16_t win;
    uint16_t crc;
    uint16_t urg_ptr;
};

struct UDPHeader {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t crc;
};

struct FlowKey {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    // Оператор равенства для использования FlowKey в unordered_map
    bool operator==(const FlowKey& other) const {
        return src_ip == other.src_ip && dst_ip == other.dst_ip &&
               src_port == other.src_port && dst_port == other.dst_port;
    }
};

// Хэш-функция для FlowKey
struct FlowKeyHash {
    std::size_t operator()(const FlowKey& key) const {
        return std::hash<uint32_t>()(key.src_ip) ^
               std::hash<uint32_t>()(key.dst_ip) ^
               std::hash<uint16_t>()(key.src_port) ^
               std::hash<uint16_t>()(key.dst_port);
    }
};

struct FlowData {
    uint64_t packet_count = 0;
    uint64_t byte_count = 0;
};

class PacketProcessor {
public:
    PacketProcessor();
    ~PacketProcessor();
    std::string getActiveInterface();
    void processFromInterface(const std::string& iface); // Переименован параметр
    void processFromFile(const std::string& filename);

private:
    std::unordered_map<FlowKey, FlowData, FlowKeyHash> flows;

    std::string ipToString(uint32_t ip);
    void processPacket(pcap_t* handle, bool isFile);
    void saveToCSV();
};

#endif // PACKETPROCESSOR_H
