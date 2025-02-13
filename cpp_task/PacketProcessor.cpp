#include "PacketProcessor.h"

PacketProcessor::PacketProcessor() {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed." << std::endl;
        exit(1);
    }
#endif
}

PacketProcessor::~PacketProcessor() {
#ifdef _WIN32
    WSACleanup();
#endif
}

std::string PacketProcessor::getActiveInterface() {
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Ошибка поиска устройств: " << errbuf << std::endl;
        return "";
    }

    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        pcap_t* handle = pcap_open_live(d->name, 65536, 1, 1000, errbuf);
        if (!handle) continue;

        struct pcap_pkthdr* header;
        const u_char* packet;
        if (pcap_next_ex(handle, &header, &packet) > 0) {
            pcap_close(handle);
            std::string iface = d->name;
            pcap_freealldevs(alldevs);
            return iface;
        }
        pcap_close(handle);
    }

    pcap_freealldevs(alldevs);
    return "";
}

std::string PacketProcessor::ipToString(uint32_t ip) {
    char str[INET_ADDRSTRLEN];
    in_addr addr;
    addr.s_addr = ip;
    return inet_ntop(AF_INET, &addr, str, INET_ADDRSTRLEN) ? std::string(str) : "Invalid IP";
}

void PacketProcessor::processFromInterface(const std::string& iface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(iface.c_str(), 65536, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Ошибка открытия интерфейса: " << errbuf << std::endl;
        return;
    }
    processPacket(handle, false);
}

void PacketProcessor::processFromFile(const std::string& filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(filename.c_str(), errbuf);
    if (!handle) {
        std::cerr << "Ошибка открытия файла: " << errbuf << std::endl;
        return;
    }
    processPacket(handle, true);
}

void PacketProcessor::processPacket(pcap_t* handle, bool isFile) {
    auto start_time = std::chrono::steady_clock::now();
    pcap_pkthdr* header;
    const u_char* packet;
    int res;

    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0) {
            // Если захват в реальном времени и истёк таймаут, проверяем время работы
            if (!isFile && std::chrono::steady_clock::now() - start_time > std::chrono::seconds(5))
                break;
            continue; // Таймаут, никаких пакетов
        }
        
        // res == 1: пакет получен
        if (header->caplen < 14)
            continue;

        EthernetHeader* eth = (EthernetHeader*)packet;
        if (ntohs(eth->ether_type) != 0x0800)
            continue;

        IPHeader* iphdr = (IPHeader*)(packet + 14);
        if ((iphdr->ver_ihl >> 4) != 4)
            continue;

        uint16_t src_port = 0, dst_port = 0;
        if (iphdr->proto == IPPROTO_TCP) {
            TCPHeader* tcph = (TCPHeader*)(packet + 14 + ((iphdr->ver_ihl & 0xF) * 4));
            src_port = ntohs(tcph->sport);
            dst_port = ntohs(tcph->dport);
        } else if (iphdr->proto == IPPROTO_UDP) {
            UDPHeader* udph = (UDPHeader*)(packet + 14 + ((iphdr->ver_ihl & 0xF) * 4));
            src_port = ntohs(udph->sport);
            dst_port = ntohs(udph->dport);
        }

        FlowKey key{ iphdr->saddr, iphdr->daddr, src_port, dst_port };
        flows[key].packet_count++;
        flows[key].byte_count += ntohs(iphdr->tlen);

        // Для реального времени завершаем сбор после 5 секунд
        if (!isFile && std::chrono::steady_clock::now() - start_time > std::chrono::seconds(5))
            break;
    }

    // Если res == -2, значит достигнут конец файла (EOF), корректно завершаем цикл
    if (res == -2) {
        std::cout << "Достигнут конец файла." << std::endl;
    } else if (res == -1) {
        std::cerr << "Ошибка чтения пакета: " << pcap_geterr(handle) << std::endl;
    }

    saveToCSV();
    pcap_close(handle);
}


void PacketProcessor::saveToCSV() {
    std::ofstream csv("flows.csv");
    if (!csv) {
        std::cerr << "Ошибка создания файла CSV!" << std::endl;
        return;
    }

    for (const auto& entry : flows) {
        const FlowKey& key = entry.first;
        const FlowData& data = entry.second;
        csv << ipToString(key.src_ip) << ","
            << ipToString(key.dst_ip) << ","
            << key.src_port << ","
            << key.dst_port << ","
            << data.packet_count << ","
            << data.byte_count << "\n";
    }
}
