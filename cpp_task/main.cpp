#include "PacketProcessor.h"
#include <cstring>

int main(int argc, char* argv[]) {
    PacketProcessor processor;

    if (argc == 1) { // Запуск без аргументов
        std::string iface = processor.getActiveInterface();
        if (!iface.empty()) 
            processor.processFromInterface(iface);
    } 
    else if (argc == 2) { // Обработка файла или интерфейса
        std::string arg(argv[1]);
        if (arg.size() > 5 && arg.substr(arg.size() - 5) == ".pcap") {
            processor.processFromFile(arg);
        } else {
            processor.processFromInterface(arg);
        }
    } 
    else { // Некорректные аргументы
        std::cerr << "Использование:\n"
                  << "  PacketProcessor [файл.pcap|интерфейс]\n"
                  << "  PacketProcessor (для автоинтерфейса)\n";
        return 1;
    }

    return 0;
}
