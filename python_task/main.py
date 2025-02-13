import os
import csv
from collections import defaultdict


def find_flows_csv(root_folder):
    for root, _, files in os.walk(root_folder):
        for file in files:
            if file == "flows.csv":
                return os.path.join(root, file)
    return None


def process_flows_csv(input_file, output_file):
    ip_stats = defaultdict(lambda: {'received_packets': 0, 'received_bytes': 0,
                                    'sent_packets': 0, 'sent_bytes': 0})

    with open(input_file, 'r') as infile:
        reader = csv.reader(infile)
        for row in reader:
            src_ip, dst_ip, src_port, dst_port, packets, bytes_ = row
            packets = int(packets)
            bytes_ = int(bytes_)

            # Учет статистики
            ip_stats[dst_ip]['received_packets'] += packets
            ip_stats[dst_ip]['received_bytes'] += bytes_
            ip_stats[src_ip]['sent_packets'] += packets
            ip_stats[src_ip]['sent_bytes'] += bytes_

    # Запись результата в новый CSV файл
    with open(output_file, 'w', newline='') as outfile:
        writer = csv.writer(outfile)
        for ip, stats in ip_stats.items():
            writer.writerow([
                ip,
                stats['received_packets'],
                stats['received_bytes'],
                stats['sent_packets'],
                stats['sent_bytes']
            ])


def main():
    # Путь к папке cpp_task
    script_dir = os.path.dirname(os.path.abspath(__file__))  # Папка с main.py
    cpp_task_folder = os.path.join(script_dir, '..', 'cpp_task')  # cpp_task на уровне выше python_task

    # Поиск файла flows.csv
    flows_csv = find_flows_csv(cpp_task_folder)
    if not flows_csv:
        print("Файл flows.csv не найден в папке cpp_task и ее поддиректориях.")
        return

    print(f"Файл flows.csv найден: {flows_csv}")

    # Путь для сохранения результата в папке python_task
    output_file = os.path.join(script_dir, 'ip_statistics.csv')

    # Обработка файла
    process_flows_csv(flows_csv, output_file)
    print(f"Результат сохранен в: {output_file}")


if __name__ == "__main__":
    main()
