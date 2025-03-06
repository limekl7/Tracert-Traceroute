# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.


import socket
import struct
import time
import sys
import os


ICMP_ECHO_REQUEST = 8
ICMP_TIME_EXCEEDED = 11
ICMP_ECHO_REPLY = 0

#контрольная сумма ICMP
def checksum(data):
    sum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + (data[i + 1] if i + 1 < len(data) else 0)
        sum = sum + word
        while sum >> 16:
            sum = (sum & 0xffff) + (sum >> 16)
    return ~sum & 0xffff

def create_icmp_packet(seq):
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, os.getpid() & 0xFFFF, seq)
    data = struct.pack("d", time.time()) + b'Hello, Traceroute!'
    my_checksum = checksum(header + data)
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), os.getpid() & 0xFFFF, seq)
    return header + data


#Разрешение IP -> в имя хоста
def resolve_hostname(ip, resolve_names):
    if resolve_names:
        try:
            return f"{socket.gethostbyaddr(ip)[0]} [{ip}]"
        except socket.herror:
            return ip
    return ip

def traceroute(destination, max_hops=30, probes_per_hop=3, resolve_names=True):
    try:
        dest_ip = socket.gethostbyname(destination)
        print(f"Traceroute to {destination} [{dest_ip}], max hops: {max_hops}")

        for ttl in range(1, max_hops + 1):
            sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            receiver = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

            sender.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            receiver.settimeout(2.0)
            receiver.bind(("", 0))

            times = []
            hop_addr = None
            reached_final = False #для последнего узла

            for probe in range(probes_per_hop):
                packet = create_icmp_packet(ttl * probes_per_hop + probe)
                start_time = time.time()

                sender.sendto(packet, (dest_ip, 1))

                try:
                    response, addr = receiver.recvfrom(1024)
                    elapsed = max((time.time() - start_time) * 1000, 1.0)
                    times.append(f"{elapsed:.2f} ms")
                    hop_addr = addr[0]

                    icmp_type = response[20]
                    if icmp_type == ICMP_ECHO_REPLY:
                        reached_final = True #ласт узел

                except socket.timeout:
                    times.append("*")

            sender.close()
            receiver.close()

            times_str = "  ".join(times)
            if hop_addr:
                hop_display = resolve_hostname(hop_addr, resolve_names)
                print(f"{ttl:2d}  {times_str}  {hop_display}")
            else:
                print(f"{ttl:2d}  {times_str}  Превышен интервал ожидания для запроса.")

            if reached_final:
                break

    except socket.gaierror:
        print("Не удалось разрешить имя хоста")
    except PermissionError:
        print("Требуются права администратора")
    except Exception as e:
        print(f"Ошибка: {e}")

def main():
    if len(sys.argv) < 2:
        print("Использование(ввести в консоль cmd с правами !администратора!): python название мэйна [-n] <host> Пример если главный файл main: python main.py 8.8.8.8")
        sys.exit(1)

    resolve_names = True
    destination = None

    if len(sys.argv) == 3 and sys.argv[1] == "-n":
        resolve_names = False
        destination = sys.argv[2]
    else:
        destination = sys.argv[1]

    traceroute(destination, resolve_names=resolve_names)

if __name__ == "__main__":
    main()

