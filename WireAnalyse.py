#!/usr/bin/env python3
#-*- coding:utf-8 -*-
#author:九思
#github:https://github.com/secsi1/WireAnalyse

import pyshark
import hashlib
import time
print(" ")
print(" / / /\ \ (_)_ __ ___  /_\  _ __   __ _| |_   _ ___  ___  ")
print(" \ \/  \/ / | '__/ _ \//_\\| '_ \ / _` | | | | / __|/ _ \ ")
print("  \  /\  /| | | |  __/  _  \ | | | (_| | | |_| \__ \  __/ ")
print("   \/  \/ |_|_|  \___\_/ \_/_| |_|\__,_|_|\__, |___/\___| ")
print("                                         |___/            ")

def analyze_traffic(pcap_file):
    capture = pyshark.FileCapture(pcap_file)

    analysis_results = []

    for packet in capture:
        try:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            hostname = packet.sniff_timestamp

            operations = packet.layers

            result = (src_ip, dst_ip, hostname, operations)
            analysis_results.append(result)

        except AttributeError:
            pass

    capture.close()

    current_time = str(time.time()).encode()
    md5_hash = hashlib.md5(current_time).hexdigest()
    filename = f"{md5_hash}.txt"

    with open(filename, 'w') as file:
        for result in analysis_results:
            file.write(f"Source IP: {result[0]}\n")
            file.write(f"Destination IP: {result[1]}\n")
            file.write(f"Hostname: {result[2]}\n")
            file.write(f"Operations: {result[3]}\n")
            file.write("\n")

    print(f"Analysis results saved to {filename}")

pcap_file = input("Please provide the path to the PCAP file: ")

analyze_traffic(pcap_file)
