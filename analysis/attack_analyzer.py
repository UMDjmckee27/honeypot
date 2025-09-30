from analysis.map import create_map
from utils.ip_utils import lookup_ip
from utils.file_utils import dump_json, dump_text
from utils.constants import *

from collections import defaultdict
from operator import itemgetter
import pandas as pd
import re


def parse_attacks_data(attacks_data):
    command_frequency = defaultdict(int) 
    download_commands_data = set()

    attacks_per_ip = {ip: 0 for ip in PORT_TO_IP.values()}
    attacks_per_config = {config: 0 for config in CONFIGS}
    attacks_per_client_id = defaultdict(int)
    attacks_per_source_ip = defaultdict(int)

    download_commands = ["wget", "curl", "scp", "rsync", "ftp", "tftp", "sftp"]

    for _, attack_data in attacks_data.items():
        destination_ip = attack_data.get("Destination_IP")
        config = attack_data.get("Configuration")
        client_id = attack_data.get("Client_ID")
        source_ip = attack_data.get("Source_IP")
        commands = attack_data.get("Commands")

        attacks_per_ip[destination_ip] += 1
        attacks_per_config[config] += 1
        attacks_per_client_id[client_id] += 1
        attacks_per_source_ip[source_ip] += 1
        for command in commands:
            command_frequency[command] += 1

            split_command = command.split(" ")
            if len(split_command) > 1 and (split_command[0] in download_commands or split_command[1] in download_commands):
                download_commands_data.add(command)

    command_frequency = dict(sorted(command_frequency.items(), key=lambda item: item[1], reverse=True))

    download_commands_data, urls = prioritize_ip_lines(download_commands_data)

    dump_json(command_frequency, COMMAND_FREQUENCY_JSON)
    dump_text(download_commands_data, DOWNLOAD_COMMANDS_TXT)
    dump_text(urls, URLS_TXT)

    with pd.ExcelWriter(ATTACK_REPORT_XLSX) as writer:
        count_attacks_per_IP(attacks_per_ip, writer)
        count_attacks_per_config(attacks_per_config, writer)
        count_client_ids(attacks_per_client_id, writer)
        count_attacks_per_source_ip(attacks_per_source_ip, writer)

def prioritize_ip_lines(command_list):
    ip_pattern = r'\b\d+\.\d+\.\d+\.\d+\b' 
    url_pattern = re.compile(r'(https?://[^\s]+)')
    
    ip_lines = []
    non_ip_lines = []
    urls = set()
    
    for line in command_list:
        if re.search(ip_pattern, line):
            ip_lines.append(line)  
        else:
            non_ip_lines.append(line)  

        urls_found = url_pattern.findall(line)
        for url in urls_found:
            urls.add(url)
    
    return ip_lines + non_ip_lines, urls

def count_attacks_per_IP(attacks_per_ip, writer):
    total = sum(attacks_per_ip.values())
    table = [[ip, count] for ip, count in attacks_per_ip.items()]
    table.append(["Total", total])

    df = pd.DataFrame(table, columns=["IP Address", "Attacks"])
    df.to_excel(writer, sheet_name="Attacks per IP", index=False)

def count_attacks_per_config(attacks_per_config, writer):
    table = [[config, count] for config, count in attacks_per_config.items()]
    df = pd.DataFrame(table, columns=["Config", "Attacks"])
    df.to_excel(writer, sheet_name="Attacks per Config", index=False)

def count_client_ids(attacks_per_client_id, writer):
    sorted_client_ids = sorted(attacks_per_client_id.items(), key=itemgetter(1), reverse=True)
    df = pd.DataFrame(sorted_client_ids, columns=["Client ID", "Attacks"])
    df.to_excel(writer, sheet_name="Attacks per Client ID", index=False)

def count_attacks_per_source_ip(source_ip_counts, writer):
    sorted_ips = sorted(source_ip_counts.items(), key=itemgetter(1), reverse=True)

    data = []
    for ip, count in sorted_ips:
        ip_info = lookup_ip(ip)
        data.append([ip, count, ip_info.get("City"), ip_info.get("Country"), ip_info.get("Latitude"), ip_info.get("Longitude")])

    create_map(data)

    top_1 = len(source_ip_counts) // 100

    top_1_percent = pd.DataFrame(data[:top_1], columns=["IP", "frequency", "city", "country", "lat", "long"])    
    top_1_percent[['IP', 'frequency', 'city', 'lat', 'long']].to_excel(writer, sheet_name=r"Top 1% Source IPs", index=False)

    total_attacks_top_20 = top_1_percent['frequency'].sum()
    summary_df = pd.DataFrame([[r"Total attacks from top 1% source IPs", total_attacks_top_20]], columns=["Description", "Count"])
    summary_df.to_excel(writer, sheet_name=r"Top 1% Source IPs", startrow=len(top_1_percent) + 2, index=False)
