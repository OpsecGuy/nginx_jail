import re
import os
import sys
import time
import threading
from datetime import datetime

abuse_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*\[.*?:(\d{2}:\d{2}:\d{2})'
all_data = []
sorted_data = {}
jail = []

min_samples = 5
rs_limit = 10.0
ban_time = 1800.0

def detect_abuse():
    while True:

        print('Watching...')
        with open('/var/log/nginx/access.log', 'r') as fp:
            for id, line in enumerate(fp.readlines()):
                line = line.replace('\n', '')
                match = re.search(abuse_pattern, line)
                if match != None:
                    ip = match.group(1)
                    date = match.group(2)
                    all_data.append([ip, date])

        for sublist in all_data:
            key = sublist[0]
            value = sublist[1]
            if key in sorted_data:
                sorted_data[key].append(value)
            else:
                sorted_data[key] = [value]

        print('Getting samples...')
        for key, value in list(sorted_data.items()):
            if len(value) < min_samples:
                del sorted_data[key]

        print('Analyzing...')
        for key, value in list(sorted_data.items()):
            my_dates = [datetime.strptime(date_str, '%H:%M:%S') for date_str in value]
            highest_date = max(my_dates).strftime('%H:%M:%S')
            lowest_date = min(my_dates).strftime('%H:%M:%S')
            
            time_difference = (datetime.strptime(highest_date, '%H:%M:%S') - datetime.strptime(lowest_date, '%H:%M:%S')).total_seconds()
            if time_difference < 1.0:
                time_difference = 1.0

            # print(f'[{len(value)}] {key} | {lowest_date} - {highest_date} delta={time_difference} | r/s: {len(value)/time_difference}')

            if len(value) / time_difference >= rs_limit:
                if key not in jail:
                    print(f'[{len(value)}] {key} | delta={time_difference}s | r/s: {len(value)/time_difference:.4}  ==>  JAIL ROOM')
                jail.append(key)

        block_ip(jail)
        print('Cleaning buffers...')
        all_data.clear()
        sorted_data.clear()
        time.sleep(5)


def block_ip(jail_list):
    with open('blocked_ips.conf', 'w+') as f:
        f.flush()
        for ip in jail_list:
            f.write(f'deny {ip};\n')
    os.system('service nginx reload')

def clean_access_log():
    while True:
        print('Cleaning access.log file and jail room...')
        jail.clear()
        os.system('sudo truncate --size 0 /var/log/nginx/access.log')
        time.sleep(ban_time)

def main():
    threading.Thread(target=clean_access_log).start()
    time.sleep(2)
    threading.Thread(target=detect_abuse).start()

if __name__ == '__main__':
    if sys.platform == 'linux':
        print('Starting app...')
        main()
    else:
        print('You can run script only on Linux OS! Exiting...')
        os._exit(0)