import re
from collections import defaultdict

# checks for any suspicious IP's
def check_ip(line, ip_dict, ip_user):
    match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line)
    if not match:
        return
    ip = match.group(0)
    def_ip_of_user(line, ip, ip_user)
    if any(keyword in line.lower() for keyword in ["fail", "unauthorized", "denied"]):
        ip_dict[ip] = ip_dict.get(ip, 0) + 1

# initalizing the ip and user dictionary
def def_ip_of_user(line, ip, ip_user):
    match = re.search(r"User\s+(\w+)", line)
    if not match:
        return
    user = match.group(1)
    ip_user[user].append(ip)

# checks for any suspicious usernames
def check_user(line, user_dict):
    match = re.search(r"User\s+(\w+)", line)
    if not match:
        return
    user = match.group(1)
    if any(keyword in line.lower() for keyword in ["attempted", "failed", "invalid"]):
        user_dict[user] = user_dict.get(user, 0) + 1

# check for any suspicious lines
def check_sus(line, warningLines, keyword, count):
    if line not in warningLines and keyword in line.upper():
        warningLines.append(line)
        count += 1
    return count

def log_analyzer() -> None: 
# initalizing varaiables
    date = ""
    time = ""
    count = 0


    filename = "sample_logs/"+ input("What is FileName: ")
    # Ask if you have a specific time and date
    response = input("Do you have a specific time and date to check? ").upper()
    if response in ("YES", "Y"):
        # too specify date filtering
        date = input("What date in format: YR(XXXX)-MTH(XX)-DAY(XX)\n") 
        # to specify time filtering
        time = input("What time in format: XX:XX:XX\n")

    # create a severity log style for filtering
    log_levels = {
            'DEBUG' : ["DEBUG", "TRACE", "VERBOSE"],
            'INFO' : ["INFO", "SUCCESS", "OK", 'STARTED', 'STOPPED', 'CONNECTED'],
            'WARNING' : ['WARNING', 'WARN', 'DEPRECATED', 'SLOW', 'TIMEOUT', 'RETRY'],
            'ERROR' : ['ERROR', 'FAILED', 'INVALID', 'DENIED', 'REFUSED', 'MISSING'],
            'CRITICAL' : ['CRITICAL', 'FATAL', 'EMERGENCY', 'CORRUPT', 'CRASH', 'PANIC'],
            'SECURITY_SPECIFIC' : ['UNAUTHORIZED', 'LOCKED', 'ANONYMOUS', 'BREACH', 'INTRUSION', 'BLOCKED', 'EXPLOIT']
        }
    while True:
        level = input("Enter log level to filter (DEBUG, INFO, WARNING, ERROR, CRITICAL, or SECURITY_SPECIFIC): ").upper()
        if level in log_levels:
            break
        else:
            print("Not a severity level")

    # keywords and each line of suspicious activity instantiated
    keywords = log_levels[level]
    warningLines = []

    # dictionary initalization
    ip_dict = dict()
    user_dict = dict()
    ip_user = defaultdict(list)
    try:
        with open(filename, 'r') as file:
            # if there is a date and time
            if date and time:
                for line in file:
                    # checking the lines that are only have the filter of date and time
                    if date in line and time in line:
                        for keyword in keywords:
                            count = check_sus(line, warningLines, keyword, count)
                        check_ip(line, ip_dict, ip_user)
                        check_user(line, user_dict)
            # if there is no provided date or time
            elif not date and not time:
                for line in file:
                    for keyword in keywords:
                        count = check_sus(line, warningLines, keyword, count)
                    check_ip(line, ip_dict, ip_user)
                    check_user(line, user_dict)
            file.close()
    except FileNotFoundError:
        print("File not Found")

    temp_count = count
    # write all the given lines to the text file
    filename = filename.rsplit(".", 1)[0]
    try:
        with open(f"{filename}.txt", 'w') as file:
            for line in warningLines: 
                file.write(line)
            file.write("=" * 41 + "\n")
            file.write((" "*16) + "SUMMARY" + "\n")
            file.write("=" * 41+ "\n")
            for ip, counts in ip_dict.items():
                if counts >= 5:
                    file.write(f"{ip}: {counts}\n")
                    temp_count += counts
            for user, counts in user_dict.items():
                if counts >= 5:
                    file.write(f"{user}: {counts}\n")
                    temp_count += counts
            for user, ip in ip_user.items():
                file.write(f'{user}: {ip}\n')
            file.write(f"Total suspicious Count: {temp_count}\n")
            if temp_count == 0:
                file.write("No Suspicious Activity")
            file.close()
    except FileNotFoundError:
        print("File not Found")

if __name__ == "__main__":
    log_analyzer()