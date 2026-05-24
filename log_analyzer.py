import re

# checks for any suspicous IP's
def check_ip(line, ip_dict):
    match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line)
    if not match:
        return
    
    ip = match.group(0)

    if any(keyword in line.lower() for keyword in ["fail", "unauthorized", "denied"]):
        ip_dict[ip] = ip_dict.get(ip, 0) + 1

# checks for any suspicous usernames
def check_user(line, user_dict):
    match = re.search(r"User\s+(\w+)", line)
    if not match:
        return
    
    user = match.group(0)

    if any(keyword in line.lower() for keyword in ["attempted", "failed", "invalid"]):
        user_dict[user] = user_dict.get(user, 0) + 1

# check for any suspicous lines
def check_sus(line, warningLines, keyword, count):
    if line not in warningLines and keyword in line:
        warningLines.append(line)
        count += 1
    return count

def log_analyzer() -> None: 
# instantiating varaiables
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

    # keywords and each line of suspicous activity instantiated
    keywords = log_levels[level]
    warningLines = []

    # dictionary initalization
    ip_dict = dict()
    user_dict = dict()
    ip_user = dict()
    with open(filename, 'r') as file:
        # if there is a date and time
        if date and time:
            for line in file:
                # checking the lines that are only have the filter of date and time
                if date in line and time in line:
                    for keyword in keywords:
                        count = check_sus(line, warningLines, keyword, count)
                    check_ip(line, ip_dict)
                    check_user(line, user_dict)
        # if there is no provided date or time
        else:
            for line in file:
                for keyword in keywords:
                    count = check_sus(line, warningLines, keyword, count)
                check_ip(line, ip_dict)
                check_user(line, user_dict)


    # write all the given lines to the text file
    filename = filename.rsplit(".", 1)[0]
    with open(f"{filename}.txt", 'w') as file:
        for line in warningLines: 
            file.write(line)
        file.write(f"Total suspicious Count: {count}\n")
        for ip, counts in ip_dict.items():
            if counts >= 5:
                file.write(f"{ip}: {counts}\n")
        for user, counts in user_dict.items():
            if counts >= 5:
                file.write(f"{user}: {counts}\n")