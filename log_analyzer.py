filename = input("What is FileName: ")
# Ask if you have a specific time and date
if(input("Do you have a specific time and date to check")):
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
keywords = log_levels[level]
warningLines = ""

with open(filename, 'r') as file:
    # if there is a date and time
    if date and time:
        for line in file:
            # checking the lines that are only have the filter of date and time
            if (date and time) in line:
                for keyword in keywords:
                    warningLines.add(line)
    # if there is no provided date or time
    else:
        for line in file:
            for keyword in keywords:
                warningLines.add(line)
        
        

# write all the given lines to the text file
with open('error.txt', 'w'):
    pass