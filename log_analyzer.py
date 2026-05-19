filename = input("What is FileName: ")

keywords = ['ERROR', 'FAILED', 'INVALID', 'LOCKED', 'UNAUTHROIZED', 'ANONYMOUS']

with open(filename, 'r') as file:
    for line in file:
        for keyword in keywords:
            # improvement needed, what if a line contains multiple keywords
            # it will print the same line multiple times
            # we should keep track of all lines that are already listed as suspicous
            # then create a verify for if that line is already checked
            if keyword in line.upper():
                print(line)
