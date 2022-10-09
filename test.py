import os
import random

os.system("make")
os.system("mkdir -p data")

counter = 0

while True:
    string = ""
    length = random.randrange(0, 1000)
    for i in range(length):
        string += chr(random.randrange(0, 256))

    #  print(f"Testing {string}");

    with open("./data/orig", "w") as f:
        f.write(string)

    os.system("sudo ./sender/sender -u 127.0.0.1 tedro.com data ./data/orig > /dev/null")

    if os.system("diff ./data/orig ./data/data > /dev/null"):
        print()
        print(f"FAILED: <{string}>")
        exit(1)
    else:
        counter += 1
        print(f"OK: {counter}", end="\r")
