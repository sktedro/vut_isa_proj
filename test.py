import os
import random

os.system("make")
os.system("mkdir -p data")

counter = 0

while True:
    string = ""
    length = random.choice(
            [random.randrange(0, 100), 
                random.randrange(0, 1000), 
                #  random.randrange(0, 1000000)
                ])

    for i in range(length):
        string += chr(random.randrange(0, 256))

    #  print(f"Testing {string}");

    with open("./data/orig", "w") as f:
        f.write(string)

    os.system("./sender/sender -u 127.0.0.1 tedro.com data ./data/orig > /dev/null 2>&1")

    if os.system("diff ./data/orig ./data/data > /dev/null"):
        print()
        print(f"FAILED! Check ./data/orig")
        exit(1)
    else:
        counter += 1
        print(f"OK: {counter}", end="\r")
