import os
import random
import filecmp

os.system("make")
os.system("mkdir -p data")

while True:
    string = ""
    length = random.randrange(0, 1000)
    for i in range(length):
        string += chr(random.randrange(31, 127))
    #  print(length)

    #  print(f"Testing {string}");

    with open("./data/orig", "w") as f:
        f.write(string)

    #  if random.randrange(0, 2):
    os.system("sudo ./sender/sender -u 127.0.0.1 tedro.com data ./data/orig > /dev/null")

    #  else:
        #  os.system(f"bash -c 'sudo ./sender/sender -u 127.0.0.1 tedro.com data <<< \"{string}\" > /dev/null'")

    if os.system("diff ./data/orig ./data/data > /dev/null"):
        print(f"FAILED: <{string}>")
        exit(1)
    else:
        print("OK")

    #  with open("./data/data") as f:
        #  result = filecmp.cmp(string, f.read(), shallow=False)
        #  print(result)


