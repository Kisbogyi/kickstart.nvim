import subprocess
import platform 
from enum import Enum
import time

cnt = 0
passed = 0
green = '\033[92m'
red = '\033[91m'
yellow = '\033[93m'
white = '\033[0m'
os = platform.platform()

class OS(Enum):
    MAC = 1
    WINDOWS = 2
    

if "macOS" in os:
    os = OS.MAC    
else:
    os = OS.WINDOWS

cnt = 0
passed = 0
green = '\033[92m'
red = '\033[91m'
yellow = '\033[93m'
white = '\033[0m'

# Define tests with @test decorator
# If it returns true it passed
# If it returns false it failed

def Test(func):
    def wrapper(command):
        global cnt
        cnt += 1
        global passed
        global green
        global red
        global yellow
        global white
        green = '\033[92m'
        red = '\033[91m'
        yellow = '\033[93m'
        white = '\033[0m'
        print(f"Test {cnt}")
        print(f"Testing: {func.__name__}")
        try:
            if func(command):
                print(f"{green}Test passed{white}")
                passed += 1
            else:
                print(f"{red}Test failed{white}")
        except:
            print(f"{yellow}Test failed with exception{white}")
    return wrapper


@Test
def run_command(command):
    try:
        subprocess.run(command, shell=True, check = True, timeout=1)
        time.sleep(1)
        return True
    except subprocess.TimeoutExpired:
        return True
    except:
        return False

@Test
def run_atomic(name):
    try:
        preqs = f"Invoke-AtomicTest {name} - GetPrereqs"
        command = f"Invoke-AtomicTest {name}"
        subprocess.run(preqs, shell=True, check = True)
        subprocess.run(command, shell=True, check = True)
        return True
    except:
        return False

def msfvenom_tests(filename):
    with open(filename, "r") as fin:
        for line in fin:
            line = line.strip()
            run_command(f"echo test; {line}")

def mac_tests():
    print("start msfvenom tests")
    msfvenom_tests("out_unix")
    
    print("start atomic tests")
    test_names = [
        "T1053.003-1",
        "T1053.003-2",
        "T1053.007-1",
        "T1053.007-2",
        "T1059.002-1",
        "T1059.004-1",
        "T1059.004-2",
        "T1059.004-14",
        "T1059.004-15",
        "T1059.004-17",
        "T1569.001-1",
    ]
    for name in test_names:
        run_atomic(name)
        

def windows_tests():
    print("start msfvenom tests")
    msfvenom_tests("test.txt")


    print("start atomic tests")
    test_names = [
    ]
    for name in test_names:
        run_atomic(name)

if os is not OS.MAC:
    pass
   #mac_tests() 

if os is not OS.MAC:
    windows_tests()
    

print("\n--------------")
if passed == cnt:
    print(green, end="")
else:
    print(red, end="")
print(f"Passed {passed}/{cnt}")
