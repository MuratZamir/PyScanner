from vulnscanner import Scanner
import sys
import concurrent.futures
import pyfiglet
import time
import re
import os


start = time.perf_counter()


def main():
    ascii_banner = pyfiglet.figlet_format("PORTPY")
    print(ascii_banner)
    
    rangePattern = re.compile(r'^\d+-\d+$')
    portPattern = re.compile(r'^\d+(,\d+)*$')

    try:
        

        # TODO: add getopt args for passing cli parameters
        targetIp = sys.argv[1]
        portNumber = sys.argv[2]

        print('Scanning is in progress...\n')

        scanner = Scanner(targetIp)

        if rangePattern.match(portNumber):
            startPort, endPort = map(int, portNumber.split('-'))
            startPort, endPort = min(startPort, endPort), max(startPort, endPort) # sorts the list if port range is given reverse order
            ports = range(startPort, endPort+1) # port range in a list
            #print(os.cpu_count())

        elif portPattern.match(portNumber):
            ports = list(map(int, portNumber.split(','))) # for comma separated ports

        else:
            ports = [int(portNumber)] # single port as a list

        print(f"{'PORT':<7}{'STATE':<6}{'SERVICE':<10}")        

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            # futures = [executor.submit(scanner.scanPort, port) for port in ports] 
            # # .scanPort function is called as a function reference 
            # concurrent.futures.wait(futures)
            executor.map(scanner.scanPort, ports)
           



    except IndexError and ValueError:
        print('[!] Error\nUsage: ./main.py <ip> <port/range>\nExample: ./main.py 10.0.0.1 1-100')

if __name__ == "__main__":
    main()


finish = time.perf_counter()

print(f'\nFinished in {round(finish-start, 2)} seconds')


