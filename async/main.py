from vulnscanner import Scanner
import sys
import pyfiglet
import time
import re
import asyncio


async def main():
    ascii_banner = pyfiglet.figlet_format("PORTPY")
    print(ascii_banner)
    
    rangePattern = re.compile(r'^\d+-\d+$')
    portPattern = re.compile(r'^\d+(,\d+)*$')

    try:
        
        targetIp = sys.argv[1]
        portNumber = sys.argv[2]

        print('Scanning is in progress...\n')

        maxConcurrentTasks = 100  # Adjust based on your system's capacity
        semaphore = asyncio.Semaphore(maxConcurrentTasks)

        # Initialize Scanner object
        scanner = Scanner(targetIp, semaphore)


        if rangePattern.match(portNumber):
            startPort, endPort = map(int, portNumber.split('-'))
            startPort, endPort = min(startPort, endPort), max(startPort, endPort) # sorts the list if port range is given reverse order
            ports = range(startPort, endPort+1) # port range in a list
            

        elif portPattern.match(portNumber):
            ports = list(map(int, portNumber.split(','))) # for comma separated ports

        else:
            ports = [int(portNumber)] # single port as a list


        print(f"{'PORT':<7}{'STATE':<6}{'SERVICE':<10}")        


        tasks = [scanner.scanPort(port) for port in ports]
        await asyncio.gather(*tasks)

           
        print(f'\nTotal open ports: {scanner.openPortCount}')

    except (IndexError, ValueError):
        print('[!] Error\nUsage: ./main.py <ip> <port/range>\nExample: ./main.py 10.0.0.1 1-100')

if __name__ == "__main__":
    start = time.perf_counter()
    
    asyncio.run(main())

    finish = time.perf_counter()
    print(f'\nFinished in {round(finish-start, 2)} seconds')


