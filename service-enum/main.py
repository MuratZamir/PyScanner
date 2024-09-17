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


        '''Further service enumeration with NMAP'''
        furtherEnum = input('\nFurther service enum? [y/n] ')
        
        

        if furtherEnum.lower() == 'y':
            allPorts = input('Service enum for all open ports? [y/n] ')
            # serviceName = scanner.portServices.get(scanner.portServices, 'unknown')
            
            if allPorts.lower() == 'y':
                
                print(f"\n{'PORT':<7}{'SERVICE':<10}")
                for port in scanner.nmapScanPorts:
                    serviceInfo = scanner.nmap(str(port))
                    print(f"{port:<7}{serviceInfo:<23}")

            elif allPorts.lower() == 'n':
                specificPorts = input('Specific port(s): [comma-separated] ')
                specificPortsList = map(int, specificPorts.split(','))  # Convert to a list of integers
                print(f"\n{'PORT':<7}{'SERVICE':<10}")
                for port in specificPortsList:
                    serviceInfo = scanner.nmap(str(port))
                    
                    print(f"{port:<7}{serviceInfo:<23}")
            

    except (IndexError, ValueError):
        print('[!] Error\nUsage: ./main.py <ip> <port/range>\nExample: ./main.py 10.0.0.1 1-100')

if __name__ == "__main__":
    start = time.perf_counter()
    
    asyncio.run(main())

    finish = time.perf_counter()
    elapsedTime = (finish - start)/60
    
    print(f'\nFinished in {round(elapsedTime, 2)} minutes')


