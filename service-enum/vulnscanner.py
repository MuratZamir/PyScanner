from IPy import IP
import sys
import socket
import asyncio
import nmap
import json


class Scanner:

    def __init__(self, target, semaphore):
        self.target = target
        self.semaphore = semaphore
        self.portServices = {
        21: 'ftp', 22: 'ssh', 23: 'telnet',
        25: 'smtp', 53: 'dns', 80: 'http',
        110: 'pop3', 111: 'rcpbind', 139: 'netbios-ssn',
        143: 'imap', 443: 'https', 445: 'microsoft-ds',
        512: 'exec',513: 'login', 514: 'shell', 631: 'ipp',
        3306: 'mysql', 3389: 'rdp', 5432: 'postgresql',
        5900: 'vnc', 6000: 'X11', 8834: 'nessus-xmlrpc', 33060: 'mysqlx'
        # add more ports and services as needed
        }
        self.openPortCount = 0 # open port counter
        self.lock = asyncio.Lock() # Lock to ensure safe access to counter
        self.nmapScanPorts = [] # counts open port numbers for nmap


    def ipToDomain(self):
        '''Function to resolve IP addresses'''
        domain = socket.gethostbyname(self.target)
        return domain


    def validateIp(self):
        '''Function to check if the IP is valid or not'''
        try:
            ipAddress = IP(self.target)
            return str(ipAddress)
        except ValueError:
            print(f'{self.target} is not a valid IP address.')
            sys.exit(1)
    


    async def scanPort(self, port):
        '''Async function to check if a port is open or not'''
        async with self.semaphore: # limits simultaneous network connections
            try: 

                convertedIp = str(self.validateIp())

                '''Returns tuple containing two objects'''
                # StreamReader for reading data from async connection
                # StreamWriter for writing data to async connection
                reader, writer = await asyncio.wait_for(asyncio.open_connection(convertedIp, port), timeout=2)

                
                serviceName = self.portServices.get(port, 'unknown')
                print(f"{port}/tcp open  {serviceName}")
                self.nmapScanPorts.append(port) # counting the open ports for nmap -sV

                async with self.lock:
                    self.openPortCount +=1

                writer.close()
                await writer.wait_closed()


            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                pass
            # uncomment if further information is needed
                # serviceName = self.portServices.get(port, 'unknown')
                # print(f"{port}/tcp closed  {serviceName} ({e})")
      

    def nmap(self, port):
        nm = nmap.PortScanner()
        try:
            versionResult = nm.scan(self.target, str(port), arguments='-sV')

            # print("Raw Nmap Output:", versionResult)
            parsedResult = versionResult['scan'][self.target]['tcp'][int(port)]

            name = parsedResult.get('name', 'unknown')
            product = parsedResult.get('product', 'unknown')
            version = parsedResult.get('version', 'unknown')
            extraInfo = parsedResult.get('extrainfo', 'unknown')
            # cpe = parsedResult['cpe']

            result = f'{product} {version} {extraInfo}'
            return result
        
        except KeyError:
            return "no version information available"
