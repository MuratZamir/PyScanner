from IPy import IP
import sys
import socket

class Scanner:

    portServices = {
        21: 'ftp',
        22: 'ssh',
        23: 'telnet',
        25: 'smtp',
        53: 'dns',
        80: 'http',
        110: 'pop3',
        111: 'rcpbind',
        139: 'netbios-ssn',
        143: 'imap',
        443: 'https',
        445: 'microsoft-ds',
        512: 'exec',
        513: 'login',
        514: 'shell',
        631: 'ipp',
        3306: 'mysql',
        3389: 'rdp',
        5432: 'postgresql',
        5900: 'vnc',
        6000: 'X11',
        8834: 'nessus-xmlrpc',
        33060: 'mysqlx'
        # add more ports and services as needed
    }


    def __init__(self, target):
        self.target = target
        #self.port = int(port)

    def ipToDomain(self):
        '''Function to resolve IP addresses'''
        domain = socket.gethostbyname(self.target)
        return domain


    def validateIp(self):
        '''Function to check if the IP is valid or not'''
        try:
            ipAddress = IP(self.target)
            return ipAddress
        except ValueError:
            print(f'{self.target} is not a valid IP address.')
            #return e 
            sys.exit(1)
    


    def scanPort(self, port):
        '''Function to check if a port is open or not'''
        sock = None # initialize the sock variable to ensure it exists
        try: 
            socket.setdefaulttimeout(1)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


            convertedIp = str(self.validateIp())
            connection = (convertedIp, port)
        

            sock.connect(connection)

            serviceName = self.portServices.get(port, 'unknown')
            print(f"{port}/tcp open  {serviceName}")
        
        except (socket.error, socket.timeout) as e:
            pass
        # uncomment if further information is needed
            # serviceName = self.portServices.get(port, 'unknown')
            # print(f"{port}/tcp closed  {serviceName} ({e})")
            
        finally:
            # ensure that sock.close() is only called if sock was created
            if sock is not None:
                sock.close()



#Inheritance
class Nmap(Scanner):
    pass
class Ffuf(Scanner):
    pass


