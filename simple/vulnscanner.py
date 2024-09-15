from IPy import IP
import sys
import socket

class Scanner:
    def __init__(self, target, port):
        self.target = target
        self.port = int(port)

    def ipToDomain(self):
        domain = socket.gethostbyname(self.target)
        return domain


    def validateIp(self):
        try:
            ipAddress = IP(self.target)
            return ipAddress
        # except Exception as e:
        #     print(type(e))
        except ValueError:
            print(f'{self.target} is not a valid IP address.')
            return socket.gethostbyname(self.target)
    


    def scanPort(self):
        try:            
            convertedIp = str(self.validateIp())
            connection = (convertedIp, self.port)
        
            socket.setdefaulttimeout(1)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            sock.connect(connection)
            print(f"[+] port {self.port} open")
            
        except (socket.error, socket.timeout):
            pass
            
        
        except socket.timeout:
            print('\n[-] timeout has occured')

        finally:
            sock.close()



#Inheritance
class Nmap(Scanner):
    pass
class Ffuf(Scanner):
    pass


