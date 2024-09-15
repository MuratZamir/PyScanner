import vulnscanner
import sys
import getopt
import pyfiglet
import timeit



ascii_banner = pyfiglet.figlet_format("PORTPY")
print(ascii_banner)

# TODO: add getopt args for passing cli parameters
targetIp = sys.argv[1]
portNumber = sys.argv[2]

def main():

    print('Host:', targetIp)
    print('Port:', portNumber)

    print('Scanning is in progress...\n')
    

    if '-' in portNumber:
        startPort, endPort = map(int, portNumber.split('-'))
        
        for port in range(startPort, endPort+1):
            target = vulnscanner.Scanner(targetIp, port)
            target.scanPort()
            # break

    else:
        target = vulnscanner.Scanner(targetIp, portNumber)
        target.scanPort()


    # execution_time = timeit.timeit(main, number=1)
    # print(execution_time)
main()


