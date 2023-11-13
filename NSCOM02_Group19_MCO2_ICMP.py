# NSCOM02 ICMP Machine Project
# S11 Group 19
# MAGDAMO, BIEN RAFAEL O.
# PANGILINAN, WILHELM VINCENT S.
# ICMP program github reference: https://github.com/kyan001/ping3

# To Run: python -c "import NSCOM02_Group19_MCO2_ICMP; NSCOM02_Group19_MCO2_ICMP.ping('8.8.8.8')"

from socket import *
import os
import sys
import struct
import time
import select
import binascii
import errno
import statistics


ICMP_ECHO_REQUEST = 8

def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = string[count+1] * 256 + string[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2
    if countTo < len(string):
        csum = csum + string[len(string) - 1]
        csum = csum & 0xffffffff
    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def receiveOnePing(mySocket, ID, timeout, destAddr):
    def read_icmp_header(raw: bytes) -> dict:
        icmp_header_keys = ('type', 'code', 'checksum', 'id', 'seq')
        return dict(zip(icmp_header_keys, struct.unpack("bbHHh", raw)))

    timeLeft = timeout
    while 1:
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []:  # Timeout
            return -1
        timeReceived = time.time()
        recPacket, addr = mySocket.recvfrom(1024)
        #Fill in start

        #Fetch the ICMP header from the IP packet
        icmp_hdr_raw = recPacket[20:28]
        icmp_header = read_icmp_header(icmp_hdr_raw)
        if icmp_header['type'] == 3:
            if icmp_header['code'] == 0:
                print("Network Unreachable")
            elif icmp_header['code'] == 1:
                print("Host Unreachable")

        if icmp_header['id'] == ID and icmp_header['type'] == 0:  # Echo reply
            timeSent = struct.unpack("d", recPacket[28:28 + struct.calcsize("d")])[0]
            return timeReceived - timeSent

        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return -1  # Return -1 for timeout

def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    myChecksum = 0
    # Make a dummy header with a 0 checksum

    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)


    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data
    mySocket.sendto(packet, (destAddr, 1)) # AF_INET address must be tuple, not str
    # print(packet)
    # Both LISTS and TUPLES consist of a number of objects
    # which can be referenced by their position number within the object.


def doOnePing(destAddr, timeout):
    icmp = getprotobyname("icmp")
    # SOCK_RAW is a powerful socket type. For more details: http://sockraw.org/papers/sock_raw

    #Fill in start
    #create socket
    try:
        mySocket = socket(AF_INET, SOCK_RAW, icmp)
        #print (mySocket)
    except PermissionError:
        if PermissionError.errno == errno.EPERM:
           mySocket = socket(AF_INET, SOCK_DGRAM, icmp)
        else:
            raise PermissionError
    #Fill in end

    myID = os.getpid() & 0xFFFF # Return the current process i

    #Fill in start
    #send a single ping using the socket, dst addr and ID
    #add delay using timeout
    #close socket

    sendOnePing(mySocket, destAddr, myID)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)
    mySocket.close()
    if delay is None:
        return None
    #Fill in end

    return delay

def ping(host, timeout=1, count=5):
    dest = gethostbyname(host)
    print("Pinging " + dest + " using Python:")
    print("")

    delays = []
    packets_sent = 0
    packets_received = 0
    timeouts = 0
    network_unreachable = 0
    host_unreachable = 0

    while packets_sent < count:
        delay = doOnePing(dest, timeout)

        if delay == -1:
            timeouts += 1
            print("Request timed out.")
        elif delay == 1:
            network_unreachable += 1
            print("Network Unreachable")
        elif delay == 2:
            host_unreachable += 1
            print("Host Unreachable")
        else:
            delays.append(delay * 1000)  # Convert delay to milliseconds
            packets_received += 1
            print(f"Reply from {dest}: {delay * 1000:.6f} ms")

        time.sleep(1)
        packets_sent += 1

    # Calculate statistics
    min_rtt = min(delays) if delays else 0
    max_rtt = max(delays) if delays else 0
    avg_rtt = statistics.mean(delays) if delays else 0

    packet_loss_rate = ((packets_sent - packets_received) / packets_sent) * 100 if packets_sent > 0 else 0
    packets_lost = packets_sent - packets_received

    print("\n--- Ping statistics for " + dest + " ---")
    print(f"\t{packets_sent} Packets: Sent = {packets_received} Received, Lost = {packets_lost} ({packet_loss_rate:.2f}% packet loss)")
    print(f"Approximate round trip times in milli-seconds:\n\t Minimum = {min_rtt:.6f}ms, Maximum = {max_rtt:.6f}ms, Average = {avg_rtt:.6f}ms")

    return delays, min_rtt, max_rtt, avg_rtt, packet_loss_rate


