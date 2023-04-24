                          Programming Assignment #3
                           
                           Aziz Huseynov  20210760
                           Amin Jalilov   20210762

                              TCPAssignment.hpp

UFD stands for Unique File Descriptor and is a combination of pid and fd.

PortTracker is needed to save used ports. We handle 0.0.0.0 case there too 
(opened for all connections).

TupleTCP is needed to save source and destination addresses and ports for each 
TCP connection.

TupleHasherTCP is needed to handle a map that maps UFD to TupleTCP.

Socket (our structure) is needed to save and maintain each TCP connection. 
It can be of various types:
{
  NULL_SOCKET - not initialized
  CLOSED_SOCKET - created
  LISTEN_SOCKET - is in listen mode
  TCP_SOCKET - tcp connection socket
}
Each Socket of type TCP_SOCKET can be of various state, each corresponding to a 
TCP state:
{
  CLOSED
  LISTEN
  SYN_SENT
  SYN_RCVD
  ESTABLISHED
  CLOSE_WAIT
  LAST_ACK
  FIN_WAIT_1
  FIN_WAIT_2
  CLOSING
  TIME_WAIT
}

waitlist in Socket is a list of pending to be established connections.
readyQueue is a queue of established but not accepted connections.

read_buf and write_buf are dynamically allocated buffers for read and write

timer is for timeouts of control packets and tcp_timer is for data packets.

TimerPayload passed relevant information to the timer.

State of TCP is tracked with seq, ack and acked (base_pointer).

portMap of type PortTracker is needed to assgin and handle used ports.

socketMap (UFD -> Socket) is needed to handle sockets and tcp connections.



                              TCPAssignment.cpp

Helper functions assignPort are used to manage port assignment (including 
0.0.0.0 case).

Helper function fixSrcAddr is used to get actual source IP when 0.0.0.0 is 
specified.

Helper function shipPacket is used to assemble the TCP datagram and send it.

Helper function max is used to find maximum among 2 seq/ack numbers.

Helper function sendData generates and sends datagrams until send window is 
saturated.

In systemCallback:

SOCKET:
A new FD is created, mapped to a new Socket (in UFD) and returned.

CLOSE:
Socket state is changed according to TCP standards. FIN or ACK packet is sent. 
Timer is set. Socket and file descriptor are removed if FIN has been received.

CONNECT:
Socket state and type are changed according to TCP standards. SYN packet is 
sent. Timer is set.

LISTEN:
Socket type is changed according to TCP standards. Backlog is set.

ACCEPT:
Sockket state and type are changed according to TCP standards. If there is a 
pending established connection, new file descriptor is created and returned.

BIND:
Socket type is changed according to TCP standards. Address and ports are binded 
to Socket.

GETSOCKNAME:
Socket source address and port are set.

GETPEERNAME:
Socket destination address and port are set.

In packetArrived:
Packet is parsed and checksum is checked. It is then handled according to TCP 
standards.

In timerCallback:
Socket is handled according to TCP standards.

Packet loss/corruption handling:
If ACK is not received withing expected timeframe, reset sequence number to base
pointer and call sendData to resend the segments.