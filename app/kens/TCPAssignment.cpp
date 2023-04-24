/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */
/*
 *  Aziz Huseynov 20210760
 *  Amin Jalilov  20210762
 */
#include "TCPAssignment.hpp"
#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>
#include <iostream>
#define UFD ((uint64_t)pid << 20 | fd)
namespace E {

TCPAssignment::TCPAssignment(Host &host)
    : HostModule("TCP", host), RoutingInfoInterface(host),
      SystemCallInterface(AF_INET, IPPROTO_TCP, host),
      TimerModule("TCP", host) {}

TCPAssignment::~TCPAssignment() {}

uint16_t TCPAssignment::assignPort(uint32_t addr, uint16_t port) {
  portMap[port].add(addr);
  return port;
}

uint16_t TCPAssignment::assignPort(uint32_t addr) {
  uint16_t port = rng() % (1 << 16);
  if (port < 1024)
    port = 1024;
  while (!portMap[htons(port)].available(addr)) {
    port++;
    if (port < 1024)
      port = 1024;
  }
  return htons(port);
}

uint32_t TCPAssignment::fixSrcAddr(uint32_t destAddr) {
  auto newip =
      getIPAddr(getRoutingTable(NetworkUtil::UINT64ToArray<4>(destAddr)))
          .value();
  return NetworkUtil::arrayToUINT64<4>(newip);
}

// void TCPAssignment::shipPacket2(uint8_t *packet, size_t packet_size) {
//   Packet pkt = Packet(packet_size);
//   pkt.writeData(0, packet, packet_size);
//   sendPacket("IPv4", std::move(pkt));
// }

uint32_t TCPAssignment::max(uint32_t a, uint32_t b) {
  if(a > b) std::swap(a, b);
  if(a - b < (1<<16)) return a;
  return b;
}

void TCPAssignment::shipPacket(TupleTCP &addr, int seq_num, int ack_num,
                               uint8_t flags, size_t data_size,
                               uint8_t *data, uint16_t win_sz) {
  uint32_t real_src_ip = addr.srcAddr;
  if (real_src_ip == 0)
    real_src_ip = fixSrcAddr(addr.destAddr);

  uint8_t raw_packet[54 + data_size];
  memset(raw_packet, 0, 54 + data_size);

  memcpy(raw_packet + 14 + 12, &real_src_ip, 4);       // Source IP
  memcpy(raw_packet + 14 + 16, &addr.destAddr, 4 + 4); // Dest IP and Ports
  *((uint32_t *)(raw_packet + 14 + 20 + 4)) = htonl(seq_num); // Seq
  *((uint32_t *)(raw_packet + 14 + 20 + 8)) = htonl(ack_num); // Ack
  raw_packet[14 + 20 + 12] = 5 << 4;                          // Data offset
  raw_packet[14 + 20 + 13] = flags;                           // Flags
  *((uint16_t *)(raw_packet + 14 + 20 + 14)) = htons(win_sz); // Windows size
  memcpy(raw_packet + 14 + 20 + 20, data, data_size);         // Data
  *((uint16_t *)(raw_packet + 14 + 20 + 16)) = htons(
      ~NetworkUtil::tcp_sum(real_src_ip, addr.destAddr, raw_packet + 14 + 20,
                            20 + data_size)); // Checksum

  Packet pkt = Packet(14 + 20 + 20 + data_size);
  pkt.writeData(0, raw_packet, 14 + 20 + 20 + data_size);
  sendPacket("IPv4", std::move(pkt));
}

void TCPAssignment::err(std::string s) {
  // std::cout << s << std::endl;
}

// TO DO: move stuff here from hpp
void TCPAssignment::initialize() {}

void TCPAssignment::finalize() {}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {

  int fd;

  sockaddr_in *addr;
  socklen_t *addr_len, addr_len_int;
  u_int32_t real_src_ip;
  TupleTCP tcp_tuple;

  uint8_t *raw_packet;

  switch (param.syscallNumber) {
  case SOCKET:
    // this->syscall_socket(syscallUUID, pid, std::get<int>(param.params[0]),
    //                      std::get<int>(param.params[1]));

    fd = createFileDescriptor(pid);

    if (fd >= (1 << 20) or pid >= (1LL << 40)) {
      err("Wrong fd and pid");
      returnSystemCall(syscallUUID, -1);
      break;
    }

    if (fd == -1 or socketMap.count(UFD)) {
      err("Too many sockets are opened");
      returnSystemCall(syscallUUID, -1);
      break;
    }

    socketMap[UFD].type = NULL_SOCKET;

    returnSystemCall(syscallUUID, fd);

    break;
  case CLOSE:
    // this->syscall_close(syscallUUID, pid, std::get<int>(param.params[0]));

    fd = std::get<int>(param.params[0]);

    if (!socketMap.count(UFD)) {
      returnSystemCall(syscallUUID, -1);
      return;
    }

    // SYN_SENT:    Do nothing
    // SYN_RCVD:    send FIN
    // ESTABLISHED: send FIN
    // CLOSE_WAIT:  send FIN

    if (socketMap[UFD].state == SYN_RCVD or
        socketMap[UFD].state == ESTABLISHED or
        socketMap[UFD].state == CLOSE_WAIT) {

      if (socketMap[UFD].state == CLOSE_WAIT)
        socketMap[UFD].state = LAST_ACK;
      else
        socketMap[UFD].state = FIN_WAIT_1;

      // Save syscall
      socketMap[UFD].syscallUUID = syscallUUID;

      socketMap[UFD].timer.last.seq_num = socketMap[UFD].seq;
      socketMap[UFD].timer.last.ack_num = 0;
      socketMap[UFD].timer.last.flags = FIN;

      // Send FIN
      if (socketMap[UFD].seq == socketMap[UFD].acked) {
        shipPacket(socketMap[UFD].addr, socketMap[UFD].seq++, 0, FIN);
        socketMap[UFD].timer.enabled = true;
        socketMap[UFD].timer.uuid =
            addTimer(TimerPayload(UFD, socketMap[UFD].addr),
                    TimeUtil::makeTime(100, TimeUtil::MSEC));
      } else socketMap[UFD].fined = true;
    } else { // Normal close
      if (socketMap[UFD].type != NULL_SOCKET) {
        portMap[socketMap[UFD].addr.srcPort].remove(
            socketMap[UFD].addr.srcAddr);
      }
      removeFileDescriptor(pid, fd);
      socketMap.erase(UFD);

      returnSystemCall(syscallUUID, 0);
    }
    break;
  case READ:
    // this->syscall_read(syscallUUID, pid, std::get<int>(param.params[0]),
    //                    std::get<void *>(param.params[1]),
    //                    std::get<int>(param.params[2]));
    fd = std::get<int>(param.params[0]);
    if(socketMap[UFD].read_buf.size()) {
      int trans = std::min(socketMap[UFD].read_buf.size(), (size_t)std::get<int>(param.params[2]));

      // std::cout << "READING UNBLOCKED: " << socketMap[UFD].read_buf.size() << " ; " <<
          // (size_t)std::get<int>(param.params[2]) << std::endl;
      uint8_t *ptr = (uint8_t *)std::get<void *>(param.params[1]);
      for(int i=0;i<trans;i++) {
        ptr[i] = socketMap[UFD].read_buf.front();
        socketMap[UFD].read_buf.pop_front();
      }
      returnSystemCall(syscallUUID, trans);
    } else {
      socketMap[UFD].syscallUUID = syscallUUID;
      socketMap[UFD].read.waiting = true;
      socketMap[UFD].read.ptr = (uint8_t*)std::get<void *>(param.params[1]);
      socketMap[UFD].read.size = std::get<int>(param.params[2]);
    }
    break;
  case WRITE:
    // this->syscall_write(syscallUUID, pid, std::get<int>(param.params[0]),
    //                     std::get<void *>(param.params[1]),
    //                     std::get<int>(param.params[2]));
    fd = std::get<int>(param.params[0]);
    {
      uint8_t* data = (uint8_t*) std::get<void *>(param.params[1]);
      size_t data_size = std::get<int>(param.params[2]);
      for(int i=0;i<data_size;i++)
        socketMap[UFD].write_buf.push_back(data[i]);
      
      socketMap[UFD].write.waiting = true;
      socketMap[UFD].write.data_size = data_size;
      socketMap[UFD].syscallUUID = syscallUUID;

      //std::cout<<"Sending new data "<<data_size<<' '<<socketMap[UFD].write_buf.size()<<std::endl;
      sendData(UFD, socketMap[UFD]);
    }
    break;
  case CONNECT:
    // this->syscall_connect(
    //     syscallUUID, pid, std::get<int>(param.params[0]), // fd
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     //addr (socklen_t)std::get<int>(param.params[2])); // len
    fd = std::get<int>(param.params[0]);
    addr = (sockaddr_in *)std::get<void *>(param.params[1]);

    if (!socketMap.count(UFD)) {
      returnSystemCall(syscallUUID, -1);
      break;
    }

    switch (socketMap[UFD].type) {
    case NULL_SOCKET:
      socketMap[UFD].addr.srcAddr = 0;
      socketMap[UFD].addr.srcPort = assignPort(socketMap[UFD].addr.srcAddr);
    case CLOSED_SOCKET:
      socketMap[UFD].type = TCP_SOCKET;

      socketMap[UFD].addr.destAddr = addr->sin_addr.s_addr;
      socketMap[UFD].addr.destPort = addr->sin_port;

      socketMap[UFD].seq = (uint32_t) 69; // rng();
      socketMap[UFD].syscallUUID = syscallUUID;

      socketMap[UFD].timer.last.seq_num = socketMap[UFD].seq;
      socketMap[UFD].timer.last.ack_num = 0;
      socketMap[UFD].timer.last.flags = SYN;

      shipPacket(socketMap[UFD].addr, socketMap[UFD].seq++, 0, SYN);
      socketMap[UFD].state = SYN_SENT;
      socketMap[UFD].timer.enabled = true;
      socketMap[UFD].timer.uuid = addTimer(
          TimerPayload(UFD, socketMap[UFD].addr), 
          TimeUtil::makeTime(100, TimeUtil::MSEC));
      break;
    case LISTEN_SOCKET:
      err("Socket is already in listen mode");
      returnSystemCall(syscallUUID, -1);
      break;
    case TCP_SOCKET:
      err("You are already talking");
      returnSystemCall(syscallUUID, -1);
      break;
    }

    break;
  case LISTEN:
    // this->syscall_listen(syscallUUID, pid, std::get<int>(param.params[0]),
    //                      std::get<int>(param.params[1]));

    fd = std::get<int>(param.params[0]);
    if (!socketMap.count(UFD)) {
      returnSystemCall(syscallUUID, -1);
      break;
    }

    switch (socketMap[UFD].type) {
    case NULL_SOCKET:
      socketMap[UFD].addr.srcAddr = 0;
      socketMap[UFD].addr.srcPort = assignPort(socketMap[UFD].addr.srcAddr);
    case CLOSED_SOCKET:
      socketMap[UFD].type = LISTEN_SOCKET;
      socketMap[UFD].backlog = std::get<int>(param.params[1]);
      break;
    case LISTEN_SOCKET:
      socketMap[UFD].backlog = std::get<int>(param.params[1]);
      break;
    case TCP_SOCKET:
      err("You aren't supposed to listen here");
      returnSystemCall(syscallUUID, -1);
      break;
    }

    returnSystemCall(syscallUUID, 0);

    break;
  case ACCEPT: {
    // this->syscall_accept(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));

    fd = std::get<int>(param.params[0]);
    addr = static_cast<struct sockaddr_in *>(std::get<void *>(param.params[1]));
    addr_len = static_cast<socklen_t *>(std::get<void *>(param.params[2]));

    if (!socketMap.count(UFD)) {
      returnSystemCall(syscallUUID, -1);
      break;
    }

    switch (socketMap[UFD].type) {
    case NULL_SOCKET:
    case CLOSED_SOCKET:
      err("You are supposed to listen from this before accept");
      returnSystemCall(syscallUUID, -1);
      break;
    case LISTEN_SOCKET:
      *addr_len = sizeof(sockaddr_in);
      socketMap[UFD].syscallUUID = syscallUUID;
      if (socketMap[UFD].readyQueue.empty()) {
        socketMap[UFD].waiting = true;
        socketMap[UFD].acceptAddr.addr = addr;
      } else {
        int nfd = createFileDescriptor(pid);
        socketMap[pid << 20 | nfd] = *socketMap[UFD].readyQueue.begin();
        socketMap[UFD].readyQueue.pop_front();
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = socketMap[UFD].addr.destAddr;
        addr->sin_port = socketMap[UFD].addr.destPort;
        returnSystemCall(syscallUUID, nfd);
      }
      break;
    case TCP_SOCKET:
      err("You aren't supposed to accept from this");
      returnSystemCall(syscallUUID, -1);
      break;
    }

    break;
  }
  case BIND:
    // this->syscall_bind(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     (socklen_t)std::get<int>(param.params[2]));

    fd = std::get<int>(param.params[0]);
    addr = (sockaddr_in *)std::get<void *>(param.params[1]);

    if (!socketMap.count(UFD) or socketMap[UFD].type != NULL_SOCKET) {
      returnSystemCall(syscallUUID, -1);
      break;
    }

    if (!portMap[addr->sin_port].available(addr->sin_addr.s_addr)) {
      returnSystemCall(syscallUUID, -1);
      break;
    }

    socketMap[UFD].type = CLOSED_SOCKET;

    socketMap[UFD].addr.srcAddr = addr->sin_addr.s_addr;
    socketMap[UFD].addr.srcPort = addr->sin_port;

    assignPort(socketMap[UFD].addr.srcAddr, socketMap[UFD].addr.srcPort);
    returnSystemCall(syscallUUID, 0);

    break;
  case GETSOCKNAME:
    // this->syscall_getsockname(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    fd = std::get<int>(param.params[0]);

    if (!socketMap.count(UFD)) {
      returnSystemCall(syscallUUID, -1);
      break;
    }

    addr = (sockaddr_in *)std::get<void *>(param.params[1]);
    addr_len = (socklen_t *)std::get<void *>(param.params[2]);
    *addr_len = sizeof(sockaddr_in);

    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = socketMap[UFD].addr.srcAddr;
    addr->sin_port = socketMap[UFD].addr.srcPort;

    returnSystemCall(syscallUUID, 0);

    break;
  case GETPEERNAME:
    // this->syscall_getpeername(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));

    fd = std::get<int>(param.params[0]);

    if (!socketMap.count(UFD) or socketMap[UFD].type != TCP_SOCKET) {
      returnSystemCall(syscallUUID, -1);
      break;
    }

    addr = (sockaddr_in *)std::get<void *>(param.params[1]);
    addr_len = (socklen_t *)std::get<void *>(param.params[2]);
    *addr_len = sizeof(sockaddr_in);

    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = socketMap[UFD].addr.destAddr;
    addr->sin_port = socketMap[UFD].addr.destPort;

    returnSystemCall(syscallUUID, 0);

    break;
  default:
    assert(0);
  }
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // 0 -> Ethernet
  // 14 -> IP header
  // 34 -> TCP header

  if (fromModule != "IPv4")
    err("Only IPv4 is supported");

  int packet_size = packet.getSize();
  int data_size = packet_size - 54;
  uint8_t raw_packet[packet_size];
  uint8_t *tcp_header = raw_packet + 14 + 20;
  uint8_t *tcp_data = raw_packet + 14 + 20 + 20;
  packet.readData(0, raw_packet, packet.getSize());
  
  TupleTCP tcp_tuple(raw_packet + 14 + 12);
  
  // --- Checksum ---
  uint16_t checksum1 = ntohs(*((uint16_t *)(raw_packet + 14 + 20 + 16)));
  *((uint16_t *)(raw_packet + 14 + 20 + 16)) = 0;
  uint16_t checksum2 = ~NetworkUtil::tcp_sum(
      tcp_tuple.srcAddr, tcp_tuple.destAddr, tcp_header, packet_size - 34);
  if(checksum1 != checksum2) {
    // std::cout << "Wrong checksum " << std::hex << checksum1 << ' ' << checksum2
    //           << std::dec << std::endl;
    return;
  }
  // Checksum done
  
  uint32_t seq = ntohl(*(uint32_t *)(tcp_header + 4));
  uint32_t ack = ntohl(*(uint32_t *)(tcp_header + 8));
  uint16_t wnd = ntohs(*(uint16_t *)(tcp_header + 14));
  uint8_t flags = tcp_header[13];

  std::swap(tcp_tuple.srcAddr, tcp_tuple.destAddr);
  std::swap(tcp_tuple.srcPort, tcp_tuple.destPort);

  for (auto &&[ufd, sock] : socketMap) {
    if (sock.addr.equalSrc(tcp_tuple) and sock.addr.equalDest(tcp_tuple) and
        sock.type == TCP_SOCKET) {
      
      if(wnd) sock.wnd = wnd;
      
      if (flags & ACK and max(sock.acked, ack) == ack) {
        size_t dlt = max(sock.acked, ack) - sock.acked;
        dlt = std::min(dlt, sock.write_buf.size());
        //std::cout<<"Freeing "<<dlt<<" B  : "<<ack<<std::endl;
        sock.acked += dlt;
        while(dlt--) sock.write_buf.pop_front();

        if (sock.fined and sock.seq == sock.acked and sock.write_buf.empty()) {
          shipPacket(sock.addr, sock.seq++, 0, FIN);
          sock.timer.enabled = true;
          sock.timer.uuid =
              addTimer(TimerPayload(ufd, sock.addr),
                       TimeUtil::makeTime(100, TimeUtil::MSEC));
        }
      }

      if(sock.timer.enabled) {
        cancelTimer(sock.timer.uuid);
        sock.timer.enabled = false;
      }
      switch (sock.state) {
      case SYN_SENT:
        if (flags & SYN and flags & ACK) {
          sock.state = ESTABLISHED;
          sock.ack = seq + 1;
          if(flags & ACK) sock.acked = ack;
          for(int _=0;_<GENSOL;_++)
          shipPacket(sock.addr, sock.seq, sock.ack, ACK);
          err("Final ACK send SS -> EST");
          returnSystemCall(sock.syscallUUID, 0);
        } else if (flags & SYN) { // simul open
          sock.state = SYN_RCVD;
          sock.timer.last.seq_num = sock.seq - 1;
          sock.timer.last.ack_num = seq + 1;
          sock.timer.last.flags   = SYN | ACK;

          for(int _=0;_<GENSOL;_++)
          shipPacket(sock.addr, sock.seq - 1, seq + 1, SYN | ACK);
          err("Final ACK send");
          
          sock.timer.enabled = true;
          sock.timer.uuid = addTimer(TimerPayload(ufd, sock.addr),
                                     TimeUtil::makeTime(100, TimeUtil::MSEC));
        }
        break;
      case SYN_RCVD:
        if (flags & ACK) {
          sock.state = ESTABLISHED;
          returnSystemCall(sock.syscallUUID, 0);
        }
        break;
      
      case CLOSE_WAIT:
      case ESTABLISHED: // -> CLOSE_WAIT
        // err("new_pack");
        if (flags & FIN) {
          sock.state = CLOSE_WAIT;
          // Send ACK
          //return;
        } else if (flags == (SYN | ACK)) {
          shipPacket(sock.addr, sock.seq - 1, seq + 1, ACK);
          return;
        }
        //sock.ack = max(sock.ack, seq + data_size);
        // std::cout<<seq<<'+'<<data_size<<' '<<sock.seq<<' '<<sock.ack<<std::endl;
        // --- HANDLING DATA ---------------------------------------------------
        if(seq == sock.ack) {
          // std::cout<<"EATING " << data_size << "B DATA" <<std::endl;
          for(int i=0;i<data_size;i++)
            sock.read_buf.push_back(tcp_data[i]);
          sock.ack = seq + data_size;
        }
        if(max(seq + data_size, sock.ack) == sock.ack and data_size) {
          shipPacket(sock.addr, sock.seq, sock.ack, ACK);

          if (sock.tcp_timer.enabled)
            cancelTimer(sock.tcp_timer.uuid);
          sock.tcp_timer.enabled = true;
          sock.tcp_timer.uuid =
              addTimer(TimerPayload(ufd, sock.addr, true),
                       TimeUtil::makeTime(100, TimeUtil::MSEC));
        }
        // std::cout<<sock.write_buf.empty()<<' '<<sock.write_buf.size()<<std::endl;
        sendData(ufd, sock);
        if(sock.read.waiting) {
          sock.read.waiting = false;
          int trans = std::min(sock.read_buf.size(),
                               (size_t) sock.read.size);
          // std::cout << "READING BLOCKED: " << sock.read_buf.size() << " ; "
          //           << sock.read.size << std::endl;
          uint8_t *ptr = (uint8_t *) sock.read.ptr;
          for (int i = 0; i < trans; i++) {
            ptr[i] = sock.read_buf.front();
            sock.read_buf.pop_front();
          }
          returnSystemCall(sock.syscallUUID, trans);
        }
        // ---------------------------------------------------------------------
        break;
      case FIN_WAIT_1:
        if (flags & FIN and flags & ACK) { // Simul close
          sock.state = CLOSED;
          // Send ACK
          for(int _=0;_<GENSOL;_++)
          shipPacket(sock.addr, sock.seq, seq + 1, ACK);

          // Close socket
          socketMap[ufd].state = TIME_WAIT;
          sock.timer.enabled = true;
          sock.timer.uuid = addTimer(TimerPayload(ufd, sock.addr),
                                     TimeUtil::makeTime(30, TimeUtil::SEC));

        } else if (flags & FIN) {
          sock.state = CLOSING;
          shipPacket(sock.addr, sock.seq, seq + 1, ACK);
        } else if (flags & ACK) {
          sock.state = FIN_WAIT_2;
        }
        break;
      case FIN_WAIT_2:
        if (flags & FIN) { // Simul close
          // Send ACK
          for(int _=0;_<GENSOL;_++)
          shipPacket(sock.addr, sock.seq, seq + 1, ACK);

          // Close socket
          sock.state = TIME_WAIT;
          sock.timer.enabled = true;
          sock.timer.uuid = addTimer(TimerPayload(ufd, sock.addr),
                                     TimeUtil::makeTime(30, TimeUtil::SEC));
        }
        break;
      case CLOSING:
        if (flags & ACK) {
          // Close socket
          sock.state = TIME_WAIT;
          sock.timer.enabled = true;
          sock.timer.uuid = addTimer(TimerPayload(ufd, sock.addr),
                                     TimeUtil::makeTime(30, TimeUtil::SEC));
        }
        break;
      case LAST_ACK:
        if (flags & ACK) {
          // Close socket
          sock.state = TIME_WAIT;
          sock.timer.enabled = true;
          sock.timer.uuid = addTimer(TimerPayload(ufd, sock.addr),
                                     TimeUtil::makeTime(30, TimeUtil::SEC));
          // if (sock.type != NULL_SOCKET) {
          //   portMap[sock.addr.srcPort].remove(
          //       sock.addr.srcAddr);
          // }
          // removeFileDescriptor(ufd >> 20, ufd & ((1 << 20) - 1));
          // UUID retval = sock.syscallUUID;
          // socketMap.erase(ufd);

          // returnSystemCall(retval, 0);
        }
        break;

      case TIME_WAIT:
        if (flags & FIN) {
          err("ALA QIRILDA!");
          shipPacket(sock.addr, sock.seq, seq + 1, ACK);
        }
      default:
        break;
      }
      return;
    }
  }

  // TCP Not found

  // Search for listening sockets/establishing
  for (auto &[ufd, sock] : socketMap) {
    if (sock.addr.equalSrc(tcp_tuple) and sock.type == LISTEN_SOCKET) {
      // Check if in half-listen state
      for (auto sockw = sock.waitlist.begin(); sockw != sock.waitlist.end();
           ++sockw) {
        if (sockw->addr.equalDest(tcp_tuple)) {
          switch (sockw->state) {
          case SYN_RCVD:
            if (flags & ACK) {
              sockw->state = ESTABLISHED;
              // sockw->ack = seq + 1;
              sockw->acked = ack;
              if (sock.waiting) {
                sock.waiting = false;
                int fd = createFileDescriptor(ufd >> 20);
                socketMap[(ufd >> 20) << 20 | fd] = *sockw;
                sock.acceptAddr.addr->sin_family = AF_INET;
                sock.acceptAddr.addr->sin_addr.s_addr = sockw->addr.destAddr;
                sock.acceptAddr.addr->sin_port = sockw->addr.destPort;
                sock.waitlist.erase(sockw);
                returnSystemCall(sock.syscallUUID, fd);
              } else {
                sock.readyQueue.push_back(*sockw);
                sock.waitlist.erase(sockw);
              }
            }
            break;
          default:
            break;
          }
          return;
        }
      }
      // New incoming
      if (flags & SYN and (sock.waitlist.size()) < sock.backlog) {
        sock.waitlist.emplace_back();
        auto sockw = std::prev(sock.waitlist.end());

        sockw->type = TCP_SOCKET;
        sockw->state = SYN_RCVD;

        sockw->addr.srcAddr = sock.addr.srcAddr;
        sockw->addr.srcPort = sock.addr.srcPort;

        sockw->addr.destAddr = tcp_tuple.destAddr;
        sockw->addr.destPort = tcp_tuple.destPort;

        uint32_t real_src_ip = sockw->addr.srcAddr;
        sockw->seq = (uint32_t)420; // rng();
        sockw->ack = seq + 1;
        sockw->wnd = wnd;

        sockw->timer.last.seq_num = sockw->seq;
        sockw->timer.last.ack_num = seq + 1;
        sockw->timer.last.flags = SYN | ACK;
        shipPacket(sockw->addr, sockw->seq++, seq + 1, SYN | ACK);
        sockw->timer.enabled = true;
        sockw->timer.uuid = addTimer(TimerPayload(ufd, sockw->addr),
                                     TimeUtil::makeTime(100, TimeUtil::MSEC));
      }

      return;
    }
  }
}

void TCPAssignment::timerCallback(std::any payload) {
  // return;
  UUID retval;
  TimerPayload tp = std::any_cast<TimerPayload>(payload);
  if (!socketMap.count(tp.ufd))
    return;

  if (socketMap[tp.ufd].type == TCP_SOCKET) {
    
    if(tp.is_tcp) {
      // std::cout << "Timer expired on "<<socketMap[tp.ufd].acked<<" -> "<< socketMap[tp.ufd].seq<<std::endl;
      socketMap[tp.ufd].seq = socketMap[tp.ufd].acked;
      sendData(tp.ufd, socketMap[tp.ufd]);
    }

    switch (socketMap[tp.ufd].state) {
      case ESTABLISHED:
        err("bruv, badman don our package");
        break;
        
      case SYN_SENT:
      case SYN_RCVD:
      case FIN_WAIT_1:
      case LAST_ACK:
        shipPacket(socketMap[tp.ufd].addr, 
                   socketMap[tp.ufd].timer.last.seq_num,
                   socketMap[tp.ufd].timer.last.ack_num,
                   socketMap[tp.ufd].timer.last.flags);
        socketMap[tp.ufd].timer.uuid = addTimer(tp, TimeUtil::makeTime(100, TimeUtil::MSEC));
        break;

      case TIME_WAIT:
        socketMap[tp.ufd].state = CLOSED;
        if (socketMap[tp.ufd].type != NULL_SOCKET) {
          portMap[socketMap[tp.ufd].addr.srcPort].remove(
              socketMap[tp.ufd].addr.srcAddr);
        }
        removeFileDescriptor(tp.ufd >> 20, tp.ufd & ((1 << 20) - 1));
        retval = socketMap[tp.ufd].syscallUUID;
        socketMap.erase(tp.ufd);
        returnSystemCall(retval, 0);
        break;

      default:
        break;
    }
  } else if (socketMap[tp.ufd].type == LISTEN_SOCKET) {
    for (auto sockw  = socketMap[tp.ufd].waitlist.begin();
              sockw != socketMap[tp.ufd].waitlist.end(); ++sockw) {
      if (sockw->addr == tp.tuple) {
        switch(sockw->state) {
          case SYN_RCVD:
            shipPacket(sockw->addr, sockw->timer.last.seq_num,
                       sockw->timer.last.ack_num, sockw->timer.last.flags);
            sockw->timer.uuid = addTimer(tp, TimeUtil::makeTime(100, TimeUtil::MSEC));
            break;

          default:
            break;
        }
      }
    }
  }
}

size_t TCPAssignment::sendData(UUID ufd, Socket &sock) {
  size_t data_sent = 0;
  while (sock.seq < sock.acked + sock.wnd and 
         sock.write_buf.size() > sock.seq - sock.acked)
  {
    size_t start_ptr = sock.seq - sock.acked;
    size_t msg_sz = std::min(std::min(512ul, sock.wnd - start_ptr),
                             sock.write_buf.size() - start_ptr);
    uint8_t datagram[msg_sz];
    for(int i=0; i<msg_sz; i++)
      datagram[i] = sock.write_buf[start_ptr + i];
    
  //std::cout<<sock.seq<<' '<<sock.acked<<' '<<sock.wnd<<' '<<(long long)sock.write_buf.size()<<std::endl;
  //std::cout<<" > "<<start_ptr<<' '<<msg_sz<<std::endl;
    shipPacket(sock.addr, sock.seq, 0, 0, msg_sz, datagram);
    sock.seq += msg_sz;
    data_sent += msg_sz;

    if(sock.tcp_timer.enabled) cancelTimer(sock.tcp_timer.uuid);
    sock.tcp_timer.enabled = true;
    sock.tcp_timer.uuid = addTimer(TimerPayload(ufd, sock.addr, true),
                              TimeUtil::makeTime(100, TimeUtil::MSEC));
  }
  sock.write.sent_size += data_sent;
  if (sock.write.waiting and sock.write.sent_size >= sock.write.data_size) {
    sock.write.waiting = false;
    sock.write.sent_size -= sock.write.data_size;
    returnSystemCall(sock.syscallUUID, sock.write.data_size);
  }
  // ADD TIMER HERE BRUV
  //std::cout<<"Total sent: "<<data_sent<<std::endl<<"---------"<<std::endl;
  return data_sent;
}

} // namespace E