/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_

#include <E/E_Common.hpp>
#include <E/E_TimeUtil.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_TimerModule.hpp>
#include <arpa/inet.h>
#include <list>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <queue>
#include <random>
#include <deque>
#include <unordered_map>
#include <unordered_set>

#define FIN 1
#define SYN 2
#define ACK 16
#define GENSOL 15

namespace E {

enum StateTCP {
  CLOSED,
  LISTEN,
  SYN_SENT,
  SYN_RCVD,
  ESTABLISHED,
  CLOSE_WAIT,
  LAST_ACK,
  FIN_WAIT_1,
  FIN_WAIT_2,
  CLOSING,
  TIME_WAIT
};

enum SocketType { NULL_SOCKET, CLOSED_SOCKET, LISTEN_SOCKET, TCP_SOCKET };

struct PortTracker {
  bool usedForAll = false;
  std::unordered_set<uint32_t> usedIP;

  void add(uint32_t addr) {
    if (addr)
      usedIP.emplace(addr);
    else
      usedForAll = true;
  }

  void remove(uint32_t addr) {
    if (addr)
      usedIP.erase(addr);
    else
      usedForAll = false;
  }

  bool available(uint32_t addr) {
    if (usedForAll)
      return false;
    if (addr)
      return !usedIP.count(addr); // Non 0.0.0.0
    return !usedIP.size();
  }
};

struct TupleTCP {
  uint32_t srcAddr, destAddr;
  uint16_t srcPort, destPort;

  TupleTCP() {}

  TupleTCP(void *tcp_packet) { memcpy(this, tcp_packet, 12); }

  bool operator==(const TupleTCP &that) const {
    return srcAddr == that.srcAddr and destAddr == that.destAddr and
           srcPort == that.srcPort and destPort == that.destPort;
  }

  bool equalSrc(const TupleTCP &that) const {
    return (srcAddr == that.srcAddr or !srcAddr or !that.srcAddr) and
           srcPort == that.srcPort;
  }
  bool equalDest(const TupleTCP &that) const {
    return destAddr == that.destAddr and destPort == that.destPort;
  }
};

struct TupleHasherTCP {
  std::size_t operator()(const TupleTCP &tuple) const {
    return std::hash<uint32_t>()(tuple.srcAddr) ^
           std::hash<uint32_t>()(tuple.destAddr) ^
           std::hash<uint32_t>()((uint32_t)tuple.srcPort << 16 |
                                 tuple.destPort);
  }
};

struct Socket {
  SocketType type = NULL_SOCKET;

  /* Bind */
  TupleTCP addr;

  /* Listen */
  // TupleTCP addr;
  size_t backlog;
  std::list<Socket> waitlist;
  std::list<Socket> readyQueue;
  bool waiting = false;
  UUID syscallUUID;
  struct {
    sockaddr_in *addr;
    socklen_t *len;
  } acceptAddr;

  /* TCP State */
  // TupleTCP addr;
  StateTCP state;
  uint32_t seq, ack;
  uint16_t wnd;
  bool fined = false;
  // UUID syscallUUID;
  struct {
    bool enabled = false;
    struct {
      uint32_t seq_num;
      uint32_t ack_num;
      uint8_t flags;
    } last;
    UUID uuid;
  } timer;

  /* TCP Data */
  struct {
    bool waiting = false;
    uint8_t* ptr;
    int size;
  } read;
  std::deque<uint8_t> read_buf;

  struct {
    bool waiting = false;
    size_t data_size;
    size_t sent_size = 0;
  } write;
  uint32_t acked;
  std::deque<uint8_t> write_buf;

  struct {
    bool enabled = false;
    UUID uuid;
  } tcp_timer;
};

struct TimerPayload {
  uint64_t ufd;
  TupleTCP tuple;
  bool is_tcp;
  TimerPayload(uint64_t _ufd, TupleTCP _tuple) {
    ufd = _ufd;
    tuple = _tuple;
    is_tcp = false;
  }

  TimerPayload(uint64_t _ufd, TupleTCP _tuple, bool b) {
    ufd = _ufd;
    tuple = _tuple;
    is_tcp = b;
  }
};

class TCPAssignment : public HostModule,
                      private RoutingInfoInterface,
                      public SystemCallInterface,
                      public TimerModule {
private:
  virtual void timerCallback(std::any payload) final;

public:
  std::mt19937 rng = std::mt19937(69);

  PortTracker portMap[1 << 16];
  std::unordered_map<uint64_t, Socket> socketMap; // fd -> socket
  // std::unordered_map<TupleTCP, int, TupleHasherTCP> addrMap; //
  // tcpTuple/(dest=0 for listen) -> fd

  void err(std::string s);
  uint16_t assignPort(uint32_t addr, uint16_t port);
  uint16_t assignPort(uint32_t addr);
  uint32_t fixSrcAddr(uint32_t destAddr);
  uint32_t max(uint32_t a, uint32_t b);
  size_t sendData(UUID ufd, Socket &sock);

  void shipPacket(TupleTCP &addr, int seq_num, int ack_num, uint8_t flags, 
                  size_t data_size = 0, uint8_t *data = NULL,
                  uint16_t win_sz = 51200);

public:
  TCPAssignment(Host &host);
  virtual void initialize();
  virtual void finalize();
  virtual ~TCPAssignment();

protected:
  virtual void systemCallback(UUID syscallUUID, int pid,
                              const SystemCallParameter &param) final;
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;
};

class TCPAssignmentProvider {
private:
  TCPAssignmentProvider() {}
  ~TCPAssignmentProvider() {}

public:
  static void allocate(Host &host) { host.addHostModule<TCPAssignment>(host); }
};

} // namespace E

#endif /* E_TCPASSIGNMENT_HPP_ */