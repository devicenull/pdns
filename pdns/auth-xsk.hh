#pragma once

#include "config.h"

#include <atomic>
#include <deque>
#include <memory>
#include <string>
#include <vector>

class DNSPacket;

#ifdef HAVE_XSK
#include "dnsdistdist/xsk.hh"
#include "iputils.hh"
#include "logging.hh"

class AuthXskResponse
{
public:
  AuthXskResponse(std::shared_ptr<XskWorker> worker, const XskPacket& packet);
  AuthXskResponse(const AuthXskResponse&) = delete;
  AuthXskResponse& operator=(const AuthXskResponse&) = delete;
  ~AuthXskResponse();

  bool send(const std::string& payload);
  void release();

private:
  std::shared_ptr<XskWorker> d_worker;
  XskPacket d_packet;
  std::atomic_bool d_consumed{false};
};

class AuthXskReceiver
{
public:
  explicit AuthXskReceiver(std::shared_ptr<XskWorker> worker);
  bool receive(DNSPacket& packet, std::string& buffer);
  [[nodiscard]] uint64_t getIncomingQueueSize() const;
  [[nodiscard]] uint64_t getOutgoingQueueSize() const;

private:
  std::shared_ptr<XskWorker> d_worker;
  std::deque<XskPacket> d_packets;
  std::atomic<uint64_t> d_bufferedPackets{0};
};

void setupAuthXsk(Logr::log_t slog);
void startAuthXskRouters();
const std::vector<std::shared_ptr<AuthXskReceiver>>& getAuthXskReceivers();
uint64_t authXskMetric(const std::string& metric);
bool authXskSendResponse(DNSPacket& packet);
bool authXskEnabled();

#else /* HAVE_XSK */

class AuthXskReceiver
{
public:
  bool receive(DNSPacket&, std::string&)
  {
    return false;
  }
};

#endif /* HAVE_XSK */
