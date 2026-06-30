#include "config.h"

#ifdef HAVE_XSK
#include "auth-xsk.hh"

#include <cerrno>
#include <cstring>
#include <set>
#include <thread>

#include "arguments.hh"
#include "auth-main.hh"
#include "dnspacket.hh"
#include "logger.hh"
#include "misc.hh"
#include "proxy-protocol.hh"
#include "responsestats.hh"
#include "threadname.hh"

namespace
{
std::vector<std::shared_ptr<XskSocket>> s_authXskSockets;
std::vector<std::shared_ptr<AuthXskReceiver>> s_authXskReceivers;

void accountXskCorruptPacket()
{
  S.inc("corrupt-packets");
  S.inc("xsk-corrupt-packets");
  S.inc("xsk-dropped-packets");
}

std::vector<ComboAddress> getConfiguredDestinations()
{
  std::vector<std::string> locals;
  stringtok(locals, ::arg()["local-address"], " ,");
  if (locals.empty()) {
    throw PDNSException("No local address specified for XSK");
  }

  std::vector<ComboAddress> destinations;
  destinations.reserve(locals.size());
  const auto defaultPort = ::arg().asNum("local-port");
  for (const auto& local : locals) {
    ComboAddress destination(local, defaultPort);
    if (IsAnyAddress(destination)) {
      throw PDNSException("XSK requires concrete local-address entries, not wildcard addresses like '" + local + "'");
    }
    destinations.push_back(destination);
  }

  return destinations;
}

void authXskRouter(const std::shared_ptr<XskSocket>& xsk)
{
  setThreadName("pdns/xskrouter");

  uint32_t failed = 0;
  std::vector<XskPacket> fillInTx;
  std::vector<XskPacket> packets;
  const auto& fds = xsk->getDescriptors();
  std::set<int> needNotify;

  for (;;) {
    try {
      auto ready = xsk->wait(-1);
      if (ready < 0) {
        if (errno == EINTR) {
          continue;
        }
        throw std::runtime_error("Unable to poll XSK descriptors: " + stringerror());
      }

      if ((fds.at(0).revents & POLLIN) != 0) {
        xsk->recv(packets, 64, &failed);
        if (failed > 0) {
          for (uint32_t counter = 0; counter < failed; ++counter) {
            accountXskCorruptPacket();
          }
        }

        for (auto& packet : packets) {
          auto worker = xsk->getWorkerByDestination(packet.getToAddr());
          if (!worker) {
            S.inc("xsk-dropped-packets");
            S.inc("xsk-no-route-packets");
            xsk->markAsFree(packet);
            continue;
          }
          worker->pushToProcessingQueue(packet);
          needNotify.insert(worker->workerWaker.getHandle());
        }

        for (auto descriptor : needNotify) {
          try {
            XskWorker::notify(descriptor);
          }
          catch (...) {
          }
        }
        needNotify.clear();
        --ready;
      }

      for (size_t fdIndex = 1; fdIndex < fds.size() && ready > 0; ++fdIndex) {
        if ((fds.at(fdIndex).revents & POLLIN) == 0) {
          continue;
        }
        --ready;
        const auto& worker = xsk->getWorkerByDescriptor(fds.at(fdIndex).fd);
        worker->processOutgoingFrames([&](XskPacket packet) {
          if ((packet.getFlags() & XskPacket::UPDATED) == 0) {
            xsk->markAsFree(packet);
            return;
          }
          if ((packet.getFlags() & XskPacket::DELAY) != 0) {
            xsk->pushDelayed(packet);
            return;
          }
          fillInTx.push_back(packet);
        });
        worker->cleanWorkerNotification();
      }

      xsk->pickUpReadyPacket(fillInTx);
      xsk->recycle(4096);
      xsk->fillFq();
      xsk->send(fillInTx);
    }
    catch (const std::exception& exp) {
      SLOG(g_log << Logger::Error << "Exception in XSK router loop: " << exp.what() << std::endl,
           g_slog->error(Logr::Error, exp.what(), "Exception in XSK router loop"));
    }
    catch (...) {
      SLOG(g_log << Logger::Error << "Unknown exception in XSK router loop" << std::endl,
           g_slog->info(Logr::Error, "Unknown exception in XSK router loop"));
    }
  }
}
}

AuthXskResponse::AuthXskResponse(std::shared_ptr<XskWorker> worker, const XskPacket& packet) :
  d_worker(std::move(worker)), d_packet(packet)
{
}

AuthXskResponse::~AuthXskResponse()
{
  release();
}

void AuthXskResponse::release()
{
  bool expected = false;
  if (d_worker && d_consumed.compare_exchange_strong(expected, true)) {
    d_worker->markAsFree(d_packet);
  }
}

bool AuthXskResponse::send(const std::string& payload)
{
  bool expected = false;
  if (!d_worker || !d_consumed.compare_exchange_strong(expected, true)) {
    return false;
  }

  PacketBuffer buffer(payload.size());
  if (!payload.empty()) {
    memcpy(buffer.data(), payload.data(), payload.size());
  }

  if (!d_packet.setPayload(buffer)) {
    d_worker->markAsFree(d_packet);
    return false;
  }

  d_packet.updatePacket();
  d_worker->pushToSendQueue(d_packet);
  d_worker->notifyXskSocket();
  return true;
}

AuthXskReceiver::AuthXskReceiver(std::shared_ptr<XskWorker> worker) :
  d_worker(std::move(worker))
{
}

bool AuthXskReceiver::receive(DNSPacket& packet, std::string& buffer)
{
  packet.d_xskResponse.reset();

  while (d_packets.empty()) {
    while (!d_worker->hasIncomingFrames()) {
      d_worker->waitForXskSocket();
    }
    d_worker->processIncomingFrames([&](XskPacket incoming) {
      d_packets.push_back(incoming);
      d_bufferedPackets.store(d_packets.size(), std::memory_order_relaxed);
    });
  }

  auto xskPacket = d_packets.front();
  d_packets.pop_front();
  d_bufferedPackets.store(d_packets.size(), std::memory_order_relaxed);

  const auto remote = xskPacket.getFromAddr();
  if (remote.sin4.sin_port == 0) {
    accountXskCorruptPacket();
    d_worker->markAsFree(xskPacket);
    return false;
  }

  const auto* payload = static_cast<const char*>(xskPacket.getPayloadData());
  buffer.assign(payload, payload + xskPacket.getDataLen());

  packet.setSocket(-1);
  packet.setRemote(&remote);
  packet.d_anyLocal = xskPacket.getToAddr();
  packet.d_dt.set();

  if (g_proxyProtocolACL.match(remote)) {
    ComboAddress psource;
    ComboAddress pdestination;
    bool proxyProto = false;
    bool tcp = false;
    std::vector<ProxyProtocolValue> ppvalues;

    ssize_t used = parseProxyHeader(buffer, proxyProto, psource, pdestination, tcp, ppvalues);
    if (used <= 0 || static_cast<size_t>(used) > g_proxyProtocolMaximumSize || (buffer.size() - used) > DNSPacket::s_udpTruncationThreshold) {
      accountXskCorruptPacket();
      S.ringAccount("remotes-corrupt", packet.d_remote);
      d_worker->markAsFree(xskPacket);
      return false;
    }
    buffer.erase(0, used);
    packet.d_inner_remote = psource;
    packet.d_tcp = tcp;
  }
  else {
    packet.d_inner_remote.reset();
  }

  if (packet.parse(buffer.data(), buffer.size()) < 0) {
    accountXskCorruptPacket();
    S.ringAccount("remotes-corrupt", packet.getInnerRemote());
    d_worker->markAsFree(xskPacket);
    return false;
  }

  packet.d_xskResponse = std::make_shared<AuthXskResponse>(d_worker, xskPacket);
  return true;
}

uint64_t AuthXskReceiver::getIncomingQueueSize() const
{
  return d_bufferedPackets.load(std::memory_order_relaxed) + d_worker->getIncomingQueueSize();
}

uint64_t AuthXskReceiver::getOutgoingQueueSize() const
{
  return d_worker->getOutgoingQueueSize();
}

void setupAuthXsk(Logr::log_t slog)
{
  if (!::arg().mustDo("xsk")) {
    return;
  }

  if (!s_authXskSockets.empty()) {
    return;
  }

  const auto ifName = ::arg()["xsk-interface"];
  if (ifName.empty()) {
    throw PDNSException("XSK is enabled but xsk-interface is empty");
  }

  const auto queues = ::arg().asNum("xsk-queues");
  if (queues <= 0) {
    throw PDNSException("XSK requires xsk-queues to be greater than zero");
  }

  const auto frames = ::arg().asNum("xsk-frames");
  if (frames <= 0) {
    throw PDNSException("XSK requires xsk-frames to be greater than zero");
  }

  const auto xskMapPath = ::arg()["xsk-map-path"];
  const auto destinationV4MapPath = ::arg()["xsk-destination-v4-map-path"];
  const auto destinationV6MapPath = ::arg()["xsk-destination-v6-map-path"];
  if (xskMapPath.empty() || destinationV4MapPath.empty() || destinationV6MapPath.empty()) {
    throw PDNSException("XSK map paths must not be empty");
  }

  auto destinations = getConfiguredDestinations();

  if (::arg().mustDo("xsk-clear-destination-maps")) {
    XskSocket::clearDestinationMap(destinationV4MapPath, false);
    XskSocket::clearDestinationMap(destinationV6MapPath, true);
  }

  for (const auto& destination : destinations) {
    XskSocket::addDestinationAddress(destination.isIPv6() ? destinationV6MapPath : destinationV4MapPath, destination);
  }

  for (int queueID = 0; queueID < queues; ++queueID) {
    auto socket = std::make_shared<XskSocket>(static_cast<size_t>(frames), ifName, static_cast<uint32_t>(queueID), xskMapPath);
    auto worker = XskWorker::create(XskWorker::Type::Bidirectional, socket->sharedEmptyFrameOffset);
    socket->addWorker(worker);

    for (const auto& destination : destinations) {
      socket->addWorkerRoute(worker, destination);
    }

    s_authXskReceivers.push_back(std::make_shared<AuthXskReceiver>(std::move(worker)));
    s_authXskSockets.push_back(std::move(socket));
  }

  SLOG(g_log << Logger::Warning << "Enabled XSK on interface " << ifName << " with " << queues << " queue(s)" << std::endl,
       slog->info(Logr::Warning, "Enabled XSK", "interface", Logging::Loggable(ifName), "queues", Logging::Loggable(queues)));
}

void startAuthXskRouters()
{
  for (const auto& socket : s_authXskSockets) {
    std::thread router(authXskRouter, socket);
    router.detach();
  }
}

const std::vector<std::shared_ptr<AuthXskReceiver>>& getAuthXskReceivers()
{
  return s_authXskReceivers;
}

uint64_t authXskMetric(const std::string& metric)
{
  if (metric == "xsk-sockets") {
    return s_authXskSockets.size();
  }

  if (metric == "xsk-receive-queue-size") {
    uint64_t total = 0;
    for (const auto& receiver : s_authXskReceivers) {
      total += receiver->getIncomingQueueSize();
    }
    return total;
  }

  if (metric == "xsk-send-queue-size") {
    uint64_t total = 0;
    for (const auto& receiver : s_authXskReceivers) {
      total += receiver->getOutgoingQueueSize();
    }
    return total;
  }

  uint64_t total = 0;
  for (const auto& socket : s_authXskSockets) {
    const auto stats = socket->getMetricsSnapshot();
    if (!stats.available) {
      if (metric == "xsk-kernel-metrics-unavailable") {
        ++total;
      }
      continue;
    }

    if (metric == "xsk-kernel-rx-dropped") {
      total += stats.rxDropped;
    }
    else if (metric == "xsk-kernel-rx-invalid-descs") {
      total += stats.rxInvalidDescs;
    }
    else if (metric == "xsk-kernel-tx-invalid-descs") {
      total += stats.txInvalidDescs;
    }
    else if (metric == "xsk-kernel-rx-ring-full") {
      total += stats.rxRingFull;
    }
    else if (metric == "xsk-kernel-rx-fill-ring-empty-descs") {
      total += stats.rxFillRingEmptyDescs;
    }
    else if (metric == "xsk-kernel-tx-ring-empty-descs") {
      total += stats.txRingEmptyDescs;
    }
  }

  return total;
}

bool authXskSendResponse(DNSPacket& packet)
{
  if (!packet.d_xskResponse) {
    return false;
  }

  const auto& payload = packet.getString();
  if (!packet.d_xskResponse->send(payload)) {
    S.inc("xsk-response-fallbacks");
    packet.d_xskResponse.reset();
    return false;
  }

  S.inc("xsk-answers");
  g_rs.submitResponse(packet, true);
  packet.d_xskResponse.reset();
  return true;
}

bool authXskEnabled()
{
  return !s_authXskReceivers.empty();
}

#endif /* HAVE_XSK */
