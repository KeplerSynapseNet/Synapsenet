#include "network/network.h"
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <array>
#include <cstring>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <fstream>
#include <random>
#include <cerrno>
#include "utils/logger.h"

namespace synapse {
namespace network {

namespace {

struct PeerRxState {
    std::vector<uint8_t> buffer;
    uint64_t windowStart = 0;
    uint64_t bytesInWindow = 0;
    uint64_t messagesInWindow = 0;
};

static constexpr size_t RX_BUFFER_LIMIT = MAX_MESSAGE_SIZE * 2;
static constexpr uint64_t RX_RATE_WINDOW_SECONDS = 1;
static constexpr uint64_t RX_MAX_BYTES_PER_WINDOW = MAX_MESSAGE_SIZE * 2;
static constexpr uint64_t RX_MAX_MESSAGES_PER_WINDOW = 500;

static bool setNonBlocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return false;
    return true;
}

static bool isValidCommand(const char command[12]) {
    for (size_t i = 0; i < 12; ++i) {
        unsigned char c = static_cast<unsigned char>(command[i]);
        if (c == 0) break;
        if (c < 32 || c > 126) return false;
    }
    return true;
}

}

std::vector<uint8_t> Message::serialize() const {
    std::vector<uint8_t> out;
    MessageHeader hdr{};
    hdr.magic = PROTOCOL_MAGIC;
    std::strncpy(hdr.command, command.c_str(), 12);
    hdr.length = payload.size();
    
    crypto::Hash256 hash = crypto::doubleSha256(payload.data(), payload.size());
    std::memcpy(&hdr.checksum, hash.data(), 4);
    
    out.resize(sizeof(MessageHeader) + payload.size());
    std::memcpy(out.data(), &hdr, sizeof(MessageHeader));
    std::memcpy(out.data() + sizeof(MessageHeader), payload.data(), payload.size());
    return out;
}

Message Message::deserialize(const std::vector<uint8_t>& data) {
    Message msg;
    if (data.size() < sizeof(MessageHeader)) return msg;
    
    MessageHeader hdr;
    std::memcpy(&hdr, data.data(), sizeof(MessageHeader));
    
    if (hdr.magic != PROTOCOL_MAGIC) return msg;
    if (hdr.length > MAX_MESSAGE_SIZE) return msg;
    if (data.size() < sizeof(MessageHeader) + hdr.length) return msg;
    
    msg.command = std::string(hdr.command, strnlen(hdr.command, 12));
    msg.payload.assign(data.begin() + sizeof(MessageHeader), 
                       data.begin() + sizeof(MessageHeader) + hdr.length);
    
    crypto::Hash256 hash = crypto::doubleSha256(msg.payload.data(), msg.payload.size());
    uint32_t checksum;
    std::memcpy(&checksum, hash.data(), 4);
    if (checksum != hdr.checksum) {
        msg.command.clear();
        msg.payload.clear();
    }
    
    return msg;
}

struct Network::Impl {
    std::unordered_map<std::string, Peer> peers;
    std::unordered_map<std::string, uint64_t> bannedPeers;
    std::unordered_map<std::string, PeerRxState> rx;
    mutable std::mutex mtx;
    std::atomic<bool> running{false};
    uint16_t port = 0;
    int listenSocket = -1;
    std::thread acceptThread;
    std::thread recvThread;
    NetworkConfig config;
    uint64_t startTime = 0;
    uint64_t bytesSent = 0;
    uint64_t bytesReceived = 0;
    uint64_t messagesSent = 0;
    uint64_t messagesReceived = 0;
    
    std::function<void(const std::string&, const Message&)> messageHandler;
    std::function<void(const Peer&)> connectHandler;
    std::function<void(const Peer&)> disconnectHandler;
    
    void acceptLoop();
    void recvLoop();
    bool sendRaw(int sock, const std::vector<uint8_t>& data);
};

void Network::Impl::acceptLoop() {
    while (running) {
        struct pollfd pfd;
        pfd.fd = listenSocket;
        pfd.events = POLLIN;
        
        if (poll(&pfd, 1, 100) <= 0) continue;
        
        struct sockaddr_in clientAddr;
        socklen_t addrLen = sizeof(clientAddr);
        int clientSock = accept(listenSocket, (struct sockaddr*)&clientAddr, &addrLen);
        
        if (clientSock < 0) continue;

        setNonBlocking(clientSock);
        
        std::string addr = inet_ntoa(clientAddr.sin_addr);
        uint16_t clientPort = ntohs(clientAddr.sin_port);
        std::string peerId = addr + ":" + std::to_string(clientPort);
        
        Peer peer;
        bool accepted = false;
        {
            std::lock_guard<std::mutex> lock(mtx);

            auto banIt = bannedPeers.find(addr);
            if (banIt != bannedPeers.end()) {
                if (std::time(nullptr) < static_cast<time_t>(banIt->second)) {
                    close(clientSock);
                    continue;
                }
                bannedPeers.erase(banIt);
            }

            if (peers.size() >= config.maxPeers) {
                close(clientSock);
                continue;
            }

            size_t inboundCount = 0;
            for (const auto& kv : peers) {
                if (!kv.second.isOutbound) inboundCount++;
            }
            if (inboundCount >= config.maxInbound) {
                close(clientSock);
                continue;
            }

            peer.id = peerId;
            peer.address = addr;
            peer.port = clientPort;
            peer.connectedAt = std::time(nullptr);
            peer.lastSeen = peer.connectedAt;
            peer.bytesRecv = 0;
            peer.bytesSent = 0;
            peer.version = 0;
            peer.startHeight = 0;
            peer.isOutbound = false;
            peer.state = PeerState::CONNECTED;
            peer.socket = clientSock;

            peers[peerId] = peer;
            rx[peerId] = PeerRxState{};
            accepted = true;
        }
        if (accepted && connectHandler) connectHandler(peer);
    }
}

void Network::Impl::recvLoop() {
    while (running) {
        std::vector<struct pollfd> fds;
        std::vector<std::string> peerIds;
        
        {
            std::lock_guard<std::mutex> lock(mtx);
            for (auto& [id, peer] : peers) {
                if (peer.state == PeerState::CONNECTED && peer.socket >= 0) {
                    struct pollfd pfd;
                    pfd.fd = peer.socket;
                    pfd.events = POLLIN;
                    fds.push_back(pfd);
                    peerIds.push_back(id);
                }
            }
        }
        
        if (fds.empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        
        int ret = poll(fds.data(), fds.size(), 100);
        if (ret <= 0) continue;
        
        for (size_t i = 0; i < fds.size(); i++) {
            if (fds[i].revents & (POLLHUP | POLLERR | POLLNVAL)) {
                std::lock_guard<std::mutex> lock(mtx);
                auto it = peers.find(peerIds[i]);
                if (it != peers.end()) {
                    Peer peer = it->second;
                    if (it->second.socket >= 0) close(it->second.socket);
                    peers.erase(it);
                    rx.erase(peer.id);
                    if (disconnectHandler) disconnectHandler(peer);
                }
                continue;
            }
            if (!(fds[i].revents & POLLIN)) continue;

            std::vector<Message> decoded;
            decoded.reserve(4);
            uint64_t now = std::time(nullptr);
            bool shouldBan = false;
            std::string banReason;
            uint32_t banSeconds = 86400;

            {
                std::lock_guard<std::mutex> lock(mtx);
                auto pit = peers.find(peerIds[i]);
                if (pit == peers.end()) continue;

                auto& peer = pit->second;
                auto& st = rx[peerIds[i]];

                if (st.windowStart == 0) st.windowStart = now;
                if (now >= st.windowStart + RX_RATE_WINDOW_SECONDS) {
                    st.windowStart = now;
                    st.bytesInWindow = 0;
                    st.messagesInWindow = 0;
                }

                std::array<uint8_t, 64 * 1024> tmp{};
                for (;;) {
                    ssize_t n = ::recv(peer.socket, tmp.data(), tmp.size(), 0);
                    if (n > 0) {
                        peer.lastSeen = now;
                        peer.bytesRecv += static_cast<uint64_t>(n);
                        bytesReceived += static_cast<uint64_t>(n);
                        st.bytesInWindow += static_cast<uint64_t>(n);
                        if (st.bytesInWindow > RX_MAX_BYTES_PER_WINDOW) {
                            shouldBan = true;
                            banReason = "rate_bytes";
                            break;
                        }
                        if (st.buffer.size() + static_cast<size_t>(n) > RX_BUFFER_LIMIT) {
                            shouldBan = true;
                            banReason = "rx_buffer_overflow";
                            break;
                        }
                        st.buffer.insert(st.buffer.end(), tmp.data(), tmp.data() + n);
                        continue;
                    }
                    if (n == 0) {
                        shouldBan = false;
                        banReason = "disconnect";
                        break;
                    }
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        break;
                    }
                    shouldBan = true;
                    banReason = "recv_error";
                    break;
                }

                if (banReason == "disconnect") {
                    Peer gone = peer;
                    if (peer.socket >= 0) close(peer.socket);
                    peers.erase(pit);
                    rx.erase(gone.id);
                    if (disconnectHandler) disconnectHandler(gone);
                    continue;
                }

                if (!shouldBan) {
                    size_t consumed = 0;
                    while (st.buffer.size() - consumed >= sizeof(MessageHeader)) {
                        MessageHeader hdr{};
                        std::memcpy(&hdr, st.buffer.data() + consumed, sizeof(MessageHeader));
                        if (hdr.magic != PROTOCOL_MAGIC) {
                            shouldBan = true;
                            banReason = "bad_magic";
                            break;
                        }
                        if (!isValidCommand(hdr.command)) {
                            shouldBan = true;
                            banReason = "bad_command";
                            break;
                        }
                        if (hdr.length > MAX_MESSAGE_SIZE) {
                            shouldBan = true;
                            banReason = "too_large";
                            break;
                        }
                        const size_t total = sizeof(MessageHeader) + static_cast<size_t>(hdr.length);
                        if (st.buffer.size() - consumed < total) break;

                        std::vector<uint8_t> frame;
                        frame.insert(frame.end(),
                                     st.buffer.begin() + static_cast<std::ptrdiff_t>(consumed),
                                     st.buffer.begin() + static_cast<std::ptrdiff_t>(consumed + total));
                        consumed += total;

                        Message msg = Message::deserialize(frame);
                        if (!msg.command.empty()) {
                            msg.from = peer.id;
                            msg.timestamp = now;
                            decoded.push_back(std::move(msg));
                            messagesReceived += 1;
                            st.messagesInWindow += 1;
                            if (st.messagesInWindow > RX_MAX_MESSAGES_PER_WINDOW) {
                                shouldBan = true;
                                banReason = "rate_msgs";
                                break;
                            }
                        } else {
                            shouldBan = true;
                            banReason = "bad_checksum";
                            break;
                        }
                    }
                    if (consumed > 0) {
                        st.buffer.erase(st.buffer.begin(), st.buffer.begin() + static_cast<std::ptrdiff_t>(consumed));
                    }
                }

                if (shouldBan) {
                    Peer gone = peer;
                    bannedPeers[gone.address] = std::time(nullptr) + banSeconds;
                    if (peer.socket >= 0) close(peer.socket);
                    peers.erase(pit);
                    rx.erase(gone.id);
                    if (disconnectHandler) disconnectHandler(gone);
                }
            }

            if (!decoded.empty() && messageHandler) {
                for (auto& msg : decoded) {
                    messageHandler(peerIds[i], msg);
                }
            }
        }
    }
}

bool Network::Impl::sendRaw(int sock, const std::vector<uint8_t>& data) {
    size_t sent = 0;
    while (sent < data.size()) {
        ssize_t n = ::send(sock, data.data() + sent, data.size() - sent, 0);
        if (n > 0) {
            sent += static_cast<size_t>(n);
            continue;
        }
        if (n == 0) return false;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            struct pollfd pfd;
            pfd.fd = sock;
            pfd.events = POLLOUT;
            int pr = poll(&pfd, 1, 250);
            if (pr <= 0) return false;
            continue;
        }
        return false;
    }
    bytesSent += data.size();
    messagesSent++;
    return true;
}

Network::Network() : impl_(std::make_unique<Impl>()) {}

Network::~Network() { stop(); }

bool Network::start(uint16_t port) {
    if (impl_->running) return false;
    
    std::vector<uint16_t> portsToTry = {port, 8334, 8335, 8336, 8337, 8338, 8339, 8340, 18333, 28333, 38333, 48333};
    
    for (uint16_t tryPort : portsToTry) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
        setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
        int flags = fcntl(sock, F_GETFL, 0);
        if (flags >= 0) fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(tryPort);
        
        if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0 && listen(sock, 10) == 0) {
            impl_->listenSocket = sock;
            impl_->port = tryPort;
            impl_->running = true;
            impl_->startTime = std::time(nullptr);
            impl_->acceptThread = std::thread(&Impl::acceptLoop, impl_.get());
            impl_->recvThread = std::thread(&Impl::recvLoop, impl_.get());
            utils::Logger::info("Network listening on port " + std::to_string(tryPort));
            return true;
        }
        int err = errno;
        utils::Logger::warn("Failed to bind/listen on port " + std::to_string(tryPort) + " errno=" + std::to_string(err));
        close(sock);
    }
    
    impl_->port = 0;
    impl_->listenSocket = -1;
    utils::Logger::error("Network failed to bind any port");
    return false;
}

void Network::stop() {
    if (!impl_->running) return;
    
    impl_->running = false;
    
    int ls = impl_->listenSocket;
    if (ls >= 0) {
        shutdown(ls, SHUT_RDWR);
        close(ls);
        impl_->listenSocket = -1;
    }
    
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        for (auto& [id, peer] : impl_->peers) {
            if (peer.socket >= 0) {
                shutdown(peer.socket, SHUT_RDWR);
                close(peer.socket);
                peer.socket = -1;
            }
        }
        impl_->peers.clear();
        impl_->rx.clear();
    }
    
    if (impl_->acceptThread.joinable()) impl_->acceptThread.join();
    if (impl_->recvThread.joinable()) impl_->recvThread.join();
    impl_->port = 0;
}

bool Network::isRunning() const {
    return impl_->running;
}

bool Network::connect(const std::string& address, uint16_t port) {
    std::string peerId = address + ":" + std::to_string(port);
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        auto banIt = impl_->bannedPeers.find(address);
        if (banIt != impl_->bannedPeers.end() && std::time(nullptr) < static_cast<time_t>(banIt->second)) {
            return false;
        }
        if (impl_->peers.find(peerId) != impl_->peers.end()) {
            return true;
        }
    }
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, address.c_str(), &addr.sin_addr) <= 0) {
        // Fallback: resolve hostname to IPv4
        struct addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        struct addrinfo* res = nullptr;
        if (getaddrinfo(address.c_str(), nullptr, &hints, &res) != 0 || !res) {
            close(sock);
            return false;
        }
        // Take first IPv4
        struct sockaddr_in* ipv4 = reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
        addr.sin_addr = ipv4->sin_addr;
        freeaddrinfo(res);
    }
    
    if (::connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return false;
    }

    setNonBlocking(sock);
    
    Peer peer;
    peer.id = peerId;
    peer.address = address;
    peer.port = port;
    peer.connectedAt = std::time(nullptr);
    peer.lastSeen = peer.connectedAt;
    peer.bytesRecv = 0;
    peer.bytesSent = 0;
    peer.version = 0;
    peer.startHeight = 0;
    peer.isOutbound = true;
    peer.state = PeerState::CONNECTED;
    peer.socket = sock;

    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        size_t outboundCount = 0;
        for (const auto& kv : impl_->peers) {
            if (kv.second.isOutbound) outboundCount++;
        }
        if (outboundCount >= impl_->config.maxOutbound) {
            close(sock);
            return false;
        }
        impl_->peers[peerId] = peer;
        impl_->rx[peerId] = PeerRxState{};
    }
    if (impl_->connectHandler) impl_->connectHandler(peer);
    return true;
}

void Network::disconnect(const std::string& peerId) {
    Peer peer;
    bool removed = false;
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        auto it = impl_->peers.find(peerId);
        if (it != impl_->peers.end()) {
            peer = it->second;
            if (it->second.socket >= 0) close(it->second.socket);
            impl_->peers.erase(it);
            impl_->rx.erase(peerId);
            removed = true;
        }
    }
    if (removed && impl_->disconnectHandler) impl_->disconnectHandler(peer);
}

void Network::ban(const std::string& peerId, uint32_t seconds) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    auto it = impl_->peers.find(peerId);
    if (it != impl_->peers.end()) {
        impl_->bannedPeers[it->second.address] = std::time(nullptr) + seconds;
        if (it->second.socket >= 0) close(it->second.socket);
        impl_->peers.erase(it);
        impl_->rx.erase(peerId);
    }
}

bool Network::broadcast(const Message& msg) {
    std::vector<uint8_t> data = msg.serialize();
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    for (auto& [id, peer] : impl_->peers) {
        if (peer.state == PeerState::CONNECTED && peer.socket >= 0) {
            if (impl_->sendRaw(peer.socket, data)) {
                peer.bytesSent += data.size();
            }
        }
    }
    return true;
}

bool Network::send(const std::string& peerId, const Message& msg) {
    std::vector<uint8_t> data = msg.serialize();
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    auto it = impl_->peers.find(peerId);
    if (it == impl_->peers.end()) return false;
    if (it->second.state != PeerState::CONNECTED) return false;
    if (it->second.socket < 0) return false;
    
    if (impl_->sendRaw(it->second.socket, data)) {
        it->second.bytesSent += data.size();
        return true;
    }
    return false;
}

std::vector<Peer> Network::getPeers() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    std::vector<Peer> result;
    for (const auto& [id, peer] : impl_->peers) {
        result.push_back(peer);
    }
    return result;
}

Peer Network::getPeer(const std::string& peerId) const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    auto it = impl_->peers.find(peerId);
    if (it != impl_->peers.end()) return it->second;
    return Peer{};
}

size_t Network::peerCount() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->peers.size();
}

size_t Network::outboundCount() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    size_t count = 0;
    for (const auto& [id, peer] : impl_->peers) {
        if (peer.isOutbound) count++;
    }
    return count;
}

void Network::onMessage(std::function<void(const std::string&, const Message&)> handler) {
    impl_->messageHandler = handler;
}

void Network::onPeerConnected(std::function<void(const Peer&)> handler) {
    impl_->connectHandler = handler;
}

void Network::onPeerDisconnected(std::function<void(const Peer&)> handler) {
    impl_->disconnectHandler = handler;
}

uint16_t Network::getPort() const {
    return impl_->port;
}

std::string Network::getLocalAddress() const {
    return "0.0.0.0";
}

NetworkStats Network::getStats() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    NetworkStats stats{};
    stats.totalPeers = impl_->peers.size();
    stats.inboundPeers = 0;
    stats.outboundPeers = 0;
    stats.bytesSent = impl_->bytesSent;
    stats.bytesReceived = impl_->bytesReceived;
    stats.messagesSent = impl_->messagesSent;
    stats.messagesReceived = impl_->messagesReceived;
    stats.uptime = std::time(nullptr) - impl_->startTime;
    
    for (const auto& [id, peer] : impl_->peers) {
        if (peer.isOutbound) stats.outboundPeers++;
        else stats.inboundPeers++;
    }
    return stats;
}

void Network::setMaxPeers(uint32_t max) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->config.maxPeers = max;
}

void Network::setMaxInbound(uint32_t max) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->config.maxInbound = max;
}

void Network::setMaxOutbound(uint32_t max) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->config.maxOutbound = max;
}

bool Network::banPeer(const std::string& peerId, uint32_t duration) {
    ban(peerId, duration);
    return true;
}

bool Network::unbanPeer(const std::string& peerId) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->bannedPeers.erase(peerId);
    return true;
}

bool Network::isBanned(const std::string& peerId) const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    auto it = impl_->bannedPeers.find(peerId);
    if (it == impl_->bannedPeers.end()) return false;
    return std::time(nullptr) < static_cast<time_t>(it->second);
}

std::vector<std::string> Network::getBannedPeers() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    std::vector<std::string> result;
    uint64_t now = std::time(nullptr);
    for (const auto& [id, until] : impl_->bannedPeers) {
        if (now < until) result.push_back(id);
    }
    return result;
}

void Network::setConfig(const NetworkConfig& config) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->config = config;
}

NetworkConfig Network::getConfig() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->config;
}

bool Network::isConnected() const {
    return impl_->running && peerCount() > 0;
}

void Network::ping(const std::string& peerId) {
    Message msg;
    msg.type = MessageType::PING;
    msg.command = "ping";
    msg.timestamp = std::time(nullptr);
    uint64_t nonce = (static_cast<uint64_t>(std::random_device{}()) << 32) | std::random_device{}();
    msg.payload.resize(8);
    for (int i = 0; i < 8; i++) {
        msg.payload[i] = static_cast<uint8_t>((nonce >> (i * 8)) & 0xff);
    }
    send(peerId, msg);
}

void Network::pingAll() {
    std::vector<std::string> ids;
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        for (const auto& [id, peer] : impl_->peers) {
            ids.push_back(id);
        }
    }
    for (const auto& id : ids) {
        ping(id);
    }
}

}
}
