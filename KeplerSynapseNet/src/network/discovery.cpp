#include "network/discovery.h"
#include "infrastructure/messages.h"
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <thread>
#include <atomic>
#include <random>
#include <algorithm>
#include <ctime>
#include <fstream>
#include <sstream>
#include <netdb.h>
#include <arpa/inet.h>

namespace synapse {
namespace network {

struct Discovery::Impl {
    std::vector<BootstrapNode> bootstrapNodes;
    std::vector<std::string> dnsSeeds;
    std::unordered_map<std::string, PeerInfo> knownPeers;
    std::unordered_set<std::string> bannedPeers;
    std::unordered_set<std::string> triedPeers;
    DiscoveryConfig config;
    mutable std::mutex mtx;
    std::atomic<bool> running{false};
    uint16_t localPort = 0;
    std::thread refreshThread;
    std::function<void(const PeerInfo&)> discoveredCallback;
    std::function<void(const std::string&)> lostCallback;
    std::function<bool(const std::string& peerId, const std::string& command, const std::vector<uint8_t>& payload)> sendMessageCallback;
    std::function<std::vector<std::string>()> getConnectedPeersCallback;
    std::mt19937 rng{std::random_device{}()};
    uint64_t startTime = 0;
    uint64_t totalDiscovered = 0;
    uint64_t totalConnected = 0;
    uint64_t totalFailed = 0;
    uint64_t dnsQueries = 0;
    uint64_t peerExchanges = 0;
    uint64_t peerExchangeSuccesses = 0;
    uint64_t lastPeerRefresh = 0;
    uint64_t lastAnnounceTime = 0;
    std::unordered_map<std::string, uint64_t> lastGetPeersRequest; // peerId -> timestamp
    std::string externalAddress;
    uint64_t estimatedNetworkSize = 0; // Cached estimate
    
    void refreshLoop();
    std::vector<std::string> resolveDNS(const std::string& hostname);
    uint64_t estimateNetworkSize() const;
};

void Discovery::Impl::refreshLoop() {
    uint64_t lastRefresh = 0;
    
    while (running) {
        uint64_t now = std::time(nullptr);
        
        if (config.enableDNS && now - lastRefresh > config.refreshInterval) {
            for (const auto& seed : dnsSeeds) {
                auto addrs = resolveDNS(seed);
                dnsQueries++;
                std::lock_guard<std::mutex> lock(mtx);
                uint16_t seedPort = localPort;
                for (const auto& bn : bootstrapNodes) {
                    if (bn.address == seed) {
                        seedPort = bn.port;
                        break;
                    }
                }
                for (const auto& addr : addrs) {
                    if (knownPeers.size() >= config.maxKnownPeers) break;
                    PeerInfo info{};
                    info.address = addr;
                    info.port = seedPort;
                    info.timestamp = now;
                    info.lastSeen = now;
                    info.services = 1;
                    info.state = DiscoveryPeerState::UNKNOWN;
                    info.attempts = 0;
                    std::string key = addr + ":" + std::to_string(info.port);
                    if (knownPeers.find(key) == knownPeers.end()) {
                        knownPeers[key] = info;
                        totalDiscovered++;
                        if (discoveredCallback) discoveredCallback(info);
                    }
                }
            }
            lastRefresh = now;
        }
        
        // Peer exchange refresh
        {
            std::lock_guard<std::mutex> lock(mtx);
            if (config.enablePeerExchange && now - lastPeerRefresh > config.discoveryInterval) {
                if (sendMessageCallback && getConnectedPeersCallback) {
                    auto connectedPeers = getConnectedPeersCallback();
                    for (const auto& peerId : connectedPeers) {
                        // Rate limiting: max 1 request per minute per peer
                        auto it = lastGetPeersRequest.find(peerId);
                        if (it != lastGetPeersRequest.end() && now - it->second < 60) {
                            continue; // Skip if requested too recently
                        }
                        lastGetPeersRequest[peerId] = now;
                        sendMessageCallback(peerId, "getpeers", {});
                    }
                    lastPeerRefresh = now;
                }
            }
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

uint64_t Discovery::Impl::estimateNetworkSize() const {
    // Simple estimation algorithm: known peers * average connectivity factor
    // This is a heuristic - real network size estimation is complex
    size_t known = knownPeers.size();
    if (known == 0) return 0;
    
    // Each peer knows on average some number of other peers
    // Use a conservative estimate: known peers * 2 (each peer knows ~2 others on average)
    // This is a very rough estimate and will be refined as network grows
    uint64_t estimate = static_cast<uint64_t>(known) * 2;
    
    // Cap estimate to reasonable maximum (avoid unrealistic numbers)
    if (estimate > 1000000) estimate = 1000000;
    
    return estimate;
}

std::vector<std::string> Discovery::Impl::resolveDNS(const std::string& hostname) {
    std::vector<std::string> results;
    struct addrinfo hints{}, *res, *p;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(hostname.c_str(), nullptr, &hints, &res) != 0) {
        return results;
    }
    
    for (p = res; p != nullptr; p = p->ai_next) {
        struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
        char ipstr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ipv4->sin_addr), ipstr, sizeof(ipstr));
        results.push_back(ipstr);
    }
    
    freeaddrinfo(res);
    return results;
}

Discovery::Discovery() : impl_(std::make_unique<Impl>()) {}
Discovery::~Discovery() { stop(); }

bool Discovery::start(uint16_t localPort) {
    if (impl_->running) return false;
    impl_->localPort = localPort;
    impl_->running = true;
    impl_->startTime = std::time(nullptr);
    impl_->refreshThread = std::thread(&Discovery::Impl::refreshLoop, impl_.get());
    return true;
}

void Discovery::stop() {
    impl_->running = false;
    if (impl_->refreshThread.joinable()) {
        impl_->refreshThread.join();
    }
}

bool Discovery::isRunning() const {
    return impl_->running;
}

void Discovery::setConfig(const DiscoveryConfig& config) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->config = config;
}

DiscoveryConfig Discovery::getConfig() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->config;
}

void Discovery::addBootstrap(const std::string& address, uint16_t port) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    BootstrapNode node;
    node.address = address;
    node.port = port;
    node.lastSeen = 0;
    node.failures = 0;
    node.active = true;
    impl_->bootstrapNodes.push_back(node);
    
    PeerInfo info{};
    info.address = address;
    info.port = port;
    info.timestamp = std::time(nullptr);
    info.lastSeen = info.timestamp;
    info.services = 1;
    info.state = DiscoveryPeerState::UNKNOWN;
    info.attempts = 0;
    std::string key = address + ":" + std::to_string(port);
    impl_->knownPeers[key] = info;
}

void Discovery::addDnsSeed(const std::string& hostname) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->dnsSeeds.push_back(hostname);
}

void Discovery::addPeer(const PeerInfo& peer) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (impl_->knownPeers.size() >= impl_->config.maxKnownPeers) return;
    std::string key = peer.address + ":" + std::to_string(peer.port);
    impl_->knownPeers[key] = peer;
    impl_->totalDiscovered++;
}

void Discovery::addKnownPeer(const PeerInfo& peer) {
    addPeer(peer);
}

void Discovery::removePeer(const std::string& address) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    for (auto it = impl_->knownPeers.begin(); it != impl_->knownPeers.end(); ) {
        if (it->second.address == address) {
            it = impl_->knownPeers.erase(it);
        } else {
            ++it;
        }
    }
}

void Discovery::markPeerFailed(const std::string& address) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    for (auto& [key, peer] : impl_->knownPeers) {
        if (peer.address == address) {
            peer.attempts++;
            impl_->totalFailed++;
            if (peer.attempts >= impl_->config.maxFailures) {
                peer.state = DiscoveryPeerState::DISCONNECTED;
            }
            break;
        }
    }
}

void Discovery::markPeerSuccess(const std::string& address) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    for (auto& [key, peer] : impl_->knownPeers) {
        if (peer.address == address) {
            peer.attempts = 0;
            peer.lastSeen = std::time(nullptr);
            peer.state = DiscoveryPeerState::CONNECTED;
            impl_->totalConnected++;
            break;
        }
    }
}

void Discovery::banPeer(const std::string& address) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->bannedPeers.insert(address);
}

void Discovery::unbanPeer(const std::string& address) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->bannedPeers.erase(address);
}

bool Discovery::isBanned(const std::string& address) const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->bannedPeers.count(address) > 0;
}

std::vector<std::string> Discovery::getBannedPeers() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return std::vector<std::string>(impl_->bannedPeers.begin(), impl_->bannedPeers.end());
}

std::vector<BootstrapNode> Discovery::getBootstrapNodes() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->bootstrapNodes;
}

std::vector<std::string> Discovery::getDnsSeeds() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->dnsSeeds;
}

std::vector<PeerInfo> Discovery::getKnownPeers(size_t limit) const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    std::vector<PeerInfo> result;
    for (const auto& [key, peer] : impl_->knownPeers) {
        if (result.size() >= limit) break;
        result.push_back(peer);
    }
    return result;
}

std::vector<PeerInfo> Discovery::getRandomPeers(size_t count) const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    std::vector<PeerInfo> all;
    for (const auto& [key, peer] : impl_->knownPeers) {
        all.push_back(peer);
    }
    std::shuffle(all.begin(), all.end(), impl_->rng);
    if (all.size() > count) all.resize(count);
    return all;
}

std::vector<std::string> Discovery::discoverPeers(size_t count) {
    std::vector<std::string> result;
    auto peers = getRandomPeers(count);
    for (const auto& peer : peers) {
        result.push_back(peer.address + ":" + std::to_string(peer.port));
    }
    return result;
}

PeerInfo Discovery::getPeer(const std::string& address) const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    for (const auto& [key, peer] : impl_->knownPeers) {
        if (peer.address == address) return peer;
    }
    return PeerInfo{};
}

bool Discovery::hasPeer(const std::string& address) const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    for (const auto& [key, peer] : impl_->knownPeers) {
        if (peer.address == address) return true;
    }
    return false;
}

void Discovery::refreshFromDNS() {
    for (const auto& seed : impl_->dnsSeeds) {
        auto addrs = impl_->resolveDNS(seed);
        impl_->dnsQueries++;
        std::lock_guard<std::mutex> lock(impl_->mtx);
        uint16_t seedPort = impl_->localPort;
        for (const auto& bn : impl_->bootstrapNodes) {
            if (bn.address == seed) {
                seedPort = bn.port;
                break;
            }
        }
        for (const auto& addr : addrs) {
            if (impl_->knownPeers.size() >= impl_->config.maxKnownPeers) break;
            PeerInfo info{};
            info.address = addr;
            info.port = seedPort;
            info.timestamp = std::time(nullptr);
            info.lastSeen = info.timestamp;
            info.state = DiscoveryPeerState::UNKNOWN;
            std::string key = addr + ":" + std::to_string(info.port);
            if (impl_->knownPeers.find(key) == impl_->knownPeers.end()) {
                impl_->knownPeers[key] = info;
                impl_->totalDiscovered++;
            }
        }
    }
}

void Discovery::refreshFromPeers() {
    if (!impl_->sendMessageCallback || !impl_->getConnectedPeersCallback) {
        impl_->peerExchanges++;
        return;
    }
    
    uint64_t now = std::time(nullptr);
    auto connectedPeers = impl_->getConnectedPeersCallback();
    size_t successCount = 0;
    
    for (const auto& peerId : connectedPeers) {
        // Rate limiting: max 1 request per minute per peer
        {
            std::lock_guard<std::mutex> lock(impl_->mtx);
            auto it = impl_->lastGetPeersRequest.find(peerId);
            if (it != impl_->lastGetPeersRequest.end() && now - it->second < 60) {
                continue; // Skip if requested too recently
            }
            impl_->lastGetPeersRequest[peerId] = now;
        }
        
        // Send GETPEERS request
        if (impl_->sendMessageCallback(peerId, "getpeers", {})) {
            successCount++;
        }
    }
    
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        impl_->peerExchanges++;
        impl_->peerExchangeSuccesses += successCount;
        impl_->lastPeerRefresh = now;
    }
}

void Discovery::announce() {
    if (!impl_->sendMessageCallback || !impl_->getConnectedPeersCallback) {
        return;
    }
    
    auto connectedPeers = impl_->getConnectedPeersCallback();
    if (connectedPeers.empty()) {
        return;
    }
    
    // Get our external address
    std::string ourAddr = impl_->externalAddress;
    if (ourAddr.empty()) {
        // Fallback: use 0.0.0.0 as indicator that we don't know our external IP
        // Peers will see this and can potentially help us discover it
        ourAddr = "0.0.0.0";
    }
    
    // Create PEERS message with ourselves
    synapse::PeersMessage peersMsg;
    synapse::PeerAddress selfAddr{};
    selfAddr.services = 1;
    selfAddr.port = impl_->localPort;
    selfAddr.timestamp = std::time(nullptr);
    selfAddr.addr.fill(0);
    
    // Convert IP string to binary format (IPv4 mapped to IPv6)
    in_addr ipv4{};
    if (ourAddr != "0.0.0.0" && inet_pton(AF_INET, ourAddr.c_str(), &ipv4) == 1) {
        selfAddr.addr[10] = 0xff;
        selfAddr.addr[11] = 0xff;
        std::memcpy(selfAddr.addr.data() + 12, &ipv4, 4);
        peersMsg.peers.push_back(selfAddr);
    } else {
        // If address is not valid or is 0.0.0.0, skip announce
        // (We don't know our external IP yet)
        return;
    }
    
    auto payload = peersMsg.serialize();
    
    // Send to all connected peers
    for (const auto& peerId : connectedPeers) {
        impl_->sendMessageCallback(peerId, "peers", payload);
    }
    
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        impl_->lastAnnounceTime = std::time(nullptr);
    }
}

void Discovery::processIncoming(const std::vector<PeerInfo>& peers) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    uint64_t now = std::time(nullptr);
    
    for (const auto& peer : peers) {
        // Validate peer address
        if (peer.address.empty() || peer.port == 0) continue;
        
        // Skip localhost addresses
        if (peer.address == "127.0.0.1" || peer.address == "::1" || 
            peer.address == "localhost" || peer.address.find("127.") == 0) {
            continue;
        }
        
        // Skip banned peers
        std::string key = peer.address + ":" + std::to_string(peer.port);
        if (impl_->bannedPeers.count(peer.address) > 0) {
            continue;
        }
        
        // Skip if we already know this peer
        if (impl_->knownPeers.find(key) != impl_->knownPeers.end()) {
            // Update lastSeen if peer is already known
            impl_->knownPeers[key].lastSeen = now;
            continue;
        }
        
        // Check if we've reached max peers
        if (impl_->knownPeers.size() >= impl_->config.maxKnownPeers) break;
        
        // Add new peer
        PeerInfo newPeer = peer;
        if (newPeer.timestamp == 0) newPeer.timestamp = now;
        if (newPeer.lastSeen == 0) newPeer.lastSeen = now;
        impl_->knownPeers[key] = newPeer;
        impl_->totalDiscovered++;
        if (impl_->discoveredCallback) impl_->discoveredCallback(newPeer);
    }
}

void Discovery::onPeerDiscovered(std::function<void(const PeerInfo&)> callback) {
    impl_->discoveredCallback = callback;
}

void Discovery::onPeerLost(std::function<void(const std::string&)> callback) {
    impl_->lostCallback = callback;
}

size_t Discovery::knownPeerCount() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->knownPeers.size();
}

size_t Discovery::activePeerCount() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    size_t count = 0;
    for (const auto& [key, peer] : impl_->knownPeers) {
        if (peer.state == DiscoveryPeerState::CONNECTED) count++;
    }
    return count;
}

DiscoveryStats Discovery::getStats() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    DiscoveryStats stats{};
    stats.totalDiscovered = impl_->totalDiscovered;
    stats.totalConnected = impl_->totalConnected;
    stats.totalFailed = impl_->totalFailed;
    stats.dnsQueries = impl_->dnsQueries;
    stats.peerExchanges = impl_->peerExchanges;
    stats.uptime = std::time(nullptr) - impl_->startTime;
    stats.bannedPeers = impl_->bannedPeers.size();
    stats.goodPeers = 0;
    stats.badPeers = 0;
    stats.knownPeersCount = impl_->knownPeers.size();
    stats.lastRefreshTime = impl_->lastPeerRefresh;
    stats.lastAnnounceTime = impl_->lastAnnounceTime;
    
    // Calculate average latency
    double totalLatency = 0.0;
    size_t latencyCount = 0;
    for (const auto& [key, peer] : impl_->knownPeers) {
        if (peer.attempts < 3) stats.goodPeers++;
        else stats.badPeers++;
        if (peer.latency > 0) {
            totalLatency += peer.latency;
            latencyCount++;
        }
    }
    stats.avgLatency = latencyCount > 0 ? totalLatency / latencyCount : 0.0;
    
    // Estimate network size
    stats.networkSize = impl_->estimateNetworkSize();
    
    // Calculate peer exchange success rate
    if (impl_->peerExchanges > 0) {
        stats.peerExchangeSuccessRate = (static_cast<double>(impl_->peerExchangeSuccesses) / impl_->peerExchanges) * 100.0;
    } else {
        stats.peerExchangeSuccessRate = 0.0;
    }
    
    // Get connected peers count (requires callback)
    if (impl_->getConnectedPeersCallback) {
        auto connected = impl_->getConnectedPeersCallback();
        stats.connectedPeers = connected.size();
    } else {
        stats.connectedPeers = 0;
    }
    
    return stats;
}

std::vector<PeerInfo> Discovery::getGoodPeers(size_t count) const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    std::vector<PeerInfo> result;
    for (const auto& [key, peer] : impl_->knownPeers) {
        if (peer.attempts < 3 && result.size() < count) {
            result.push_back(peer);
        }
    }
    return result;
}

std::vector<PeerInfo> Discovery::getNewPeers(size_t count) const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    std::vector<std::pair<uint64_t, PeerInfo>> sorted;
    for (const auto& [key, peer] : impl_->knownPeers) {
        sorted.emplace_back(peer.timestamp, peer);
    }
    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) {
        return a.first > b.first;
    });
    std::vector<PeerInfo> result;
    for (size_t i = 0; i < count && i < sorted.size(); i++) {
        result.push_back(sorted[i].second);
    }
    return result;
}

void Discovery::pruneOldPeers(uint64_t maxAge) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    uint64_t now = std::time(nullptr);
    for (auto it = impl_->knownPeers.begin(); it != impl_->knownPeers.end(); ) {
        if (now - it->second.lastSeen > maxAge) {
            it = impl_->knownPeers.erase(it);
        } else {
            ++it;
        }
    }
}

bool Discovery::exportPeers(const std::string& path) const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    std::ofstream f(path);
    if (!f) return false;
    for (const auto& [key, peer] : impl_->knownPeers) {
        f << peer.address << ":" << peer.port << "\n";
    }
    return true;
}

bool Discovery::importPeers(const std::string& path) {
    std::ifstream f(path);
    if (!f) return false;
    std::string line;
    while (std::getline(f, line)) {
        auto pos = line.find(':');
        if (pos != std::string::npos) {
            PeerInfo info{};
            info.address = line.substr(0, pos);
            info.port = std::stoi(line.substr(pos + 1));
            info.timestamp = std::time(nullptr);
            info.lastSeen = info.timestamp;
            info.state = DiscoveryPeerState::UNKNOWN;
            addPeer(info);
        }
    }
    return true;
}

bool Discovery::setupUPnP(uint16_t port) {
    return false;
}

bool Discovery::setupNatPmp(uint16_t port) {
    return false;
}

std::string Discovery::getExternalAddress() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    // If we already have an external address, return it
    if (!impl_->externalAddress.empty() && impl_->externalAddress != "0.0.0.0") {
        return impl_->externalAddress;
    }
    
    // Try to get from connected peers (they might have seen our address)
    // This is a simple heuristic: if we have connected peers, we can ask them
    // For now, return empty string if not set - will be set via announce or external discovery
    return impl_->externalAddress;
}

void Discovery::setExternalAddress(const std::string& address) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->externalAddress = address;
}

void Discovery::setSendMessageCallback(std::function<bool(const std::string& peerId, const std::string& command, const std::vector<uint8_t>& payload)> callback) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->sendMessageCallback = callback;
}

void Discovery::setGetConnectedPeersCallback(std::function<std::vector<std::string>()> callback) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->getConnectedPeersCallback = callback;
}

}
}
