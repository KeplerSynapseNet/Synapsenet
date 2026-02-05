#include "privacy/privacy.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <mutex>
#include <poll.h>

namespace synapse {
namespace privacy {

struct Socks5Proxy::Impl {
    std::string proxyHost = "127.0.0.1";
    uint16_t proxyPort = 9050;
    int socket = -1;
    bool connected = false;
    bool authenticated = false;
    mutable std::mutex mtx;
    
    bool sendAll(const uint8_t* data, size_t len);
    bool recvAll(uint8_t* data, size_t len);
};

bool Socks5Proxy::Impl::sendAll(const uint8_t* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(socket, data + sent, len - sent, 0);
        if (n <= 0) return false;
        sent += n;
    }
    return true;
}

bool Socks5Proxy::Impl::recvAll(uint8_t* data, size_t len) {
    size_t received = 0;
    while (received < len) {
        ssize_t n = recv(socket, data + received, len - received, 0);
        if (n <= 0) return false;
        received += n;
    }
    return true;
}

Socks5Proxy::Socks5Proxy() : impl_(std::make_unique<Impl>()) {}
Socks5Proxy::~Socks5Proxy() { disconnect(); }

bool Socks5Proxy::connect(const std::string& host, uint16_t port) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    impl_->proxyHost = host;
    impl_->proxyPort = port;
    
    impl_->socket = ::socket(AF_INET, SOCK_STREAM, 0);
    if (impl_->socket < 0) return false;
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    
    if (::connect(impl_->socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(impl_->socket);
        impl_->socket = -1;
        return false;
    }
    
    impl_->connected = true;
    impl_->authenticated = false;
    uint8_t greeting[3] = {0x05, 0x01, 0x00};
    if (!impl_->sendAll(greeting, 3)) {
        disconnect();
        return false;
    }
    uint8_t response[2];
    if (!impl_->recvAll(response, 2)) {
        disconnect();
        return false;
    }
    if (!(response[0] == 0x05 && response[1] == 0x00)) {
        disconnect();
        return false;
    }
    impl_->authenticated = true;
    return true;
}

void Socks5Proxy::disconnect() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    if (impl_->socket >= 0) {
        close(impl_->socket);
        impl_->socket = -1;
    }
    impl_->connected = false;
    impl_->authenticated = false;
}

bool Socks5Proxy::isConnected() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->connected;
}

bool Socks5Proxy::authenticate() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    if (!impl_->connected) return false;
    
    uint8_t greeting[3] = {0x05, 0x01, 0x00};
    if (!impl_->sendAll(greeting, 3)) return false;
    
    uint8_t response[2];
    if (!impl_->recvAll(response, 2)) return false;
    
    impl_->authenticated = response[0] == 0x05 && response[1] == 0x00;
    return impl_->authenticated;
}

bool Socks5Proxy::connectToTarget(const std::string& targetHost, uint16_t targetPort) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    if (!impl_->connected) return false;
    if (!impl_->authenticated) {
        uint8_t greeting[3] = {0x05, 0x01, 0x00};
        if (!impl_->sendAll(greeting, 3)) return false;
        uint8_t response[2];
        if (!impl_->recvAll(response, 2)) return false;
        if (!(response[0] == 0x05 && response[1] == 0x00)) return false;
        impl_->authenticated = true;
    }
    
    std::vector<uint8_t> request;
    request.push_back(0x05);
    request.push_back(0x01);
    request.push_back(0x00);
    
    in_addr ipv4{};
    in6_addr ipv6{};
    if (inet_pton(AF_INET, targetHost.c_str(), &ipv4) == 1) {
        request.push_back(0x01);
        uint8_t* addr = reinterpret_cast<uint8_t*>(&ipv4);
        request.insert(request.end(), addr, addr + 4);
    } else if (inet_pton(AF_INET6, targetHost.c_str(), &ipv6) == 1) {
        request.push_back(0x04);
        uint8_t* addr = reinterpret_cast<uint8_t*>(&ipv6);
        request.insert(request.end(), addr, addr + 16);
    } else {
        request.push_back(0x03);
        request.push_back(static_cast<uint8_t>(targetHost.size()));
        request.insert(request.end(), targetHost.begin(), targetHost.end());
    }
    request.push_back((targetPort >> 8) & 0xFF);
    request.push_back(targetPort & 0xFF);
    
    if (!impl_->sendAll(request.data(), request.size())) return false;
    
    uint8_t header[4];
    if (!impl_->recvAll(header, 4)) return false;
    if (!(header[0] == 0x05 && header[1] == 0x00)) return false;
    
    uint8_t atyp = header[3];
    size_t addrLen = 0;
    if (atyp == 0x01) {
        addrLen = 4;
    } else if (atyp == 0x04) {
        addrLen = 16;
    } else if (atyp == 0x03) {
        uint8_t len = 0;
        if (!impl_->recvAll(&len, 1)) return false;
        addrLen = len;
    } else {
        return false;
    }
    
    std::vector<uint8_t> discard(addrLen + 2);
    if (!impl_->recvAll(discard.data(), discard.size())) return false;
    
    return true;
}

std::vector<uint8_t> Socks5Proxy::sendData(const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    if (!impl_->connected) return {};
    
    if (!impl_->sendAll(data.data(), data.size())) return {};
    
    std::vector<uint8_t> response;
    std::vector<uint8_t> buffer(4096);
    size_t maxBytes = 1024 * 1024;
    
    while (response.size() < maxBytes) {
        struct pollfd pfd;
        pfd.fd = impl_->socket;
        pfd.events = POLLIN;
        int ret = poll(&pfd, 1, 200);
        if (ret <= 0) break;
        if (!(pfd.revents & POLLIN)) break;
        ssize_t n = recv(impl_->socket, buffer.data(), buffer.size(), 0);
        if (n <= 0) break;
        response.insert(response.end(), buffer.begin(), buffer.begin() + n);
    }
    
    return response;
}

void Socks5Proxy::setProxy(const std::string& host, uint16_t port) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->proxyHost = host;
    impl_->proxyPort = port;
}

}
}
