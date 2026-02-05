#include "quantum/quantum_security.h"
#include <mutex>
#include <random>

namespace synapse {
namespace quantum {

struct QuantumSecurityManager::Impl {
    SecurityLevel level = SecurityLevel::HIGH;
    bool initialized = false;
    mutable std::mutex mtx;
    
    Kyber kyber_;
    Dilithium dilithium_;
    Sphincs sphincs_;
    HybridKEM hybridKEM_;
    HybridSig hybridSig_;
    OTPManager otpManager_;
    HWRNG hwrng_;
    QKDIntegration qkd_;
    CryptoSelector selector_;
    KeyDerivation kdf_;
    TimingDefense timing_;
    
    QuantumStats stats{};
};

QuantumSecurityManager::QuantumSecurityManager() : impl_(std::make_unique<Impl>()) {}
QuantumSecurityManager::~QuantumSecurityManager() { shutdown(); }

bool QuantumSecurityManager::init(SecurityLevel level) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    if (impl_->initialized) return true;
    
    impl_->level = level;
    impl_->selector_.setSecurityLevel(level);
    
    if (!impl_->hwrng_.init()) {
        return false;
    }
    
    if (!impl_->otpManager_.init("otp_keys")) {
        return false;
    }
    
    impl_->initialized = true;
    return true;
}

void QuantumSecurityManager::shutdown() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    if (!impl_->initialized) return;
    
    impl_->otpManager_.shutdown();
    impl_->qkd_.shutdown();
    impl_->initialized = false;
}

Kyber& QuantumSecurityManager::kyber() { return impl_->kyber_; }
Dilithium& QuantumSecurityManager::dilithium() { return impl_->dilithium_; }
Sphincs& QuantumSecurityManager::sphincs() { return impl_->sphincs_; }
HybridKEM& QuantumSecurityManager::hybridKEM() { return impl_->hybridKEM_; }
HybridSig& QuantumSecurityManager::hybridSig() { return impl_->hybridSig_; }
OTPManager& QuantumSecurityManager::otpManager() { return impl_->otpManager_; }
HWRNG& QuantumSecurityManager::hwrng() { return impl_->hwrng_; }
QKDIntegration& QuantumSecurityManager::qkd() { return impl_->qkd_; }
CryptoSelector& QuantumSecurityManager::selector() { return impl_->selector_; }
KeyDerivation& QuantumSecurityManager::kdf() { return impl_->kdf_; }
TimingDefense& QuantumSecurityManager::timing() { return impl_->timing_; }

void QuantumSecurityManager::setSecurityLevel(SecurityLevel level) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->level = level;
    impl_->selector_.setSecurityLevel(level);
}

SecurityLevel QuantumSecurityManager::getSecurityLevel() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->level;
}

QuantumStats QuantumSecurityManager::getStats() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->stats;
}

struct QuantumManager::Impl {
    SecurityLevel level = SecurityLevel::STANDARD;
    bool initialized = false;
    mutable std::mutex mtx;
    std::mt19937_64 rng;
    
    Kyber kyber_;
    Dilithium dilithium_;
    HybridKEM hybridKEM_;
    HybridSig hybridSig_;
    OTPManager otpManager_;
    HWRNG hwrng_;
    
    QuantumStats stats{};
    HybridKeyPair currentKeyPair;
    
    Impl() : rng(std::random_device{}()) {}
};

QuantumManager::QuantumManager() : impl_(std::make_unique<Impl>()) {}
QuantumManager::~QuantumManager() { shutdown(); }

bool QuantumManager::init(SecurityLevel level) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    if (impl_->initialized) return true;
    
    impl_->level = level;
    
    if (!impl_->hwrng_.init()) {
        return false;
    }
    
    if (!impl_->otpManager_.init("quantum_keys")) {
        return false;
    }
    
    impl_->currentKeyPair = impl_->hybridKEM_.generateKeyPair();
    impl_->initialized = true;
    return true;
}

void QuantumManager::shutdown() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    if (!impl_->initialized) return;
    
    impl_->otpManager_.shutdown();
    impl_->initialized = false;
}

void QuantumManager::performMaintenance() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    if (!impl_->initialized) return;
    
    pruneExpiredKeys();
}

void QuantumManager::rotateKeys() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    if (!impl_->initialized) return;
    
    impl_->currentKeyPair = impl_->hybridKEM_.generateKeyPair();
}

void QuantumManager::pruneExpiredKeys() {
    impl_->otpManager_.pruneExpiredKeys();
}

std::vector<uint8_t> QuantumManager::generateQuantumSafeKey(size_t length) {
    return impl_->hwrng_.generate(length);
}

std::vector<uint8_t> QuantumManager::encryptQuantumSafe(const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    if (!impl_->initialized || data.empty()) return {};
    
    auto result = impl_->hybridKEM_.encapsulate(impl_->currentKeyPair);
    
    std::vector<uint8_t> output;
    output.reserve(4 + result.ciphertext.size() + data.size());
    
    uint32_t ctSize = static_cast<uint32_t>(result.ciphertext.size());
    output.push_back((ctSize >> 24) & 0xFF);
    output.push_back((ctSize >> 16) & 0xFF);
    output.push_back((ctSize >> 8) & 0xFF);
    output.push_back(ctSize & 0xFF);
    
    output.insert(output.end(), result.ciphertext.begin(), result.ciphertext.end());
    
    for (size_t i = 0; i < data.size(); i++) {
        output.push_back(data[i] ^ result.sharedSecret[i % result.sharedSecret.size()]);
    }
    
    impl_->stats.hybridOperations++;
    return output;
}

std::vector<uint8_t> QuantumManager::decryptQuantumSafe(const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    if (!impl_->initialized || data.size() < 4) return {};
    
    uint32_t ctSize = (static_cast<uint32_t>(data[0]) << 24) |
                      (static_cast<uint32_t>(data[1]) << 16) |
                      (static_cast<uint32_t>(data[2]) << 8) |
                      static_cast<uint32_t>(data[3]);
    
    if (data.size() < 4 + ctSize) return {};
    
    std::vector<uint8_t> ciphertext(data.begin() + 4, data.begin() + 4 + ctSize);
    std::vector<uint8_t> encrypted(data.begin() + 4 + ctSize, data.end());
    
    auto sharedSecret = impl_->hybridKEM_.decapsulate(ciphertext, impl_->currentKeyPair);
    
    std::vector<uint8_t> result(encrypted.size());
    for (size_t i = 0; i < encrypted.size(); i++) {
        result[i] = encrypted[i] ^ sharedSecret[i % sharedSecret.size()];
    }
    
    impl_->stats.hybridOperations++;
    return result;
}

std::vector<uint8_t> QuantumManager::signQuantumSafe(const std::vector<uint8_t>& message) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    if (!impl_->initialized) return {};
    
    HybridKeyPair sigKeyPair;
    sigKeyPair.classicSecretKey.resize(32);
    for (auto& b : sigKeyPair.classicSecretKey) b = impl_->rng() & 0xFF;
    sigKeyPair.pqcSecretKey.resize(32);
    for (auto& b : sigKeyPair.pqcSecretKey) b = impl_->rng() & 0xFF;
    
    auto result = impl_->hybridSig_.sign(message, sigKeyPair);
    impl_->stats.hybridOperations++;
    return result.signature;
}

bool QuantumManager::verifyQuantumSafe(const std::vector<uint8_t>& message,
                                        const std::vector<uint8_t>& signature) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    if (!impl_->initialized) return false;
    
    HybridKeyPair pubKeyPair;
    pubKeyPair.classicPublicKey.resize(32);
    pubKeyPair.pqcPublicKey.resize(32);
    
    impl_->stats.hybridOperations++;
    return impl_->hybridSig_.verify(message, signature, pubKeyPair);
}

void QuantumManager::setSecurityLevel(SecurityLevel level) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->level = level;
}

SecurityLevel QuantumManager::getSecurityLevel() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->level;
}

bool QuantumManager::isQuantumSafe() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->initialized && impl_->level >= SecurityLevel::STANDARD;
}

QuantumStats QuantumManager::getStats() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->stats;
}

}
}
