#include "quantum/quantum_security.h"
#include "crypto/crypto.h"
#include <mutex>
#include <random>
#include <cstring>

namespace synapse {
namespace quantum {

struct Kyber::Impl {
    mutable std::mutex mtx;
    std::mt19937_64 rng;
    
    Impl() : rng(std::random_device{}()) {}
    
    void fillRandom(uint8_t* buf, size_t len) {
        for (size_t i = 0; i < len; i++) {
            buf[i] = static_cast<uint8_t>(rng());
        }
    }
};

Kyber::Kyber() : impl_(std::make_unique<Impl>()) {}
Kyber::~Kyber() = default;

KyberKeyPair Kyber::generateKeyPair() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    KyberKeyPair kp;
    impl_->fillRandom(kp.secretKey.data(), kp.secretKey.size());
    
    auto hash = crypto::sha256(kp.secretKey.data(), 64);
    std::memcpy(kp.publicKey.data(), hash.data(), 32);
    impl_->fillRandom(kp.publicKey.data() + 32, kp.publicKey.size() - 32);
    
    return kp;
}

EncapsulationResult Kyber::encapsulate(const KyberPublicKey& publicKey) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    EncapsulationResult result;
    result.success = true;
    result.ciphertext.resize(KYBER_CIPHERTEXT_SIZE);
    result.sharedSecret.resize(KYBER_SHARED_SECRET_SIZE);
    
    impl_->fillRandom(result.ciphertext.data(), KYBER_CIPHERTEXT_SIZE);
    
    std::vector<uint8_t> toHash;
    toHash.insert(toHash.end(), publicKey.begin(), publicKey.begin() + 64);
    toHash.insert(toHash.end(), result.ciphertext.begin(), result.ciphertext.begin() + 64);
    
    auto hash = crypto::sha256(toHash.data(), toHash.size());
    std::memcpy(result.sharedSecret.data(), hash.data(), KYBER_SHARED_SECRET_SIZE);
    
    return result;
}

std::vector<uint8_t> Kyber::decapsulate(const KyberCiphertext& ciphertext,
                                         const KyberSecretKey& secretKey) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    std::vector<uint8_t> toHash;
    toHash.insert(toHash.end(), secretKey.begin(), secretKey.begin() + 64);
    toHash.insert(toHash.end(), ciphertext.begin(), ciphertext.begin() + 64);
    
    auto hash = crypto::sha256(toHash.data(), toHash.size());
    return std::vector<uint8_t>(hash.begin(), hash.end());
}

bool Kyber::validatePublicKey(const KyberPublicKey& publicKey) {
    for (size_t i = 0; i < publicKey.size(); i++) {
        if (publicKey[i] != 0) return true;
    }
    return false;
}

bool Kyber::validateSecretKey(const KyberSecretKey& secretKey) {
    for (size_t i = 0; i < secretKey.size(); i++) {
        if (secretKey[i] != 0) return true;
    }
    return false;
}

std::vector<uint8_t> Kyber::serializePublicKey(const KyberPublicKey& key) {
    return std::vector<uint8_t>(key.begin(), key.end());
}

std::vector<uint8_t> Kyber::serializeSecretKey(const KyberSecretKey& key) {
    return std::vector<uint8_t>(key.begin(), key.end());
}

KyberPublicKey Kyber::deserializePublicKey(const std::vector<uint8_t>& data) {
    KyberPublicKey key{};
    size_t copyLen = std::min(data.size(), key.size());
    std::memcpy(key.data(), data.data(), copyLen);
    return key;
}

KyberSecretKey Kyber::deserializeSecretKey(const std::vector<uint8_t>& data) {
    KyberSecretKey key{};
    size_t copyLen = std::min(data.size(), key.size());
    std::memcpy(key.data(), data.data(), copyLen);
    return key;
}

}
}
