#include "quantum/quantum_security.h"
#include "crypto/crypto.h"
#include <mutex>
#include <random>
#include <cstring>

namespace synapse {
namespace quantum {

struct HybridSig::Impl {
    mutable std::mutex mtx;
    std::mt19937_64 rng;
    CryptoAlgorithm classicAlgo = CryptoAlgorithm::CLASSIC_ED25519;
    CryptoAlgorithm pqcAlgo = CryptoAlgorithm::LATTICE_DILITHIUM65;
    Dilithium dilithium;
    
    Impl() : rng(std::random_device{}()) {}
    
    void fillRandom(uint8_t* buf, size_t len) {
        for (size_t i = 0; i < len; i++) {
            buf[i] = static_cast<uint8_t>(rng());
        }
    }
};

HybridSig::HybridSig() : impl_(std::make_unique<Impl>()) {}
HybridSig::~HybridSig() = default;

HybridKeyPair HybridSig::generateKeyPair() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    HybridKeyPair kp;
    kp.classicAlgo = impl_->classicAlgo;
    kp.pqcAlgo = impl_->pqcAlgo;
    
    kp.classicSecretKey.resize(64);
    kp.classicPublicKey.resize(32);
    impl_->fillRandom(kp.classicSecretKey.data(), 64);
    
    auto hash = crypto::sha256(kp.classicSecretKey.data(), 32);
    std::memcpy(kp.classicPublicKey.data(), hash.data(), 32);
    
    auto dilithiumKp = impl_->dilithium.generateKeyPair();
    kp.pqcPublicKey.assign(dilithiumKp.publicKey.begin(), dilithiumKp.publicKey.end());
    kp.pqcSecretKey.assign(dilithiumKp.secretKey.begin(), dilithiumKp.secretKey.end());
    
    return kp;
}

SignatureResult HybridSig::sign(const std::vector<uint8_t>& message,
                                 const HybridKeyPair& secretKey) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    SignatureResult result;
    result.success = true;
    
    std::vector<uint8_t> classicSig(64);
    std::vector<uint8_t> toSign;
    toSign.insert(toSign.end(), message.begin(), message.end());
    toSign.insert(toSign.end(), secretKey.classicSecretKey.begin(), 
                  secretKey.classicSecretKey.begin() + 32);
    
    auto hash = crypto::sha256(toSign.data(), toSign.size());
    std::memcpy(classicSig.data(), hash.data(), 32);
    impl_->fillRandom(classicSig.data() + 32, 32);
    
    DilithiumSecretKey dilithiumSk{};
    size_t copyLen = std::min(secretKey.pqcSecretKey.size(), dilithiumSk.size());
    std::memcpy(dilithiumSk.data(), secretKey.pqcSecretKey.data(), copyLen);
    
    auto pqcResult = impl_->dilithium.sign(message, dilithiumSk);
    
    result.signature = classicSig;
    result.signature.insert(result.signature.end(), 
                            pqcResult.signature.begin(), 
                            pqcResult.signature.end());
    
    return result;
}

bool HybridSig::verify(const std::vector<uint8_t>& message,
                       const std::vector<uint8_t>& signature,
                       const HybridKeyPair& publicKey) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    if (signature.size() < 64 + DILITHIUM_SIGNATURE_SIZE) {
        return false;
    }
    
    DilithiumSignature dilithiumSig{};
    std::memcpy(dilithiumSig.data(), signature.data() + 64, DILITHIUM_SIGNATURE_SIZE);
    
    DilithiumPublicKey dilithiumPk{};
    size_t copyLen = std::min(publicKey.pqcPublicKey.size(), dilithiumPk.size());
    std::memcpy(dilithiumPk.data(), publicKey.pqcPublicKey.data(), copyLen);
    
    return impl_->dilithium.verify(message, dilithiumSig, dilithiumPk);
}

void HybridSig::setClassicAlgorithm(CryptoAlgorithm algo) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->classicAlgo = algo;
}

void HybridSig::setPQCAlgorithm(CryptoAlgorithm algo) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->pqcAlgo = algo;
}

}
}
