#include "quantum/quantum_security.h"
#include <set>
#include <mutex>

namespace synapse {
namespace quantum {

struct CryptoSelector::Impl {
    SecurityLevel level = SecurityLevel::HIGH;
    std::set<CryptoAlgorithm> disabledAlgos;
    mutable std::mutex mtx;
};

CryptoSelector::CryptoSelector() : impl_(std::make_unique<Impl>()) {}
CryptoSelector::~CryptoSelector() = default;

void CryptoSelector::setSecurityLevel(SecurityLevel level) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->level = level;
}

SecurityLevel CryptoSelector::getSecurityLevel() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->level;
}

CryptoAlgorithm CryptoSelector::selectKEM() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    switch (impl_->level) {
        case SecurityLevel::PARANOID:
            if (isAlgorithmAvailable(CryptoAlgorithm::HYBRID_KEM)) {
                return CryptoAlgorithm::HYBRID_KEM;
            }
            break;
        case SecurityLevel::HIGH:
            if (isAlgorithmAvailable(CryptoAlgorithm::LATTICE_KYBER768)) {
                return CryptoAlgorithm::LATTICE_KYBER768;
            }
            break;
        case SecurityLevel::STANDARD:
        default:
            break;
    }
    
    return CryptoAlgorithm::CLASSIC_X25519;
}

CryptoAlgorithm CryptoSelector::selectSignature() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    switch (impl_->level) {
        case SecurityLevel::PARANOID:
            if (isAlgorithmAvailable(CryptoAlgorithm::HYBRID_SIG)) {
                return CryptoAlgorithm::HYBRID_SIG;
            }
            if (isAlgorithmAvailable(CryptoAlgorithm::HASH_SPHINCS128S)) {
                return CryptoAlgorithm::HASH_SPHINCS128S;
            }
            break;
        case SecurityLevel::HIGH:
            if (isAlgorithmAvailable(CryptoAlgorithm::LATTICE_DILITHIUM65)) {
                return CryptoAlgorithm::LATTICE_DILITHIUM65;
            }
            break;
        case SecurityLevel::STANDARD:
        default:
            break;
    }
    
    return CryptoAlgorithm::CLASSIC_ED25519;
}

CryptoAlgorithm CryptoSelector::selectEncryption() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    switch (impl_->level) {
        case SecurityLevel::PARANOID:
            if (isAlgorithmAvailable(CryptoAlgorithm::OTP_VERNAM)) {
                return CryptoAlgorithm::OTP_VERNAM;
            }
            break;
        case SecurityLevel::HIGH:
        case SecurityLevel::STANDARD:
        default:
            break;
    }
    
    return CryptoAlgorithm::CLASSIC_AES256GCM;
}

bool CryptoSelector::isAlgorithmAvailable(CryptoAlgorithm algo) const {
    return impl_->disabledAlgos.find(algo) == impl_->disabledAlgos.end();
}

void CryptoSelector::disableAlgorithm(CryptoAlgorithm algo) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->disabledAlgos.insert(algo);
}

void CryptoSelector::enableAlgorithm(CryptoAlgorithm algo) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->disabledAlgos.erase(algo);
}

std::vector<CryptoAlgorithm> CryptoSelector::getAvailableKEMs() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    std::vector<CryptoAlgorithm> kems;
    
    if (isAlgorithmAvailable(CryptoAlgorithm::CLASSIC_X25519)) {
        kems.push_back(CryptoAlgorithm::CLASSIC_X25519);
    }
    if (isAlgorithmAvailable(CryptoAlgorithm::LATTICE_KYBER768)) {
        kems.push_back(CryptoAlgorithm::LATTICE_KYBER768);
    }
    if (isAlgorithmAvailable(CryptoAlgorithm::HYBRID_KEM)) {
        kems.push_back(CryptoAlgorithm::HYBRID_KEM);
    }
    if (isAlgorithmAvailable(CryptoAlgorithm::QKD_BB84)) {
        kems.push_back(CryptoAlgorithm::QKD_BB84);
    }
    
    return kems;
}

std::vector<CryptoAlgorithm> CryptoSelector::getAvailableSignatures() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    std::vector<CryptoAlgorithm> sigs;
    
    if (isAlgorithmAvailable(CryptoAlgorithm::CLASSIC_ED25519)) {
        sigs.push_back(CryptoAlgorithm::CLASSIC_ED25519);
    }
    if (isAlgorithmAvailable(CryptoAlgorithm::LATTICE_DILITHIUM65)) {
        sigs.push_back(CryptoAlgorithm::LATTICE_DILITHIUM65);
    }
    if (isAlgorithmAvailable(CryptoAlgorithm::HASH_SPHINCS128S)) {
        sigs.push_back(CryptoAlgorithm::HASH_SPHINCS128S);
    }
    if (isAlgorithmAvailable(CryptoAlgorithm::HYBRID_SIG)) {
        sigs.push_back(CryptoAlgorithm::HYBRID_SIG);
    }
    
    return sigs;
}

std::vector<CryptoAlgorithm> CryptoSelector::getAvailableEncryptions() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    std::vector<CryptoAlgorithm> encs;
    
    if (isAlgorithmAvailable(CryptoAlgorithm::CLASSIC_AES256GCM)) {
        encs.push_back(CryptoAlgorithm::CLASSIC_AES256GCM);
    }
    if (isAlgorithmAvailable(CryptoAlgorithm::OTP_VERNAM)) {
        encs.push_back(CryptoAlgorithm::OTP_VERNAM);
    }
    
    return encs;
}

}
}
