#include "core/wallet.h"
#include "crypto/crypto.h"
#include <cstring>
#include <fstream>
#include <mutex>
#include <random>
#include <chrono>

namespace synapse {
namespace core {

static const char* BIP39_WORDLIST[] = {
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
    "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
    "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
    "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april",
    "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
    "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact",
    "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume",
    "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
    "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado",
    "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis",
    "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball",
    "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base",
    "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become",
    "beef", "before", "begin", "behave", "behind", "believe", "below", "belt",
    "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle",
    "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black",
    "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood",
    "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body",
    "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring",
    "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain",
    "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief",
    "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother",
    "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb",
    "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus",
    "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable"
};

static std::vector<uint8_t> generateRandom(size_t len) {
    std::vector<uint8_t> result(len);
    std::random_device rd;
    std::mt19937_64 gen(rd() ^ std::chrono::high_resolution_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<uint32_t> dist(0, 255);
    for (size_t i = 0; i < len; i++) {
        result[i] = static_cast<uint8_t>(dist(gen));
    }
    return result;
}

static std::vector<uint8_t> simplePbkdf2(const std::string& password, const std::vector<uint8_t>& salt, int iterations) {
    std::vector<uint8_t> key(64);
    std::vector<uint8_t> block(password.begin(), password.end());
    block.insert(block.end(), salt.begin(), salt.end());
    
    for (int i = 0; i < iterations; i++) {
        auto hash = crypto::sha256(block.data(), block.size());
        block.assign(hash.begin(), hash.end());
    }
    
    for (size_t i = 0; i < 64 && i < block.size(); i++) {
        key[i] = block[i % block.size()];
    }
    for (size_t i = block.size(); i < 64; i++) {
        key[i] = block[i % block.size()] ^ static_cast<uint8_t>(i);
    }
    
    return key;
}

struct Wallet::Impl {
    std::vector<std::string> seedWords;
    std::vector<uint8_t> masterSeed;
    crypto::PrivateKey privateKey;
    crypto::PublicKey publicKey;
    std::string address;
    double balance = 0.0;
    double pendingBalance = 0.0;
    double stakedBalance = 0.0;
    bool locked = true;
    std::string walletPath;
    mutable std::mutex mtx;
    
    void deriveMasterSeed();
    void deriveKeys();
    std::string deriveAddress();
};

void Wallet::Impl::deriveMasterSeed() {
    std::string mnemonic;
    for (const auto& word : seedWords) {
        if (!mnemonic.empty()) mnemonic += " ";
        mnemonic += word;
    }
    
    std::vector<uint8_t> salt(8);
    const char* saltPrefix = "mnemonic";
    std::memcpy(salt.data(), saltPrefix, 8);
    
    masterSeed = simplePbkdf2(mnemonic, salt, 2048);
}

void Wallet::Impl::deriveKeys() {
    if (masterSeed.empty()) return;
    
    auto hash = crypto::sha256(masterSeed.data(), masterSeed.size());
    std::memcpy(privateKey.data(), hash.data(), std::min(hash.size(), privateKey.size()));
    
    publicKey = crypto::derivePublicKey(privateKey);
    address = deriveAddress();
}

std::string Wallet::Impl::deriveAddress() {
    if (publicKey[0] == 0 && publicKey[1] == 0) return "";
    
    auto hash = crypto::sha256(publicKey.data(), publicKey.size());
    
    static const char* hex = "0123456789abcdef";
    std::string addr = "SN";
    for (int i = 0; i < 20; i++) {
        addr += hex[hash[i] >> 4];
        addr += hex[hash[i] & 0x0F];
    }
    
    return addr;
}

Wallet::Wallet() : impl_(std::make_unique<Impl>()) {}
Wallet::~Wallet() {
    lock();
}

bool Wallet::create() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    impl_->seedWords.clear();
    
    auto entropy = generateRandom(32);
    
    for (int i = 0; i < 24; i++) {
        int idx = 0;
        for (int j = 0; j < 11; j++) {
            int bitPos = i * 11 + j;
            int bytePos = bitPos / 8;
            int bitOffset = 7 - (bitPos % 8);
            if (bytePos < 32 && (entropy[bytePos] >> bitOffset) & 1) {
                idx |= (1 << (10 - j));
            }
        }
        idx %= 256;
        impl_->seedWords.push_back(BIP39_WORDLIST[idx]);
    }
    
    impl_->deriveMasterSeed();
    impl_->deriveKeys();
    impl_->locked = false;
    
    return true;
}

bool Wallet::restore(const std::vector<std::string>& seedWords) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    if (seedWords.size() != 24) return false;
    
    impl_->seedWords = seedWords;
    impl_->deriveMasterSeed();
    impl_->deriveKeys();
    impl_->locked = false;
    
    return true;
}

bool Wallet::load(const std::string& path, const std::string& password) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    std::ifstream file(path, std::ios::binary);
    if (!file) return false;
    
    std::vector<uint8_t> encrypted((std::istreambuf_iterator<char>(file)),
                                    std::istreambuf_iterator<char>());
    file.close();
    
    if (encrypted.size() < 44) return false;
    
    std::vector<uint8_t> salt(encrypted.begin(), encrypted.begin() + 16);
    std::vector<uint8_t> ciphertext(encrypted.begin() + 16, encrypted.end());
    
    std::vector<uint8_t> key = simplePbkdf2(password, salt, 2048);
    key.resize(32);
    
    std::vector<uint8_t> plaintext(ciphertext.size());
    for (size_t i = 0; i < ciphertext.size(); i++) {
        plaintext[i] = ciphertext[i] ^ key[i % key.size()];
    }
    
    impl_->seedWords.clear();
    std::string word;
    for (uint8_t c : plaintext) {
        if (c == ' ' || c == '\n' || c == 0) {
            if (!word.empty()) {
                impl_->seedWords.push_back(word);
                word.clear();
            }
        } else if (c >= 'a' && c <= 'z') {
            word += c;
        }
    }
    if (!word.empty()) {
        impl_->seedWords.push_back(word);
    }
    
    if (impl_->seedWords.size() != 24) return false;
    
    impl_->deriveMasterSeed();
    impl_->deriveKeys();
    impl_->walletPath = path;
    impl_->locked = false;
    
    return true;
}

bool Wallet::save(const std::string& path, const std::string& password) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    if (impl_->seedWords.empty()) return false;
    
    std::string plaintext;
    for (const auto& word : impl_->seedWords) {
        if (!plaintext.empty()) plaintext += " ";
        plaintext += word;
    }
    
    auto salt = generateRandom(16);
    std::vector<uint8_t> key = simplePbkdf2(password, salt, 2048);
    key.resize(32);
    
    std::vector<uint8_t> ciphertext(plaintext.size());
    for (size_t i = 0; i < plaintext.size(); i++) {
        ciphertext[i] = static_cast<uint8_t>(plaintext[i]) ^ key[i % key.size()];
    }
    
    std::ofstream file(path, std::ios::binary);
    if (!file) return false;
    
    file.write(reinterpret_cast<char*>(salt.data()), salt.size());
    file.write(reinterpret_cast<char*>(ciphertext.data()), ciphertext.size());
    
    impl_->walletPath = path;
    return file.good();
}

void Wallet::lock() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    std::memset(impl_->masterSeed.data(), 0, impl_->masterSeed.size());
    std::memset(impl_->privateKey.data(), 0, impl_->privateKey.size());
    impl_->masterSeed.clear();
    impl_->locked = true;
}

bool Wallet::unlock(const std::string& password) {
    return load(impl_->walletPath, password);
}

bool Wallet::isLocked() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->locked;
}

std::vector<std::string> Wallet::getSeedWords() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->seedWords;
}

std::string Wallet::getAddress() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->address;
}

std::vector<uint8_t> Wallet::getPublicKey() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return std::vector<uint8_t>(impl_->publicKey.begin(), impl_->publicKey.end());
}

double Wallet::getBalance() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->balance;
}

double Wallet::getPendingBalance() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->pendingBalance;
}

double Wallet::getStakedBalance() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->stakedBalance;
}

void Wallet::setBalance(double balance) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->balance = balance;
}

void Wallet::setPendingBalance(double pending) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->pendingBalance = pending;
}

void Wallet::setStakedBalance(double staked) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->stakedBalance = staked;
}

std::vector<uint8_t> Wallet::sign(const std::vector<uint8_t>& message) const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    if (impl_->locked) return {};
    
    auto hash = crypto::sha256(message.data(), message.size());
    crypto::Hash256 h;
    std::memcpy(h.data(), hash.data(), std::min(hash.size(), h.size()));
    
    auto sig = crypto::sign(h, impl_->privateKey);
    return std::vector<uint8_t>(sig.begin(), sig.end());
}

bool Wallet::verify(const std::vector<uint8_t>& message, const std::vector<uint8_t>& signature,
                    const std::vector<uint8_t>& publicKey) {
    if (signature.size() != 64 || publicKey.size() != 33) return false;
    
    auto hash = crypto::sha256(message.data(), message.size());
    crypto::Hash256 h;
    std::memcpy(h.data(), hash.data(), std::min(hash.size(), h.size()));
    
    crypto::Signature sig;
    std::memcpy(sig.data(), signature.data(), std::min(signature.size(), sig.size()));
    
    crypto::PublicKey pub;
    std::memcpy(pub.data(), publicKey.data(), std::min(publicKey.size(), pub.size()));
    
    return crypto::verify(h, sig, pub);
}

}
}
