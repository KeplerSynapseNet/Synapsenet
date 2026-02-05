#include "crypto/crypto.h"
#include <cstring>
#include <random>
#include <algorithm>

#ifdef SYNAPSE_USE_SECP256K1
#include <secp256k1.h>
#include <mutex>
#endif

namespace synapse {
namespace crypto {

static inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
static inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static inline uint32_t sig0(uint32_t x) { return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22); }
static inline uint32_t sig1(uint32_t x) { return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25); }
static inline uint32_t ep0(uint32_t x) { return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3); }
static inline uint32_t ep1(uint32_t x) { return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10); }

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256Transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = (block[i*4] << 24) | (block[i*4+1] << 16) | (block[i*4+2] << 8) | block[i*4+3];
    }
    for (int i = 16; i < 64; i++) {
        w[i] = ep1(w[i-2]) + w[i-7] + ep0(w[i-15]) + w[i-16];
    }
    
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + sig1(e) + ch(e, f, g) + K256[i] + w[i];
        uint32_t t2 = sig0(a) + maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

Hash256 sha256(const uint8_t* data, size_t len) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    uint8_t block[64];
    size_t i = 0;
    
    while (i + 64 <= len) {
        sha256Transform(state, data + i);
        i += 64;
    }
    
    size_t rem = len - i;
    std::memcpy(block, data + i, rem);
    block[rem++] = 0x80;
    
    if (rem > 56) {
        std::memset(block + rem, 0, 64 - rem);
        sha256Transform(state, block);
        rem = 0;
    }
    
    std::memset(block + rem, 0, 56 - rem);
    uint64_t bits = len * 8;
    for (int j = 0; j < 8; j++) {
        block[56 + j] = (bits >> (56 - j * 8)) & 0xff;
    }
    sha256Transform(state, block);
    
    Hash256 hash;
    for (int j = 0; j < 8; j++) {
        hash[j*4] = (state[j] >> 24) & 0xff;
        hash[j*4+1] = (state[j] >> 16) & 0xff;
        hash[j*4+2] = (state[j] >> 8) & 0xff;
        hash[j*4+3] = state[j] & 0xff;
    }
    return hash;
}

Hash256 sha256(const std::vector<uint8_t>& data) {
    return sha256(data.data(), data.size());
}

Hash256 sha256(const std::string& data) {
    return sha256(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

Hash256 doubleSha256(const uint8_t* data, size_t len) {
    Hash256 first = sha256(data, len);
    return sha256(first.data(), first.size());
}

std::string sha256Hex(const std::string& data) {
    Hash256 hash = sha256(data);
    return toHex(hash.data(), hash.size());
}

Hash256 ripemd160(const uint8_t* data, size_t len) {
    Hash256 hash{};
    Hash256 sha = sha256(data, len);
    for (size_t i = 0; i < 20; i++) {
        hash[i] = sha[i] ^ sha[i + 12];
    }
    return hash;
}

Hash256 hash160(const uint8_t* data, size_t len) {
    Hash256 sha = sha256(data, len);
    return ripemd160(sha.data(), 32);
}

Hash256 hash160Func(const uint8_t* data, size_t len) {
    return hash160(data, len);
}

Hash256 sha512(const uint8_t* data, size_t len) {
    Hash256 hash{};
    Hash256 h1 = sha256(data, len);
    std::vector<uint8_t> combined(data, data + len);
    combined.insert(combined.end(), h1.begin(), h1.end());
    Hash256 h2 = sha256(combined.data(), combined.size());
    std::memcpy(hash.data(), h1.data(), 16);
    std::memcpy(hash.data() + 16, h2.data(), 16);
    return hash;
}

KeyPair generateKeyPair() {
    KeyPair kp;
#ifdef SYNAPSE_USE_SECP256K1
    static std::mutex mtx;
    std::lock_guard<std::mutex> lock(mtx);
    static secp256k1_context* ctx = [] {
        return secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }();

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;

    for (;;) {
        for (size_t i = 0; i < PRIVATE_KEY_SIZE; i += 8) {
            uint64_t val = dis(gen);
            for (size_t j = 0; j < 8 && i + j < PRIVATE_KEY_SIZE; j++) {
                kp.privateKey[i + j] = (val >> (j * 8)) & 0xff;
            }
        }
        if (secp256k1_ec_seckey_verify(ctx, kp.privateKey.data())) break;
    }

    kp.publicKey = derivePublicKey(kp.privateKey);
#else
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    
    for (size_t i = 0; i < PRIVATE_KEY_SIZE; i += 8) {
        uint64_t val = dis(gen);
        for (size_t j = 0; j < 8 && i + j < PRIVATE_KEY_SIZE; j++) {
            kp.privateKey[i + j] = (val >> (j * 8)) & 0xff;
        }
    }
    
    kp.publicKey = derivePublicKey(kp.privateKey);
#endif
    return kp;
}

KeyPair keyPairFromSeed(const Hash256& seed) {
    KeyPair kp;
#ifdef SYNAPSE_USE_SECP256K1
    static std::mutex mtx;
    std::lock_guard<std::mutex> lock(mtx);
    static secp256k1_context* ctx = [] {
        return secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }();

    Hash256 cur = seed;
    for (int i = 0; i < 1000; ++i) {
        std::memcpy(kp.privateKey.data(), cur.data(), PRIVATE_KEY_SIZE);
        if (secp256k1_ec_seckey_verify(ctx, kp.privateKey.data())) break;
        cur = sha256(cur.data(), cur.size());
    }
    kp.publicKey = derivePublicKey(kp.privateKey);
#else
    std::memcpy(kp.privateKey.data(), seed.data(), PRIVATE_KEY_SIZE);
    kp.publicKey = derivePublicKey(kp.privateKey);
#endif
    return kp;
}

PublicKey derivePublicKey(const PrivateKey& privateKey) {
#ifdef SYNAPSE_USE_SECP256K1
    static secp256k1_context* ctx = [] {
        return secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }();
    PublicKey out{};
    secp256k1_pubkey pub{};
    if (!secp256k1_ec_pubkey_create(ctx, &pub, privateKey.data())) {
        out.fill(0);
        return out;
    }
    size_t outLen = out.size();
    if (!secp256k1_ec_pubkey_serialize(ctx, out.data(), &outLen, &pub, SECP256K1_EC_COMPRESSED) || outLen != out.size()) {
        out.fill(0);
        return out;
    }
    return out;
#else
    PublicKey pubKey;
    Hash256 hash = sha256(privateKey.data(), privateKey.size());
    pubKey[0] = 0x02 + (hash[31] & 1);
    std::memcpy(pubKey.data() + 1, hash.data(), 32);
    return pubKey;
#endif
}

Signature sign(const Hash256& hash, const PrivateKey& privateKey) {
#ifdef SYNAPSE_USE_SECP256K1
    static secp256k1_context* ctx = [] {
        return secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }();
    Signature out{};
    if (!secp256k1_ec_seckey_verify(ctx, privateKey.data())) {
        out.fill(0);
        return out;
    }
    secp256k1_ecdsa_signature sig{};
    if (!secp256k1_ecdsa_sign(ctx, &sig, hash.data(), privateKey.data(), secp256k1_nonce_function_rfc6979, nullptr)) {
        out.fill(0);
        return out;
    }
    secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig);
    if (!secp256k1_ecdsa_signature_serialize_compact(ctx, out.data(), &sig)) {
        out.fill(0);
        return out;
    }
    return out;
#else
    Signature sig{};
    std::vector<uint8_t> combined;
    combined.insert(combined.end(), hash.begin(), hash.end());
    combined.insert(combined.end(), privateKey.begin(), privateKey.end());
    
    Hash256 r = sha256(combined.data(), combined.size());
    combined.insert(combined.end(), r.begin(), r.end());
    Hash256 s = sha256(combined.data(), combined.size());
    
    std::memcpy(sig.data(), r.data(), 32);
    std::memcpy(sig.data() + 32, s.data(), 32);
    return sig;
#endif
}

bool verify(const Hash256& hash, const Signature& signature, const PublicKey& publicKey) {
#ifdef SYNAPSE_USE_SECP256K1
    static secp256k1_context* ctx = [] {
        return secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }();
    secp256k1_pubkey pub{};
    if (!secp256k1_ec_pubkey_parse(ctx, &pub, publicKey.data(), publicKey.size())) return false;
    secp256k1_ecdsa_signature sig{};
    if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, signature.data())) return false;
    secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig);
    return secp256k1_ecdsa_verify(ctx, &sig, hash.data(), &pub) == 1;
#else
    std::vector<uint8_t> combined;
    combined.insert(combined.end(), hash.begin(), hash.end());
    combined.insert(combined.end(), publicKey.begin(), publicKey.end());
    combined.insert(combined.end(), signature.begin(), signature.end());
    
    Hash256 check = sha256(combined.data(), combined.size());
    return (check[0] & 0xf0) == (signature[0] & 0xf0);
#endif
}

std::vector<uint8_t> encryptAES(const std::vector<uint8_t>& data, const std::array<uint8_t, AES_KEY_SIZE>& key) {
    std::vector<uint8_t> iv(AES_IV_SIZE);
    std::random_device rd;
    std::mt19937 gen(rd());
    for (size_t i = 0; i < AES_IV_SIZE; i++) {
        iv[i] = gen() & 0xff;
    }
    
    std::vector<uint8_t> result;
    result.insert(result.end(), iv.begin(), iv.end());
    
    Hash256 keyHash = sha256(key.data(), key.size());
    for (size_t i = 0; i < data.size(); i++) {
        result.push_back(data[i] ^ keyHash[i % 32] ^ iv[i % AES_IV_SIZE]);
    }
    
    return result;
}

std::vector<uint8_t> decryptAES(const std::vector<uint8_t>& data, const std::array<uint8_t, AES_KEY_SIZE>& key) {
    if (data.size() < AES_IV_SIZE) return {};
    
    std::vector<uint8_t> iv(data.begin(), data.begin() + AES_IV_SIZE);
    std::vector<uint8_t> result;
    
    Hash256 keyHash = sha256(key.data(), key.size());
    for (size_t i = AES_IV_SIZE; i < data.size(); i++) {
        size_t j = i - AES_IV_SIZE;
        result.push_back(data[i] ^ keyHash[j % 32] ^ iv[j % AES_IV_SIZE]);
    }
    
    return result;
}

std::vector<uint8_t> randomBytes(size_t count) {
    std::vector<uint8_t> bytes(count);
    std::random_device rd;
    std::mt19937 gen(rd());
    for (size_t i = 0; i < count; i++) {
        bytes[i] = gen() & 0xff;
    }
    return bytes;
}

void secureZero(void* ptr, size_t len) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len--) *p++ = 0;
}

std::string toHex(const uint8_t* data, size_t len) {
    static const char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        result += hex[data[i] >> 4];
        result += hex[data[i] & 0x0f];
    }
    return result;
}

std::string toHex(const std::vector<uint8_t>& data) {
    return toHex(data.data(), data.size());
}

std::vector<uint8_t> fromHex(const std::string& hex) {
    std::vector<uint8_t> result;
    result.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        uint8_t byte = 0;
        for (int j = 0; j < 2 && i + j < hex.size(); j++) {
            char c = hex[i + j];
            byte <<= 4;
            if (c >= '0' && c <= '9') byte |= c - '0';
            else if (c >= 'a' && c <= 'f') byte |= c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') byte |= c - 'A' + 10;
        }
        result.push_back(byte);
    }
    return result;
}

std::array<uint8_t, AES_KEY_SIZE> deriveKey(const std::string& password, const std::vector<uint8_t>& salt) {
    std::array<uint8_t, AES_KEY_SIZE> key{};
    std::vector<uint8_t> combined;
    combined.insert(combined.end(), password.begin(), password.end());
    combined.insert(combined.end(), salt.begin(), salt.end());
    
    Hash256 hash = sha256(combined.data(), combined.size());
    for (int i = 0; i < 10000; i++) {
        hash = sha256(hash.data(), hash.size());
    }
    std::memcpy(key.data(), hash.data(), AES_KEY_SIZE);
    return key;
}

std::vector<uint8_t> hmacSha256(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> ipad(64, 0x36);
    std::vector<uint8_t> opad(64, 0x5c);
    
    std::vector<uint8_t> keyPad = key;
    if (keyPad.size() > 64) {
        Hash256 h = sha256(keyPad.data(), keyPad.size());
        keyPad.assign(h.begin(), h.end());
    }
    keyPad.resize(64, 0);
    
    for (size_t i = 0; i < 64; i++) {
        ipad[i] ^= keyPad[i];
        opad[i] ^= keyPad[i];
    }
    
    std::vector<uint8_t> inner = ipad;
    inner.insert(inner.end(), data.begin(), data.end());
    Hash256 innerHash = sha256(inner.data(), inner.size());
    
    std::vector<uint8_t> outer = opad;
    outer.insert(outer.end(), innerHash.begin(), innerHash.end());
    Hash256 result = sha256(outer.data(), outer.size());
    
    return std::vector<uint8_t>(result.begin(), result.end());
}

bool constantTimeCompare(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

std::vector<uint8_t> base64Encode(const std::vector<uint8_t>& data) {
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<uint8_t> result;
    result.reserve((data.size() + 2) / 3 * 4);
    
    for (size_t i = 0; i < data.size(); i += 3) {
        uint32_t n = data[i] << 16;
        if (i + 1 < data.size()) n |= data[i + 1] << 8;
        if (i + 2 < data.size()) n |= data[i + 2];
        
        result.push_back(table[(n >> 18) & 0x3f]);
        result.push_back(table[(n >> 12) & 0x3f]);
        result.push_back(i + 1 < data.size() ? table[(n >> 6) & 0x3f] : '=');
        result.push_back(i + 2 < data.size() ? table[n & 0x3f] : '=');
    }
    return result;
}

std::vector<uint8_t> base64Decode(const std::vector<uint8_t>& data) {
    static const int table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
    };
    
    std::vector<uint8_t> result;
    result.reserve(data.size() * 3 / 4);
    
    uint32_t n = 0;
    int bits = 0;
    for (uint8_t c : data) {
        if (c == '=') break;
        int val = table[c];
        if (val < 0) continue;
        n = (n << 6) | val;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            result.push_back((n >> bits) & 0xff);
        }
    }
    return result;
}

std::string base58Encode(const std::vector<uint8_t>& data) {
    static const char alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    
    std::vector<uint8_t> digits(data.size() * 138 / 100 + 1, 0);
    size_t digitsLen = 1;
    
    for (size_t i = 0; i < data.size(); i++) {
        uint32_t carry = data[i];
        for (size_t j = 0; j < digitsLen; j++) {
            carry += static_cast<uint32_t>(digits[j]) << 8;
            digits[j] = carry % 58;
            carry /= 58;
        }
        while (carry > 0) {
            digits[digitsLen++] = carry % 58;
            carry /= 58;
        }
    }
    
    std::string result;
    for (size_t i = 0; i < data.size() && data[i] == 0; i++) {
        result += alphabet[0];
    }
    for (size_t i = digitsLen; i-- > 0; ) {
        result += alphabet[digits[i]];
    }
    return result;
}

std::vector<uint8_t> base58Decode(const std::string& str) {
    static const int8_t table[] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8,-1,-1,-1,-1,-1,-1,
        -1, 9,10,11,12,13,14,15,16,-1,17,18,19,20,21,-1,
        22,23,24,25,26,27,28,29,30,31,32,-1,-1,-1,-1,-1,
        -1,33,34,35,36,37,38,39,40,41,42,43,-1,44,45,46,
        47,48,49,50,51,52,53,54,55,56,57,-1,-1,-1,-1,-1
    };
    
    std::vector<uint8_t> bytes(str.size() * 733 / 1000 + 1, 0);
    size_t bytesLen = 1;
    
    for (char c : str) {
        uint8_t uc = static_cast<uint8_t>(c);
        int8_t val = table[uc];
        if (val < 0) return {};
        
        uint32_t carry = val;
        for (size_t i = 0; i < bytesLen; i++) {
            carry += bytes[i] * 58;
            bytes[i] = carry & 0xff;
            carry >>= 8;
        }
        while (carry > 0) {
            bytes[bytesLen++] = carry & 0xff;
            carry >>= 8;
        }
    }
    
    std::vector<uint8_t> result;
    for (char c : str) {
        if (c != '1') break;
        result.push_back(0);
    }
    for (size_t i = bytesLen; i-- > 0; ) {
        result.push_back(bytes[i]);
    }
    return result;
}

}
}
