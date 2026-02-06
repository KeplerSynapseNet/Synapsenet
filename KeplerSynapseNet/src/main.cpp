#include <iostream>
#include <string>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>
#include <ctime>
#include <vector>
#include <memory>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <unordered_map>
#include <unordered_set>
#include <condition_variable>
#include <random>
#include <filesystem>
#include <algorithm>
#include <utility>
#include <cmath>
#include <stdexcept>
#include <limits>
#include <optional>
#include <cctype>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>

#include "core/ledger.h"
#include "core/knowledge.h"
#include "core/transfer.h"
#include "core/consensus.h"
#include "core/poe_v1_engine.h"
#if SYNAPSE_BUILD_TUI
#include "tui/tui.h"
#endif
#include "network/network.h"
#include "network/discovery.h"
#include "model/model_loader.h"
#include "model/model_access.h"
#include "crypto/crypto.h"
#include "crypto/keys.h"
#include "database/database.h"
#include "utils/logger.h"
#include "utils/config.h"
#include "utils/single_instance.h"
#include "utils/utils.h"
#include "privacy/privacy.h"
#include "python/sandbox.h"
#include "quantum/quantum_security.h"
#include "infrastructure/messages.h"
#include "web/rpc_server.h"
#include "web/web.h"
#include "../third_party/llama.cpp/vendor/nlohmann/json.hpp"

namespace synapse {

using json = nlohmann::json;

static std::atomic<bool> g_running{true};
static std::atomic<bool> g_reloadConfig{false};
static std::atomic<bool> g_daemonMode{false};

// Forward declarations
std::string formatUptime(uint64_t seconds);

struct NodeConfig {
    std::string dataDir;
    std::string configPath;
    std::string networkType = "mainnet";
    std::string logLevel = "info";
    std::string bindAddress = "0.0.0.0";
    uint16_t port = 8333;
    uint16_t rpcPort = 8332;
    uint32_t maxPeers = 125;
    uint32_t maxConnections = 125;
    uint32_t maxInbound = 100;
    uint32_t maxOutbound = 25;
    uint32_t dbCacheSize = 450;
    uint32_t maxMempool = 300;
    bool daemon = false;
    bool tui = true;
    bool amnesia = false;
    bool testnet = false;
    bool regtest = false;
    bool discovery = true;
    bool showVersion = false;
    bool showHelp = false;
    bool privacyMode = false;
    bool quantumSecurity = false;
    bool resetNgt = false;
    bool dev = false;
    std::string poeValidators;
    std::string poeValidatorMode = "static"; // static|stake
    std::string poeMinStake = "0";           // NGT (decimal), used when poeValidatorMode == "stake"
    bool cli = false;
    std::string securityLevel = "standard";
    std::vector<std::string> connectNodes;
    std::vector<std::string> addNodes;
    std::vector<std::string> seedNodes;
    std::vector<std::string> commandArgs;
};

struct NodeStats {
    uint64_t uptime = 0;
    uint64_t peersConnected = 0;
    uint64_t peersInbound = 0;
    uint64_t peersOutbound = 0;
    uint64_t knowledgeEntries = 0;
    uint64_t transactionsProcessed = 0;
    uint64_t blocksValidated = 0;
    uint64_t modelRequests = 0;
    uint64_t bytesReceived = 0;
    uint64_t bytesSent = 0;
    double syncProgress = 0.0;
    double cpuUsage = 0.0;
    uint64_t memoryUsage = 0;
    uint64_t diskUsage = 0;
};

struct SystemInfo {
    std::string osName;
    std::string osVersion;
    std::string architecture;
    uint32_t cpuCores;
    uint64_t totalMemory;
    uint64_t availableMemory;
    uint64_t totalDisk;
    uint64_t availableDisk;
};

class SynapseNet {
public:
    SynapseNet() : running_(false), startTime_(0), syncProgress_(0.0) {}
    ~SynapseNet() { shutdown(); }
    
    bool initialize(const NodeConfig& config) {
        config_ = config;
        for (char& c : config_.poeValidatorMode) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (config_.poeValidatorMode != "stake") config_.poeValidatorMode = "static";
        if (config_.poeMinStake.empty()) config_.poeMinStake = "0";
        utils::Config::instance().setDataDir(config_.dataDir);
        
	        utils::Logger::init(config_.dataDir + "/synapsenet.log");
	        utils::Logger::enableConsole(!config_.tui);
	        setLogLevel(config_.logLevel);
	        utils::Logger::info("SynapseNet v0.1.0 starting...");
	        utils::Logger::info("Data directory: " + config_.dataDir);
        
        if (!config_.tui) std::cout << "Loading configuration..." << std::endl;
        if (!loadConfiguration()) {
            utils::Logger::error("Failed to load configuration");
            return false;
        }
        
        if (!config_.tui) std::cout << "Initializing database..." << std::endl;
        if (!initDatabase()) return false;
        
        if (!config_.tui) std::cout << "Initializing crypto..." << std::endl;
        if (!initCrypto()) return false;
        
        if (!config_.tui) std::cout << "Initializing quantum security..." << std::endl;
        if (!initQuantumSecurity()) return false;

        if (!config_.cli) {
            if (!config_.tui) std::cout << "Initializing network..." << std::endl;
            if (!initNetwork()) return false;
        }
        
	        if (!config_.tui) std::cout << "Initializing core..." << std::endl;
	        if (!initCore()) return false;

	        bool needsModel = !config_.cli;
	        if (config_.cli && !config_.commandArgs.empty()) {
	            const std::string cmd = config_.commandArgs[0];
	            needsModel = (cmd == "model" || cmd == "ai");
	        }

	        if (needsModel) {
	            if (!config_.tui) std::cout << "Initializing model..." << std::endl;
	            if (!initModel()) return false;
	        }

	        if (!config_.cli) {
	            if (!config_.tui) std::cout << "Initializing privacy..." << std::endl;
	            if (!initPrivacy()) return false;

	            if (!config_.tui) std::cout << "Initializing RPC..." << std::endl;
            if (!initRPC()) return false;

            if (!config_.tui) std::cout << "Initializing mempool..." << std::endl;
            if (!initMempool()) return false;
        }
        
        utils::Logger::info("All subsystems initialized successfully");
        if (!config_.tui) std::cout << "Initialization complete!" << std::endl;
        return true;
    }

	private:
	    enum class PoeInvKind : uint8_t { ENTRY = 1, VOTE = 2, EPOCH = 3 };
	    struct PoeSyncState {
	        bool active = false;
	        bool done = false;
	        bool inFlight = false;
	        crypto::Hash256 after{};
	        uint32_t limit = 0;
	        uint64_t lastRequestAt = 0;
	        uint64_t pages = 0;
	    };
	    struct PoePeerSyncState {
	        PoeSyncState entries;
	        PoeSyncState votes;
	        PoeSyncState epochs;
	    };

        // Remote model routing (opt-in)
        struct RemoteOfferCache {
            synapse::RemoteModelOfferMessage offer;
            std::string peerId;
            uint64_t receivedAt = 0;
        };

        struct RemoteSessionInfo {
            std::string peerId;
            std::string sessionId;
            std::string providerAddress;
            uint64_t pricePerRequestAtoms = 0;
            uint64_t expiresAt = 0;
        };

        struct RemotePending {
            bool done = false;
            std::string text;
            uint32_t tokensUsed = 0;
            uint64_t latencyMs = 0;
        };

        struct ProviderSession {
            std::string renterId;
            uint64_t expiresAt = 0;
            uint64_t pricePerRequestAtoms = 0;
        };

	    json parseRpcParams(const std::string& paramsJson) const {
	    if (paramsJson.empty()) {
	        return json::object();
	    }
    json parsed = json::parse(paramsJson, nullptr, false);
    if (parsed.is_discarded()) {
        throw std::runtime_error("Invalid JSON params");
    }
    if (parsed.is_array()) {
        if (parsed.empty()) return json::object();
        if (!parsed.front().is_object()) {
            throw std::runtime_error("Expected object params");
        }
        return parsed.front();
    }
    if (!parsed.is_object()) {
        throw std::runtime_error("Expected object params");
    }
    return parsed;
}

crypto::Hash256 parseHash256Hex(const std::string& hex) const {
    crypto::Hash256 out{};
    auto bytes = crypto::fromHex(hex);
    if (bytes.size() != out.size()) {
        throw std::runtime_error("Expected 32-byte hex string");
    }
    std::memcpy(out.data(), bytes.data(), out.size());
    return out;
}

uint64_t parseNgtAtomic(const std::string& value) const {
    if (value.empty()) {
        throw std::runtime_error("Empty amount");
    }
    std::string t = value;
    for (auto& c : t) {
        if (c == ',') c = '.';
    }
    size_t dot = t.find('.');
    std::string intPart = dot == std::string::npos ? t : t.substr(0, dot);
    std::string fracPart = dot == std::string::npos ? "" : t.substr(dot + 1);
    if (intPart.empty()) intPart = "0";
    if (fracPart.size() > 8) {
        throw std::runtime_error("Too many decimals");
    }
    unsigned __int128 iv = 0;
    for (char c : intPart) {
        if (c < '0' || c > '9') throw std::runtime_error("Invalid number");
        iv = iv * 10 + static_cast<unsigned>(c - '0');
    }
    unsigned __int128 fv = 0;
    for (char c : fracPart) {
        if (c < '0' || c > '9') throw std::runtime_error("Invalid number");
        fv = fv * 10 + static_cast<unsigned>(c - '0');
    }
    for (size_t i = fracPart.size(); i < 8; ++i) fv *= 10;
    unsigned __int128 total = iv * 100000000ULL + fv;
    if (total > std::numeric_limits<uint64_t>::max()) {
        throw std::runtime_error("Amount too large");
    }
    return static_cast<uint64_t>(total);
}

double atomsToNgt(uint64_t atoms) const {
    return static_cast<double>(atoms) / 100000000.0;
}

std::string addressFromPubKey(const crypto::PublicKey& pubKey) const {
    std::string hex = crypto::toHex(pubKey);
    if (hex.size() < 52) return {};
    return "ngt1" + hex.substr(0, 52);
}

uint64_t poeMinStakeAtoms() const {
    try {
        return parseNgtAtomic(config_.poeMinStake);
    } catch (...) {
        return 0;
    }
}

void updatePoeValidatorsFromStake() {
    if (!poeV1_ || !transfer_) return;
    if (config_.poeValidatorMode != "stake") return;

    crypto::PublicKey selfPub{};
    bool hasSelfPub = false;
    if (keys_ && keys_->isValid()) {
        auto pubV = keys_->getPublicKey();
        if (pubV.size() >= crypto::PUBLIC_KEY_SIZE) {
            std::memcpy(selfPub.data(), pubV.data(), selfPub.size());
            hasSelfPub = true;
        }
    }

    std::vector<crypto::PublicKey> candidates;
    candidates.reserve(256);

    auto addPk = [&](const crypto::PublicKey& pk) {
        if (std::all_of(pk.begin(), pk.end(), [](uint8_t b) { return b == 0; })) return;
        candidates.push_back(pk);
    };

    auto addValidatorHex = [&](const std::string& token) {
        std::string t = token;
        auto isSpace = [](unsigned char c) { return std::isspace(c) != 0; };
        while (!t.empty() && isSpace(static_cast<unsigned char>(t.front()))) t.erase(t.begin());
        while (!t.empty() && isSpace(static_cast<unsigned char>(t.back()))) t.pop_back();
        if (t.empty()) return;

        if (t == "self") {
            if (hasSelfPub) addPk(selfPub);
            return;
        }

        if (t.rfind("0x", 0) == 0 || t.rfind("0X", 0) == 0) t = t.substr(2);
        auto bytes = crypto::fromHex(t);
        if (bytes.size() != crypto::PUBLIC_KEY_SIZE) return;
        crypto::PublicKey pk{};
        std::memcpy(pk.data(), bytes.data(), pk.size());
        addPk(pk);
    };

    if (!config_.poeValidators.empty()) {
        std::string raw = config_.poeValidators;
        for (char& c : raw) {
            if (c == ';') c = ',';
        }
        std::string cur;
        for (char c : raw) {
            if (c == ',') {
                addValidatorHex(cur);
                cur.clear();
            } else {
                cur.push_back(c);
            }
        }
        addValidatorHex(cur);
    }

    for (const auto& pk : poeV1_->getStaticValidators()) addPk(pk);

    for (const auto& sid : poeV1_->listEntryIds(0)) {
        auto e = poeV1_->getEntry(sid);
        if (e) addPk(e->authorPubKey);
    }
    for (const auto& vid : poeV1_->listVoteIds(0)) {
        auto v = poeV1_->getVoteById(vid);
        if (v) addPk(v->validatorPubKey);
    }

    std::sort(candidates.begin(), candidates.end(), [](const crypto::PublicKey& a, const crypto::PublicKey& b) {
        return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
    });
    candidates.erase(std::unique(candidates.begin(), candidates.end(), [](const crypto::PublicKey& a, const crypto::PublicKey& b) {
        return a == b;
    }), candidates.end());

    uint64_t minStake = poeMinStakeAtoms();
    std::vector<crypto::PublicKey> eligible;
    eligible.reserve(candidates.size());
    for (const auto& pk : candidates) {
        std::string addr = addressFromPubKey(pk);
        if (addr.empty()) continue;
        uint64_t bal = transfer_->getBalance(addr);
        if (bal >= minStake) eligible.push_back(pk);
    }

    if (eligible.empty() && hasSelfPub) eligible.push_back(selfPub);
    if (!eligible.empty()) poeV1_->setStaticValidators(eligible);
}

std::filesystem::path poeDbPath() const {
    std::filesystem::path path = std::filesystem::path(config_.dataDir) / "poe" / "poe.db";
    return path;
}

crypto::Hash256 rewardIdForAcceptance(const crypto::Hash256& submitId) {
    std::vector<uint8_t> buf;
    const std::string tag = "poe_v1_accept";
    buf.insert(buf.end(), tag.begin(), tag.end());
    buf.insert(buf.end(), submitId.begin(), submitId.end());
    return crypto::sha256(buf.data(), buf.size());
}

crypto::Hash256 rewardIdForEpoch(uint64_t epochId, const crypto::Hash256& contentId) {
    std::vector<uint8_t> buf;
    const std::string tag = "poe_v1_epoch";
    buf.insert(buf.end(), tag.begin(), tag.end());
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<uint8_t>((epochId >> (8 * i)) & 0xFF));
    }
    buf.insert(buf.end(), contentId.begin(), contentId.end());
    return crypto::sha256(buf.data(), buf.size());
}

std::string handleRpcPoeSubmit(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    std::string typeStr = params.value("type", "");
    std::string question = params.value("question", "");
    std::string answer = params.value("answer", "");
    std::string source = params.value("source", "");
    bool autoFinalize = params.value("auto_finalize", true);

    if (!poeV1_ || !transfer_ || !keys_ || !keys_->isValid() || address_.empty()) {
        throw std::runtime_error("PoE or wallet not ready");
    }

    auto lower = [](std::string s) {
        for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return s;
    };

    core::poe_v1::ContentType type = core::poe_v1::ContentType::QA;
    if (!typeStr.empty()) {
        std::string t = lower(typeStr);
        if (t == "qa" || t == "qna") type = core::poe_v1::ContentType::QA;
        else if (t == "text") type = core::poe_v1::ContentType::TEXT;
        else if (t == "code" || t == "patch") type = core::poe_v1::ContentType::CODE;
        else if (t == "linklist" || t == "links") type = core::poe_v1::ContentType::LINKLIST;
        else if (t == "other") type = core::poe_v1::ContentType::OTHER;
        else throw std::runtime_error("unknown type");
    }

    std::vector<crypto::Hash256> citations;
    if (params.contains("citations")) {
        if (!params["citations"].is_array()) {
            throw std::runtime_error("citations must be array");
        }
        for (const auto& item : params["citations"]) {
            if (!item.is_string()) throw std::runtime_error("citation must be hex string");
            citations.push_back(parseHash256Hex(item.get<std::string>()));
        }
    }

    crypto::PrivateKey pk{};
    auto pkv = keys_->getPrivateKey();
    if (pkv.size() < pk.size()) {
        throw std::runtime_error("Invalid private key");
    }
    std::memcpy(pk.data(), pkv.data(), pk.size());

    std::string title;
    std::string body;
    if (type == core::poe_v1::ContentType::QA) {
        if (question.empty() || answer.empty()) {
            throw std::runtime_error("question and answer are required");
        }
        title = question;
        body = answer;
        if (!source.empty()) {
            body += "\nsource: " + source;
        }
    } else if (type == core::poe_v1::ContentType::CODE) {
        title = params.value("title", "");
        body = params.value("patch", "");
        if (body.empty()) body = params.value("body", "");
        if (title.empty() || body.empty()) {
            throw std::runtime_error("title and patch/body are required");
        }
    } else {
        title = params.value("title", "");
        body = params.value("body", "");
        if (title.empty() || body.empty()) {
            throw std::runtime_error("title and body are required");
        }
    }

    updatePoeValidatorsFromStake();
    auto submitRes = poeV1_->submit(type, title, body, citations, pk, autoFinalize);
    if (!submitRes.ok) {
        throw std::runtime_error("PoE submit failed: " + submitRes.error);
    }

    crypto::PublicKey authorPub = crypto::derivePublicKey(pk);
    std::string authorAddr = addressFromPubKey(authorPub);
    if (authorAddr.empty()) authorAddr = address_;

    uint64_t credited = 0;
    if (submitRes.finalized && submitRes.acceptanceReward > 0) {
        crypto::Hash256 rewardId = rewardIdForAcceptance(submitRes.submitId);
        if (transfer_->creditRewardDeterministic(authorAddr, rewardId, submitRes.acceptanceReward)) {
            credited = submitRes.acceptanceReward;
        }
    }

    {
        std::lock_guard<std::mutex> lock(invMtx_);
        knownPoeEntries_.insert(crypto::toHex(submitRes.submitId));
    }
    broadcastInv(synapse::InvType::POE_ENTRY, submitRes.submitId);
    for (const auto& v : poeV1_->getVotesForSubmit(submitRes.submitId)) {
        crypto::Hash256 vid = v.payloadHash();
        {
            std::lock_guard<std::mutex> lock(invMtx_);
                knownPoeVotes_.insert(crypto::toHex(vid));
        }
        broadcastInv(synapse::InvType::POE_VOTE, vid);
    }

    if (ledger_) {
        auto pub = keys_->getPublicKey();
        auto entry = poeV1_->getEntry(submitRes.submitId);
        if (entry) {
            core::Event ev{};
            ev.timestamp = entry->timestamp;
            ev.type = core::EventType::POE_ENTRY;
            ev.data = entry->serialize();
            if (pub.size() >= ev.author.size()) {
                std::memcpy(ev.author.data(), pub.data(), ev.author.size());
            }
            ledger_->append(ev);
        }

        for (const auto& v : poeV1_->getVotesForSubmit(submitRes.submitId)) {
            core::Event ev{};
            ev.timestamp = std::time(nullptr);
            ev.type = core::EventType::POE_VOTE;
            ev.data = v.serialize();
            if (pub.size() >= ev.author.size()) {
                std::memcpy(ev.author.data(), pub.data(), ev.author.size());
            }
            ledger_->append(ev);
        }
    }

    json result;
    result["status"] = "ok";
    result["submitId"] = crypto::toHex(submitRes.submitId);
    result["contentId"] = crypto::toHex(submitRes.contentId);
    result["contentType"] = static_cast<int>(type);
    result["finalized"] = submitRes.finalized;
    result["acceptanceRewardAtoms"] = submitRes.acceptanceReward;
    result["acceptanceReward"] = atomsToNgt(submitRes.acceptanceReward);
    result["creditedAtoms"] = credited;
    result["credited"] = atomsToNgt(credited);

    return result.dump();
}

std::string handleRpcPoeSubmitCode(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    params["type"] = "code";
    if (!params.contains("body") && params.contains("patch")) {
        params["body"] = params["patch"];
    }
    return handleRpcPoeSubmit(params.dump());
}

std::string handleRpcPoeListCode(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    size_t limit = 25;
    if (params.contains("limit")) {
        limit = static_cast<size_t>(std::max(1, params.value("limit", 25)));
    }
    if (!poeV1_) {
        throw std::runtime_error("PoE not ready");
    }

    json out = json::array();
    auto ids = poeV1_->listEntryIds(0);
    for (auto it = ids.rbegin(); it != ids.rend() && out.size() < limit; ++it) {
        auto e = poeV1_->getEntry(*it);
        if (!e) continue;
        if (e->contentType != core::poe_v1::ContentType::CODE) continue;
        json item;
        item["submitId"] = crypto::toHex(*it);
        item["contentId"] = crypto::toHex(e->contentId());
        item["timestamp"] = e->timestamp;
        item["title"] = e->title;
        item["finalized"] = poeV1_->isFinalized(*it);
        out.push_back(item);
    }
    return out.dump();
}

std::string handleRpcPoeFetchCode(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    std::string idHex = params.value("id", "");
    if (idHex.empty()) idHex = params.value("submitId", "");
    if (idHex.empty()) idHex = params.value("contentId", "");
    if (idHex.empty()) {
        throw std::runtime_error("id required");
    }
    if (!poeV1_) {
        throw std::runtime_error("PoE not ready");
    }

    crypto::Hash256 id = parseHash256Hex(idHex);
    auto entry = poeV1_->getEntry(id);
    crypto::Hash256 submitId = id;
    if (!entry) {
        entry = poeV1_->getEntryByContentId(id);
        if (entry) submitId = entry->submitId();
    }
    if (!entry) {
        throw std::runtime_error("not_found");
    }
    if (entry->contentType != core::poe_v1::ContentType::CODE) {
        throw std::runtime_error("not_code_entry");
    }

    json out;
    out["submitId"] = crypto::toHex(submitId);
    out["contentId"] = crypto::toHex(entry->contentId());
    out["timestamp"] = entry->timestamp;
    out["authorPubKey"] = crypto::toHex(entry->authorPubKey);
    out["title"] = entry->title;
    out["patch"] = entry->body;
    json cites = json::array();
    for (const auto& c : entry->citations) cites.push_back(crypto::toHex(c));
    out["citations"] = cites;
    out["finalized"] = poeV1_->isFinalized(submitId);
    uint64_t expected = poeV1_->calculateAcceptanceReward(*entry);
    out["acceptanceRewardAtoms"] = expected;
    out["acceptanceReward"] = atomsToNgt(expected);
    return out.dump();
}

std::string handleRpcPoeVote(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    if (!poeV1_ || !keys_ || !keys_->isValid()) {
        throw std::runtime_error("PoE or wallet not ready");
    }
    std::string submitHex = params.value("submitId", "");
    if (submitHex.empty()) {
        throw std::runtime_error("submitId required");
    }
    crypto::Hash256 submitId = parseHash256Hex(submitHex);

    crypto::PrivateKey pk{};
    auto pkv = keys_->getPrivateKey();
    if (pkv.size() < pk.size()) {
        throw std::runtime_error("Invalid private key");
    }
    std::memcpy(pk.data(), pkv.data(), pk.size());

    core::poe_v1::ValidationVoteV1 vote;
    vote.version = 1;
    vote.submitId = submitId;
    vote.prevBlockHash = poeV1_->chainSeed();
    vote.flags = params.value("flags", 0);
    if (params.contains("scores")) {
        const auto& scores = params["scores"];
        if (!scores.is_array() || scores.size() != 3) {
            throw std::runtime_error("scores must be array of 3 integers");
        }
        for (size_t i = 0; i < 3; ++i) {
            vote.scores[i] = static_cast<uint16_t>(scores[i].get<int>());
        }
    } else {
        vote.scores = {100, 100, 100};
    }
    core::poe_v1::signValidationVoteV1(vote, pk);
    bool added = poeV1_->addVote(vote);

    crypto::Hash256 voteId = vote.payloadHash();
    if (added) {
        {
            std::lock_guard<std::mutex> lock(invMtx_);
            knownPoeVotes_.insert(crypto::toHex(voteId));
        }
        broadcastInv(synapse::InvType::POE_VOTE, voteId);

        if (ledger_) {
            core::Event ev{};
            ev.timestamp = std::time(nullptr);
            ev.type = core::EventType::POE_VOTE;
            ev.data = vote.serialize();
            auto pub = keys_->getPublicKey();
            if (pub.size() >= ev.author.size()) {
                std::memcpy(ev.author.data(), pub.data(), ev.author.size());
            }
            ledger_->append(ev);
        }
    }

    uint64_t credited = maybeCreditAcceptanceReward(submitId);

    json result;
    result["status"] = added ? "vote_added" : "vote_duplicate";
    result["added"] = added;
    result["voteId"] = crypto::toHex(voteId);
    result["creditedAtoms"] = credited;
    result["credited"] = atomsToNgt(credited);
    return result.dump();
}

std::string handleRpcPoeFinalize(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    if (!poeV1_) {
        throw std::runtime_error("PoE not ready");
    }
    std::string submitHex = params.value("submitId", "");
    if (submitHex.empty()) {
        throw std::runtime_error("submitId required");
    }
    crypto::Hash256 submitId = parseHash256Hex(submitHex);
    auto fin = poeV1_->finalize(submitId);
    uint64_t credited = maybeCreditAcceptanceReward(submitId);

    json result;
    if (!fin) {
        result["status"] = "pending";
        result["finalized"] = false;
    } else {
        result["status"] = "finalized";
        result["finalized"] = true;
        result["finalizedAt"] = fin->finalizedAt;
        result["validatorSetHash"] = crypto::toHex(fin->validatorSetHash);
        result["voteCount"] = fin->votes.size();
    }
    result["creditedAtoms"] = credited;
    result["credited"] = atomsToNgt(credited);
    return result.dump();
}

	    std::string handleRpcPoeEpoch(const std::string& paramsJson) {
	        auto params = parseRpcParams(paramsJson);
	        if (!poeV1_ || !transfer_) {
	            throw std::runtime_error("PoE/transfer not ready");
    }

    uint64_t budget = 0;
    if (params.contains("budget_atoms")) {
        budget = params["budget_atoms"].get<uint64_t>();
    } else if (params.contains("budget")) {
        if (params["budget"].is_number()) {
            double v = params["budget"].get<double>();
            budget = static_cast<uint64_t>(std::llround(v * 100000000.0));
        } else if (params["budget"].is_string()) {
            budget = parseNgtAtomic(params["budget"].get<std::string>());
        } else {
            throw std::runtime_error("budget must be number or string");
        }
    } else {
        int64_t cfgBudget = utils::Config::instance().getInt64(
            "poe.epoch_budget",
            config_.dev ? 100000000LL : 1000000000LL);
        if (cfgBudget > 0) budget = static_cast<uint64_t>(cfgBudget);
    }

    uint32_t iterations = params.value("iterations",
        static_cast<uint32_t>(std::max(1, utils::Config::instance().getInt(
            "poe.epoch_iterations",
            config_.dev ? 10 : 20))));

    bool creditRewards = params.value("credit_rewards", true);

	    auto epochRes = poeV1_->runEpoch(budget, iterations);
	    if (!epochRes.ok) {
	        throw std::runtime_error("PoE epoch failed: " + epochRes.error);
	    }

	    {
	        crypto::Hash256 hid = poeEpochInvHash(epochRes.epochId);
	        std::lock_guard<std::mutex> lock(invMtx_);
	        knownPoeEpochs_.insert(crypto::toHex(hid));
	    }
	    broadcastInv(synapse::InvType::POE_EPOCH, poeEpochInvHash(epochRes.epochId));

	    uint64_t mintedTotal = 0;
	    uint64_t mintedMine = 0;
	    uint64_t mintedCount = 0;
	    json allocations = json::array();

    for (const auto& alloc : epochRes.allocations) {
        std::string addr = addressFromPubKey(alloc.authorPubKey);
        crypto::Hash256 rid = rewardIdForEpoch(epochRes.epochId, alloc.contentId);
        bool credited = false;
        if (creditRewards && !addr.empty()) {
            if (transfer_->creditRewardDeterministic(addr, rid, alloc.amount)) {
                credited = true;
                mintedTotal += alloc.amount;
                mintedCount += 1;
                if (!address_.empty() && addr == address_) mintedMine += alloc.amount;
            }
        }
        json entry;
        entry["submitId"] = crypto::toHex(alloc.submitId);
        entry["contentId"] = crypto::toHex(alloc.contentId);
        entry["author"] = addr;
        entry["score"] = alloc.score;
        entry["amountAtoms"] = alloc.amount;
        entry["amount"] = atomsToNgt(alloc.amount);
        entry["credited"] = credited;
        allocations.push_back(entry);
    }

    json result;
    result["status"] = "ok";
    result["epochId"] = epochRes.epochId;
    result["allocationHash"] = crypto::toHex(epochRes.allocationHash);
    result["mintedAtoms"] = mintedTotal;
    result["minted"] = atomsToNgt(mintedTotal);
    result["mintedEntries"] = mintedCount;
    result["mintedSelfAtoms"] = mintedMine;
    result["mintedSelf"] = atomsToNgt(mintedMine);
    result["allocations"] = allocations;
    return result.dump();
}

std::string handleRpcPoeExport(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    std::string pathStr = params.value("path", "");
    if (pathStr.empty()) {
        throw std::runtime_error("path required");
    }
    std::filesystem::path target(pathStr);
    bool targetIsDir = std::filesystem::exists(target) ? std::filesystem::is_directory(target)
                                                       : target.has_filename() ? false : true;
    std::filesystem::path outDb = targetIsDir ? (target / "poe.db") : target;
    std::filesystem::create_directories(outDb.parent_path());

    auto srcDb = poeDbPath();
    auto srcWal = srcDb;
    srcWal += "-wal";
    auto srcShm = srcDb;
    srcShm += "-shm";

    std::error_code ec;
    std::filesystem::copy_file(srcDb, outDb, std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) throw std::runtime_error("copy DB failed: " + ec.message());

    json copied = json::array();
    copied.push_back(outDb.string());

    if (std::filesystem::exists(srcWal)) {
        auto outWal = outDb;
        outWal += "-wal";
        ec.clear();
        std::filesystem::copy_file(srcWal, outWal, std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) throw std::runtime_error("copy WAL failed: " + ec.message());
        copied.push_back(outWal.string());
    }
    if (std::filesystem::exists(srcShm)) {
        auto outShm = outDb;
        outShm += "-shm";
        ec.clear();
        std::filesystem::copy_file(srcShm, outShm, std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) throw std::runtime_error("copy SHM failed: " + ec.message());
        copied.push_back(outShm.string());
    }

    json result;
    result["status"] = "exported";
    result["paths"] = copied;
    return result.dump();
}

std::string handleRpcPoeImport(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    std::string pathStr = params.value("path", "");
    if (pathStr.empty()) {
        throw std::runtime_error("path required");
    }
    if (!poeV1_) {
        throw std::runtime_error("PoE not ready");
    }

    std::filesystem::path target(pathStr);
    bool targetIsDir = std::filesystem::exists(target) ? std::filesystem::is_directory(target)
                                                       : target.has_filename() ? false : true;
    std::filesystem::path inDb = targetIsDir ? (target / "poe.db") : target;
    if (!std::filesystem::exists(inDb)) {
        throw std::runtime_error("source DB not found");
    }
    auto inWal = inDb;
    inWal += "-wal";
    auto inShm = inDb;
    inShm += "-shm";

    auto destDb = poeDbPath();
    auto destWal = destDb;
    destWal += "-wal";
    auto destShm = destDb;
    destShm += "-shm";

    auto cfg = poeV1_->getConfig();
    auto validators = poeV1_->getStaticValidators();
    poeV1_->close();

    std::filesystem::create_directories(destDb.parent_path());
    std::error_code ec;
    std::filesystem::copy_file(inDb, destDb, std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) throw std::runtime_error("copy DB failed: " + ec.message());

    if (std::filesystem::exists(inWal)) {
        ec.clear();
        std::filesystem::copy_file(inWal, destWal, std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) throw std::runtime_error("copy WAL failed: " + ec.message());
    }
    if (std::filesystem::exists(inShm)) {
        ec.clear();
        std::filesystem::copy_file(inShm, destShm, std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) throw std::runtime_error("copy SHM failed: " + ec.message());
    }

    if (!poeV1_->open(destDb.string())) {
        throw std::runtime_error("Failed to reopen PoE DB");
    }
    poeV1_->setConfig(cfg);
    if (!validators.empty()) {
        poeV1_->setStaticValidators(validators);
    }

    json result;
    result["status"] = "imported";
    result["path"] = destDb.string();
    return result.dump();
}

std::string handleRpcWalletAddress(const std::string& paramsJson) {
    (void)paramsJson;
    if (!keys_ || !keys_->isValid()) {
        throw std::runtime_error("Wallet not loaded");
    }
    auto pubV = keys_->getPublicKey();
    if (pubV.size() < crypto::PUBLIC_KEY_SIZE) {
        throw std::runtime_error("Invalid public key");
    }
    crypto::PublicKey pk{};
    std::memcpy(pk.data(), pubV.data(), pk.size());
    json result;
    result["address"] = address_;
    result["pubkey"] = crypto::toHex(pk);
    return result.dump();
}

std::string handleRpcWalletBalance(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    if (!transfer_) {
        throw std::runtime_error("Transfer not ready");
    }
    std::string addr = params.value("address", "");
    if (addr.empty()) addr = address_;
    if (addr.empty()) {
        throw std::runtime_error("address required");
    }
    uint64_t bal = transfer_->getBalance(addr);
    json result;
    result["address"] = addr;
    result["balanceAtoms"] = bal;
    result["balance"] = atomsToNgt(bal);
    result["totalSupplyAtoms"] = transfer_->totalSupply();
    result["totalSupply"] = atomsToNgt(transfer_->totalSupply());
    return result.dump();
}

static std::string modelStateToString(model::ModelState s) {
    switch (s) {
        case model::ModelState::UNLOADED: return "UNLOADED";
        case model::ModelState::LOADING: return "LOADING";
        case model::ModelState::READY: return "READY";
        case model::ModelState::GENERATING: return "GENERATING";
        case model::ModelState::ERROR: return "ERROR";
        case model::ModelState::DOWNLOADING: return "DOWNLOADING";
    }
    return "UNKNOWN";
}

std::string handleRpcModelStatus(const std::string& paramsJson) {
    (void)paramsJson;
    if (!modelLoader_) {
        throw std::runtime_error("Model not ready");
    }
    std::lock_guard<std::mutex> lock(modelMtx_);
    auto info = modelLoader_->getInfo();
    json out;
    out["loaded"] = modelLoader_->isLoaded();
    out["state"] = modelStateToString(modelLoader_->getState());
    out["generating"] = modelLoader_->isGenerating();
    out["name"] = info.name;
    out["path"] = info.path;
    out["sizeBytes"] = info.sizeBytes;
    out["error"] = modelLoader_->getError();
    out["requests"] = modelRequests_.load();
    return out.dump();
}

std::string handleRpcModelList(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    if (!modelLoader_) {
        throw std::runtime_error("Model not ready");
    }
    std::string dir = params.value("dir", "");
    if (dir.empty()) dir = config_.dataDir + "/models";
    std::lock_guard<std::mutex> lock(modelMtx_);
    auto models = modelLoader_->listModels(dir);
    json out = json::array();
    for (const auto& m : models) {
        json item;
        item["name"] = m.name;
        item["path"] = m.path;
        item["sizeBytes"] = m.sizeBytes;
        item["format"] = static_cast<int>(m.format);
        item["quantization"] = m.quantization;
        out.push_back(item);
    }
    return out.dump();
}

std::string handleRpcModelLoad(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    if (!modelLoader_) {
        throw std::runtime_error("Model not ready");
    }
    std::string path = params.value("path", "");
    std::string name = params.value("name", "");
    if (path.empty() && !name.empty()) {
        path = (std::filesystem::path(config_.dataDir) / "models" / name).string();
    }
    if (path.empty()) {
        throw std::runtime_error("path required");
    }
    if (!std::filesystem::exists(path)) {
        throw std::runtime_error("model_not_found");
    }

    model::LoaderConfig cfg = modelLoader_->getConfig();
    if (params.contains("contextSize")) cfg.contextSize = static_cast<uint32_t>(std::max(256, params.value("contextSize", 2048)));
    if (params.contains("threads")) cfg.threads = static_cast<uint32_t>(std::max(1, params.value("threads", 4)));
    if (params.contains("gpuLayers")) cfg.gpuLayers = static_cast<uint32_t>(std::max(0, params.value("gpuLayers", 0)));
    if (params.contains("useGpu")) cfg.useGpu = params.value("useGpu", false);
    if (params.contains("useMmap")) cfg.useMmap = params.value("useMmap", true);
    if (params.contains("useMlock")) cfg.useMlock = params.value("useMlock", false);

    std::lock_guard<std::mutex> lock(modelMtx_);
    bool ok = modelLoader_->load(path, cfg);

    json out;
    out["ok"] = ok;
    out["state"] = modelStateToString(modelLoader_->getState());
    out["error"] = modelLoader_->getError();
    auto info = modelLoader_->getInfo();
    out["name"] = info.name;
    out["path"] = info.path;
    out["sizeBytes"] = info.sizeBytes;

    if (ok) {
        utils::Config::instance().set("model.last_path", path);
        utils::Config::instance().save(config_.dataDir + "/synapsenet.conf");
    }

    return out.dump();
}

std::string handleRpcModelUnload(const std::string& paramsJson) {
    (void)paramsJson;
    if (!modelLoader_) {
        throw std::runtime_error("Model not ready");
    }
    std::lock_guard<std::mutex> lock(modelMtx_);
    bool ok = modelLoader_->unload();
    json out;
    out["ok"] = ok;
    out["state"] = modelStateToString(modelLoader_->getState());
    return out.dump();
}

std::string handleRpcModelRemoteList(const std::string& paramsJson) {
    (void)paramsJson;
    json out = json::array();
    const uint64_t now = std::time(nullptr);
    std::lock_guard<std::mutex> lock(remoteMtx_);
    for (const auto& [offerId, cache] : remoteOffers_) {
        const auto& o = cache.offer;
        if (o.expiresAt != 0 && o.expiresAt < now) continue;
        json item;
        item["offerId"] = offerId;
        item["peerId"] = cache.peerId;
        item["receivedAt"] = cache.receivedAt;
        item["modelId"] = o.modelId;
        item["providerAddress"] = o.providerAddress;
        item["pricePerRequestAtoms"] = o.pricePerRequestAtoms;
        item["maxSlots"] = o.maxSlots;
        item["usedSlots"] = o.usedSlots;
        item["expiresAt"] = o.expiresAt;
        out.push_back(item);
    }
    return out.dump();
}

std::string handleRpcModelRemoteRent(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    if (!network_) {
        throw std::runtime_error("network_not_ready");
    }
    if (!keys_ || !keys_->isValid()) {
        throw std::runtime_error("wallet_not_ready");
    }

    const std::string offerId = params.value("offerId", "");
    if (offerId.empty()) {
        throw std::runtime_error("offerId required");
    }

    RemoteOfferCache offer;
    {
        std::lock_guard<std::mutex> lock(remoteMtx_);
        auto it = remoteOffers_.find(offerId);
        if (it == remoteOffers_.end()) {
            throw std::runtime_error("offer_not_found");
        }
        offer = it->second;
    }

    synapse::RemoteModelRentMessage rent;
    rent.offerId = offerId;
    rent.timestamp = std::time(nullptr);
    auto pubV = keys_->getPublicKey();
    if (pubV.size() < rent.renterPubKey.size()) {
        throw std::runtime_error("invalid_pubkey");
    }
    std::memcpy(rent.renterPubKey.data(), pubV.data(), rent.renterPubKey.size());

    {
        std::lock_guard<std::mutex> lock(remoteMtx_);
        remoteRentOkByOffer_.erase(offerId);
    }

    network_->send(offer.peerId, makeMessage("m_rent", rent.serialize()));

    const uint64_t deadline = std::time(nullptr) + (config_.dev ? 10 : 30);
    synapse::RemoteModelRentOkMessage ok;
    for (;;) {
        std::unique_lock<std::mutex> lk(remoteMtx_);
        auto it = remoteRentOkByOffer_.find(offerId);
        if (it != remoteRentOkByOffer_.end()) {
            ok = it->second;
            break;
        }
        lk.unlock();
        if (std::time(nullptr) >= deadline) {
            throw std::runtime_error("rent_timeout");
        }
        std::unique_lock<std::mutex> waitLk(remoteMtx_);
        remoteCv_.wait_for(waitLk, std::chrono::milliseconds(250));
    }

    json out;
    out["ok"] = true;
    out["offerId"] = offerId;
    out["peerId"] = offer.peerId;
    out["sessionId"] = ok.sessionId;
    out["providerAddress"] = ok.providerAddress;
    out["pricePerRequestAtoms"] = ok.pricePerRequestAtoms;
    out["expiresAt"] = ok.expiresAt;
    return out.dump();
}

std::string handleRpcModelRemoteEnd(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    const std::string sessionId = params.value("sessionId", "");
    if (sessionId.empty()) throw std::runtime_error("sessionId required");
    std::lock_guard<std::mutex> lock(remoteMtx_);
    remoteSessions_.erase(sessionId);
    json out;
    out["ok"] = true;
    return out.dump();
}

static std::string accessModeToString(model::AccessMode m) {
    switch (m) {
        case model::AccessMode::PRIVATE: return "PRIVATE";
        case model::AccessMode::SHARED: return "SHARED";
        case model::AccessMode::PAID: return "PAID";
        case model::AccessMode::COMMUNITY: return "COMMUNITY";
    }
    return "UNKNOWN";
}

static model::AccessMode parseAccessMode(const std::string& s) {
    std::string t;
    t.reserve(s.size());
    for (char c : s) t.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    if (t == "PRIVATE") return model::AccessMode::PRIVATE;
    if (t == "SHARED") return model::AccessMode::SHARED;
    if (t == "PAID") return model::AccessMode::PAID;
    if (t == "COMMUNITY" || t == "PUBLIC") return model::AccessMode::COMMUNITY;
    throw std::runtime_error("invalid access mode");
}

std::string handleRpcModelAccessGet(const std::string& paramsJson) {
    (void)paramsJson;
    if (!modelAccess_) throw std::runtime_error("model access not ready");
    json out;
    out["mode"] = accessModeToString(modelAccess_->getMode());
    out["maxSlots"] = modelAccess_->getMaxSlots();
    out["activeSlots"] = modelAccess_->getActiveSlots();
    out["availableSlots"] = modelAccess_->getAvailableSlots();
    out["pricePerHourAtoms"] = modelAccess_->getPrice();
    out["remotePricePerRequestAtoms"] = remotePricePerRequestAtoms_;
    return out.dump();
}

std::string handleRpcModelAccessSet(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    if (!modelAccess_) throw std::runtime_error("model access not ready");

    bool changed = false;
    if (params.contains("mode") && params["mode"].is_string()) {
        modelAccess_->setMode(parseAccessMode(params["mode"].get<std::string>()));
        utils::Config::instance().set("model.access.mode", accessModeToString(modelAccess_->getMode()));
        changed = true;
    }
    if (params.contains("maxSlots")) {
        uint32_t slots = static_cast<uint32_t>(std::max(1, params.value("maxSlots", 3)));
        modelAccess_->setMaxSlots(slots);
        utils::Config::instance().set("model.access.max_slots", static_cast<int>(slots));
        changed = true;
    }
    if (params.contains("pricePerHourAtoms")) {
        uint64_t p = static_cast<uint64_t>(std::max<int64_t>(0, params.value("pricePerHourAtoms", 0)));
        modelAccess_->setPrice(p);
        utils::Config::instance().set("model.access.price_per_hour_atoms", static_cast<int64_t>(p));
        changed = true;
    }
    if (params.contains("remotePricePerRequestAtoms")) {
        uint64_t p = static_cast<uint64_t>(std::max<int64_t>(0, params.value("remotePricePerRequestAtoms", 0)));
        remotePricePerRequestAtoms_ = p;
        utils::Config::instance().set("model.remote.price_per_request_atoms", static_cast<int64_t>(p));
        changed = true;
    }

    if (changed) {
        utils::Config::instance().save(config_.dataDir + "/synapsenet.conf");
    }
    return handleRpcModelAccessGet("{}");
}

std::string handleRpcMarketListings(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    if (!modelMarketplace_) throw std::runtime_error("marketplace_not_ready");
    bool includeInactive = params.value("includeInactive", false);
    auto listings = modelMarketplace_->getAllListings(includeInactive);
    json out = json::array();
    for (const auto& l : listings) {
        json item;
        item["modelId"] = l.modelId;
        item["ownerId"] = l.ownerId;
        item["name"] = l.name;
        item["description"] = l.description;
        item["sizeBytes"] = l.size;
        item["format"] = l.format;
        item["pricePerHourAtoms"] = l.pricePerHourAtoms;
        item["pricePerRequestAtoms"] = l.pricePerRequestAtoms;
        item["maxSlots"] = l.maxSlots;
        item["usedSlots"] = l.usedSlots;
        item["availableSlots"] = l.availableSlots;
        item["ratingMilli"] = l.ratingMilli;
        item["ratingCount"] = l.ratingCount;
        item["totalRequests"] = l.totalRequests;
        item["totalEarningsAtoms"] = l.totalEarningsAtoms;
        item["active"] = l.active;
        item["createdAt"] = l.createdAt;
        item["lastActive"] = l.lastActive;
        out.push_back(item);
    }
    return out.dump();
}

std::string handleRpcMarketStats(const std::string& paramsJson) {
    (void)paramsJson;
    if (!modelMarketplace_) throw std::runtime_error("marketplace_not_ready");
    auto st = modelMarketplace_->getStats();
    json out;
    out["totalListings"] = st.totalListings;
    out["activeListings"] = st.activeListings;
    out["totalRentals"] = st.totalRentals;
    out["activeRentals"] = st.activeRentals;
    out["totalSessions"] = st.totalSessions;
    out["activeSessions"] = st.activeSessions;
    out["totalRequests"] = st.totalRequests;
    out["totalVolumeAtoms"] = st.totalVolumeAtoms;
    out["totalEarningsAtoms"] = st.totalEarningsAtoms;
    out["avgPricePerRequestAtoms"] = st.avgPricePerRequestAtoms;
    return out.dump();
}

std::string createAndSubmitPaymentTx(const std::string& to, uint64_t amountAtoms, uint64_t& feeAtomsOut) {
    if (!transfer_ || !keys_ || !keys_->isValid() || address_.empty()) {
        throw std::runtime_error("wallet/transfer not ready");
    }
    if (amountAtoms == 0) {
        feeAtomsOut = 0;
        return "";
    }
    if (!transfer_->hasSufficientBalance(address_, amountAtoms)) {
        throw std::runtime_error("insufficient_balance");
    }

    uint64_t fee = transfer_->estimateFee(0);
    core::Transaction tx;
    for (int i = 0; i < 5; ++i) {
        tx = transfer_->createTransaction(address_, to, amountAtoms, fee);
        uint64_t requiredFee = transfer_->estimateFee(tx.serialize().size());
        if (requiredFee == fee) break;
        fee = requiredFee;
    }

    crypto::PrivateKey pk{};
    auto pkv = keys_->getPrivateKey();
    if (pkv.size() < pk.size()) {
        throw std::runtime_error("invalid private key");
    }
    std::memcpy(pk.data(), pkv.data(), pk.size());
    if (!transfer_->signTransaction(tx, pk)) {
        throw std::runtime_error("failed_to_sign_tx");
    }
    if (!transfer_->submitTransaction(tx)) {
        throw std::runtime_error("failed_to_submit_tx");
    }
    feeAtomsOut = fee;
    return crypto::toHex(tx.txid);
}

std::string handleRpcAiCompleteRemote(const json& params, const std::string& prompt, const model::GenerationParams& gp) {
    if (!network_) throw std::runtime_error("network_not_ready");
    if (!keys_ || !keys_->isValid()) throw std::runtime_error("wallet_not_ready");

    const std::string sessionId = params.value("remoteSessionId", params.value("sessionId", ""));
    if (sessionId.empty()) throw std::runtime_error("remoteSessionId required");

    RemoteSessionInfo session;
    {
        std::lock_guard<std::mutex> lock(remoteMtx_);
        auto it = remoteSessions_.find(sessionId);
        if (it == remoteSessions_.end()) throw std::runtime_error("remote_session_not_found");
        session = it->second;
    }
    const uint64_t now = std::time(nullptr);
    if (session.expiresAt != 0 && session.expiresAt < now) {
        throw std::runtime_error("remote_session_expired");
    }

    uint64_t feeAtoms = 0;
    std::string paymentTxidHex;
    if (session.pricePerRequestAtoms > 0) {
        paymentTxidHex = createAndSubmitPaymentTx(session.providerAddress, session.pricePerRequestAtoms, feeAtoms);
    }

    synapse::RemoteModelInferMessage req;
    req.sessionId = session.sessionId;
    req.requestId = randomHex16();
    req.prompt = prompt;
    req.maxTokens = gp.maxTokens;
    req.temperature = gp.temperature;
    req.topP = gp.topP;
    req.topK = gp.topK;
    req.paymentTxidHex = paymentTxidHex;
    req.timestamp = now;
    auto pubV = keys_->getPublicKey();
    if (pubV.size() >= req.renterPubKey.size()) {
        std::memcpy(req.renterPubKey.data(), pubV.data(), req.renterPubKey.size());
    }

    {
        std::lock_guard<std::mutex> lock(remoteMtx_);
        RemotePending p;
        p.done = false;
        remotePending_[req.requestId] = std::move(p);
    }

    network_->send(session.peerId, makeMessage("m_infer", req.serialize()));

    const uint64_t deadline = std::time(nullptr) + (config_.dev ? 45 : 120);
    RemotePending done;
    for (;;) {
        {
            std::lock_guard<std::mutex> lock(remoteMtx_);
            auto it = remotePending_.find(req.requestId);
            if (it != remotePending_.end() && it->second.done) {
                done = it->second;
                remotePending_.erase(it);
                break;
            }
        }
        if (std::time(nullptr) >= deadline) {
            std::lock_guard<std::mutex> lock(remoteMtx_);
            remotePending_.erase(req.requestId);
            throw std::runtime_error("remote_infer_timeout");
        }
        std::unique_lock<std::mutex> lk(remoteMtx_);
        remoteCv_.wait_for(lk, std::chrono::milliseconds(250));
    }

    json out;
    out["model"] = "remote";
    out["text"] = done.text;
    json r;
    r["peerId"] = session.peerId;
    r["sessionId"] = session.sessionId;
    r["providerAddress"] = session.providerAddress;
    r["pricePerRequestAtoms"] = session.pricePerRequestAtoms;
    r["paymentTxid"] = paymentTxidHex;
    r["feeAtoms"] = feeAtoms;
    out["remote"] = r;
    return out.dump();
}

std::string handleRpcAiComplete(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    if (!modelLoader_) {
        throw std::runtime_error("Model not ready");
    }
    std::string prompt = params.value("prompt", "");
    if (prompt.empty()) {
        throw std::runtime_error("prompt required");
    }
	    if (prompt.size() > 1024 * 1024) {
	        throw std::runtime_error("prompt too large");
	    }
        const bool remote = params.value("remote", false) || params.contains("remoteSessionId");
	    bool webInject = params.value("webInject", utils::Config::instance().getBool("web.inject.enabled", false));
	    bool webOnion = params.value("webOnion", utils::Config::instance().getBool("web.inject.onion", false));
	    bool webTor = params.value("webTor", utils::Config::instance().getBool("web.inject.tor_clearnet", false));
	    std::string webQuery = params.value("webQuery", "");

    model::GenerationParams gp;
    if (params.contains("maxTokens")) gp.maxTokens = static_cast<uint32_t>(std::max(1, params.value("maxTokens", 512)));
    if (params.contains("temperature")) gp.temperature = static_cast<float>(std::max(0.0, params.value("temperature", 0.7)));
    if (params.contains("topP")) gp.topP = static_cast<float>(std::max(0.0, params.value("topP", 0.9)));
    if (params.contains("topK")) gp.topK = static_cast<uint32_t>(std::max(0, params.value("topK", 40)));
    if (params.contains("seed")) gp.seed = static_cast<uint64_t>(std::max<int64_t>(0, params.value("seed", 0)));
    if (params.contains("stopSequences") && params["stopSequences"].is_array()) {
        gp.stopSequences.clear();
        for (const auto& s : params["stopSequences"]) {
            if (s.is_string()) gp.stopSequences.push_back(s.get<std::string>());
        }
	    }
	    if (params.contains("jsonMode")) gp.jsonMode = params.value("jsonMode", false);

        if (remote) {
            return handleRpcAiCompleteRemote(params, prompt, gp);
        }

        std::lock_guard<std::mutex> lock(modelMtx_);
        if (!modelLoader_->isLoaded()) {
            throw std::runtime_error("model_not_loaded");
        }
        if (modelLoader_->isGenerating()) {
            throw std::runtime_error("model_busy");
        }
        modelRequests_.fetch_add(1);

	    std::string finalPrompt = prompt;
	    uint64_t webResults = 0;
	    uint64_t webClearnet = 0;
	    uint64_t webDarknet = 0;
	    if (webInject) {
	        if (ensureWebSubsystem()) {
	            std::lock_guard<std::mutex> wlock(webMtx_);
	            if (webAi_ && webSearch_) {
	                web::SearchConfig cfg = webSearch_->getConfig();
	                cfg.enableClearnet = true;
	                cfg.enableDarknet = webOnion;
	                cfg.routeClearnetThroughTor = webTor;
	                webSearch_->setConfig(cfg);
	                try {
	                    if (!webQuery.empty() && webDetector_) {
	                        web::QueryAnalysis analysis = webDetector_->analyze(webQuery);
	                        std::vector<web::SearchResult> results = webSearch_->search(webQuery, analysis.type);
	                        webResults = static_cast<uint64_t>(results.size());
	                        for (const auto& r : results) {
	                            if (r.isOnion) webDarknet++;
	                            else webClearnet++;
	                        }
	                        finalPrompt = webAi_->injectContext(prompt, results);
	                    } else {
	                        finalPrompt = webAi_->processQuery(prompt);
	                        auto st = webAi_->getStats();
	                        webResults = st.lastResultCount;
	                        webClearnet = st.lastClearnetResults;
	                        webDarknet = st.lastDarknetResults;
	                    }
	                } catch (...) {
	                    finalPrompt = prompt;
	                }
	            }
	        }
	    }

	    std::string text = modelLoader_->generate(finalPrompt, gp);
	    auto info = modelLoader_->getInfo();
	    json out;
	    out["model"] = info.name;
	    out["text"] = text;
	    out["webInject"] = webInject;
	    if (webInject) {
	        json w;
	        w["lastResults"] = webResults;
	        w["lastClearnetResults"] = webClearnet;
	        w["lastDarknetResults"] = webDarknet;
	        if (!webQuery.empty()) w["query"] = webQuery;
	        out["web"] = w;
	    }
	    return out.dump();
	}

std::string handleRpcAiStop(const std::string& paramsJson) {
    (void)paramsJson;
    if (!modelLoader_) {
        throw std::runtime_error("Model not ready");
    }
    modelLoader_->stopGeneration();
    json out;
    out["ok"] = true;
    return out.dump();
}

std::string handleRpcPoeValidators(const std::string& paramsJson) {
    (void)paramsJson;
    if (!poeV1_) {
        throw std::runtime_error("PoE not ready");
    }
    json out = json::array();
    for (const auto& v : poeV1_->getStaticValidators()) {
        out.push_back(crypto::toHex(v));
    }
    return out.dump();
}

static std::string peerStateToString(network::PeerState s) {
    switch (s) {
        case network::PeerState::CONNECTING: return "CONNECTING";
        case network::PeerState::HANDSHAKING: return "HANDSHAKING";
        case network::PeerState::CONNECTED: return "CONNECTED";
        case network::PeerState::DISCONNECTING: return "DISCONNECTING";
        case network::PeerState::DISCONNECTED: return "DISCONNECTED";
        case network::PeerState::BANNED: return "BANNED";
    }
    return "UNKNOWN";
}

std::string handleRpcNodeStatus(const std::string& paramsJson) {
    (void)paramsJson;
    NodeStats st = getStats();
    json out;
    out["running"] = running_.load();
    out["networkType"] = config_.networkType;
    out["p2pPort"] = network_ ? network_->getPort() : config_.port;
    out["rpcPort"] = config_.rpcPort;
    out["peersConnected"] = st.peersConnected;
    out["uptimeSeconds"] = st.uptime;
    out["uptime"] = formatUptime(st.uptime);
    out["syncProgress"] = st.syncProgress;
    if (ledger_) {
        out["ledgerHeight"] = ledger_->height();
        out["ledgerEvents"] = ledger_->eventCount();
        out["tipHash"] = crypto::toHex(ledger_->tipHash());
    }
    out["knowledgeEntries"] = st.knowledgeEntries;
    out["walletAddress"] = address_;
    out["privacyMode"] = config_.privacyMode;
    out["quantumSecurity"] = config_.quantumSecurity;
    return out.dump();
}

std::string handleRpcNodePeers(const std::string& paramsJson) {
    (void)paramsJson;
    json out = json::array();
    if (!network_) return out.dump();
    for (const auto& p : network_->getPeers()) {
        json item;
        item["id"] = p.id;
        item["address"] = p.address;
        item["port"] = p.port;
        item["connectedAt"] = p.connectedAt;
        item["lastSeen"] = p.lastSeen;
        item["bytesRecv"] = p.bytesRecv;
        item["bytesSent"] = p.bytesSent;
        item["version"] = p.version;
        item["startHeight"] = p.startHeight;
        item["outbound"] = p.isOutbound;
        item["state"] = peerStateToString(p.state);
        out.push_back(item);
    }
    return out.dump();
}

std::string handleRpcNodeLogs(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    size_t limit = 100;
    if (params.contains("limit")) {
        limit = static_cast<size_t>(std::max(1, params.value("limit", 100)));
    }
    auto logs = utils::Logger::getRecentLogs(limit);
    json out = json::array();
    for (const auto& e : logs) {
        json item;
        item["timestamp"] = e.timestamp;
        item["level"] = static_cast<int>(e.level);
        item["category"] = e.category;
        item["message"] = e.message;
        out.push_back(item);
    }
    return out.dump();
}

std::string handleRpcNodeSeeds(const std::string& paramsJson) {
    (void)paramsJson;
    json out;
    out["bootstrap"] = json::array();
    out["dnsSeeds"] = json::array();
    if (!discovery_) return out.dump();

    for (const auto& bn : discovery_->getBootstrapNodes()) {
        json item;
        item["address"] = bn.address;
        item["port"] = bn.port;
        item["active"] = bn.active;
        item["failures"] = bn.failures;
        item["lastSeen"] = bn.lastSeen;
        out["bootstrap"].push_back(item);
    }
    for (const auto& seed : discovery_->getDnsSeeds()) {
        out["dnsSeeds"].push_back(seed);
    }
    return out.dump();
}

std::string handleRpcNodeDiscoveryStats(const std::string& paramsJson) {
    (void)paramsJson;
    json out;
    if (!discovery_) {
        out["running"] = false;
        out["knownPeers"] = 0;
        out["connectedPeers"] = 0;
        out["dnsSeeds"] = 0;
        out["bootstrapNodes"] = 0;
        out["dnsQueries"] = 0;
        out["peerExchanges"] = 0;
        out["lastPeerRefresh"] = 0;
        out["lastAnnounce"] = 0;
        return out.dump();
    }
    auto st = discovery_->getStats();
    out["running"] = discovery_->isRunning();
    out["knownPeers"] = st.knownPeersCount;
    out["connectedPeers"] = st.connectedPeers;
    out["dnsSeeds"] = discovery_->getDnsSeeds().size();
    out["bootstrapNodes"] = discovery_->getBootstrapNodes().size();
    out["dnsQueries"] = st.dnsQueries;
    out["peerExchanges"] = st.peerExchanges;
    out["peerExchangeSuccessRate"] = st.peerExchangeSuccessRate;
    out["lastPeerRefresh"] = st.lastRefreshTime;
    out["lastAnnounce"] = st.lastAnnounceTime;
    out["networkSizeEstimate"] = st.networkSize;
    out["totalDiscovered"] = st.totalDiscovered;
    out["totalConnected"] = st.totalConnected;
    out["totalFailed"] = st.totalFailed;
    return out.dump();
}

		public:
		    int runCommand(const std::vector<std::string>& args) {
	        if (args.empty()) return 0;
	        if (args[0] == "model") {
	            if (args.size() == 1 || args[1] == "help") {
	                std::cout << "Usage:\n";
	                std::cout << "  synapsed model status\n";
	                std::cout << "  synapsed model list [--dir PATH]\n";
	                std::cout << "  synapsed model load (--path PATH | --name FILENAME)\n";
	                std::cout << "    [--context N] [--threads N] [--gpu-layers N] [--use-gpu 0|1] [--mmap 0|1]\n";
	                std::cout << "  synapsed model unload\n";
	                return 0;
	            }
	            std::string sub = args[1];
	            try {
	                if (sub == "status") {
	                    std::cout << handleRpcModelStatus("{}") << "\n";
	                    return 0;
	                }
	                if (sub == "list") {
	                    json params;
	                    for (size_t i = 2; i < args.size(); ++i) {
	                        if (args[i] == "--dir" && i + 1 < args.size()) {
	                            params["dir"] = args[i + 1];
	                            i++;
	                        }
	                    }
	                    std::cout << handleRpcModelList(params.dump()) << "\n";
	                    return 0;
	                }
	                if (sub == "load") {
	                    json params;
	                    for (size_t i = 2; i < args.size(); ++i) {
	                        if (args[i] == "--path" && i + 1 < args.size()) {
	                            params["path"] = args[i + 1];
	                            i++;
	                        } else if (args[i] == "--name" && i + 1 < args.size()) {
	                            params["name"] = args[i + 1];
	                            i++;
	                        } else if (args[i] == "--context" && i + 1 < args.size()) {
	                            params["contextSize"] = std::stoi(args[i + 1]);
	                            i++;
	                        } else if (args[i] == "--threads" && i + 1 < args.size()) {
	                            params["threads"] = std::stoi(args[i + 1]);
	                            i++;
	                        } else if (args[i] == "--gpu-layers" && i + 1 < args.size()) {
	                            params["gpuLayers"] = std::stoi(args[i + 1]);
	                            i++;
	                        } else if (args[i] == "--use-gpu" && i + 1 < args.size()) {
	                            params["useGpu"] = (std::stoi(args[i + 1]) != 0);
	                            i++;
	                        } else if (args[i] == "--mmap" && i + 1 < args.size()) {
	                            params["useMmap"] = (std::stoi(args[i + 1]) != 0);
	                            i++;
	                        }
	                    }
	                    std::cout << handleRpcModelLoad(params.dump()) << "\n";
	                    return 0;
	                }
	                if (sub == "unload") {
	                    std::cout << handleRpcModelUnload("{}") << "\n";
	                    return 0;
	                }
	            } catch (const std::exception& e) {
	                std::cerr << e.what() << "\n";
	                return 1;
	            }
	            std::cerr << "Unknown model subcommand: " << sub << "\n";
	            return 1;
	        }
	        if (args[0] == "ai") {
	            if (args.size() == 1 || args[1] == "help") {
	                std::cout << "Usage:\n";
	                std::cout << "  synapsed ai complete --prompt TEXT [--max-tokens N] [--temperature X]\n";
	                std::cout << "  synapsed ai stop\n";
	                return 0;
	            }
	            std::string sub = args[1];
	            try {
	                if (sub == "stop") {
	                    std::cout << handleRpcAiStop("{}") << "\n";
	                    return 0;
	                }
	                if (sub == "complete") {
	                    json params;
	                    for (size_t i = 2; i < args.size(); ++i) {
	                        if (args[i] == "--prompt" && i + 1 < args.size()) {
	                            params["prompt"] = args[i + 1];
	                            i++;
	                        } else if (args[i] == "--max-tokens" && i + 1 < args.size()) {
	                            params["maxTokens"] = std::stoi(args[i + 1]);
	                            i++;
	                        } else if (args[i] == "--temperature" && i + 1 < args.size()) {
	                            params["temperature"] = std::stod(args[i + 1]);
	                            i++;
	                        }
	                    }
	                    std::cout << handleRpcAiComplete(params.dump()) << "\n";
	                    return 0;
	                }
	            } catch (const std::exception& e) {
	                std::cerr << e.what() << "\n";
	                return 1;
	            }
	            std::cerr << "Unknown ai subcommand: " << sub << "\n";
	            return 1;
	        }
	        if (args[0] != "poe") {
	            std::cerr << "Unknown command: " << args[0] << "\n";
	            return 1;
	        }
	        if (args.size() == 1 || args[1] == "help") {
	            std::cout << "Usage:\n";
	            std::cout << "  synapsed poe submit --question Q --answer A [--source S]\n";
	            std::cout << "  synapsed poe submit-code --title T (--patch P | --patch-file PATH)\n";
	            std::cout << "  synapsed poe list-code [--limit N]\n";
	            std::cout << "  synapsed poe fetch-code <submitIdHex|contentIdHex>\n";
	            std::cout << "  synapsed poe vote <submitIdHex>\n";
	            std::cout << "  synapsed poe finalize <submitIdHex>\n";
	            std::cout << "  synapsed poe epoch [--budget NGT] [--iters N]\n";
	            std::cout << "  synapsed poe export <path>\n";
            std::cout << "  synapsed poe import <path>\n";
            std::cout << "  synapsed poe pubkey\n";
            std::cout << "  synapsed poe validators\n";
            return 0;
        }

        auto parseHash256 = [](const std::string& hex, crypto::Hash256& out) -> bool {
            auto bytes = crypto::fromHex(hex);
            if (bytes.size() != out.size()) return false;
            std::memcpy(out.data(), bytes.data(), out.size());
            return true;
        };

        auto parseNgtAtomic = [](const std::string& s, uint64_t& out) -> bool {
            if (s.empty()) return false;
            std::string t = s;
            for (auto& c : t) if (c == ',') c = '.';
            size_t dot = t.find('.');
            std::string intPart = dot == std::string::npos ? t : t.substr(0, dot);
            std::string fracPart = dot == std::string::npos ? "" : t.substr(dot + 1);
            if (intPart.empty()) intPart = "0";
            if (fracPart.size() > 8) return false;
            for (char c : intPart) if (c < '0' || c > '9') return false;
            for (char c : fracPart) if (c < '0' || c > '9') return false;
            unsigned __int128 iv = 0;
            for (char c : intPart) iv = iv * 10 + static_cast<unsigned>(c - '0');
            unsigned __int128 fv = 0;
            for (char c : fracPart) fv = fv * 10 + static_cast<unsigned>(c - '0');
            for (size_t i = fracPart.size(); i < 8; ++i) fv *= 10;
            unsigned __int128 total = iv * 100000000ULL + fv;
            if (total > std::numeric_limits<uint64_t>::max()) return false;
            out = static_cast<uint64_t>(total);
            return true;
        };

        auto rewardIdForEpoch = [](uint64_t epochId, const crypto::Hash256& contentId) -> crypto::Hash256 {
            std::vector<uint8_t> buf;
            const std::string tag = "poe_v1_epoch";
            buf.insert(buf.end(), tag.begin(), tag.end());
            for (int i = 0; i < 8; ++i) buf.push_back(static_cast<uint8_t>((epochId >> (8 * i)) & 0xFF));
            buf.insert(buf.end(), contentId.begin(), contentId.end());
            return crypto::sha256(buf.data(), buf.size());
        };

        auto addressFromPubKey = [](const crypto::PublicKey& pubKey) -> std::string {
            std::string hex = crypto::toHex(pubKey);
            if (hex.size() < 52) return {};
            return "ngt1" + hex.substr(0, 52);
        };

        const std::string sub = args[1];
        if (sub == "pubkey") {
            if (!keys_ || !keys_->isValid()) {
                std::cerr << "Wallet not loaded\n";
                return 1;
            }
            auto pubV = keys_->getPublicKey();
            if (pubV.size() < crypto::PUBLIC_KEY_SIZE) {
                std::cerr << "Invalid public key\n";
                return 1;
            }
            crypto::PublicKey pk{};
            std::memcpy(pk.data(), pubV.data(), pk.size());
            std::cout << crypto::toHex(pk) << "\n";
            return 0;
        }
        if (sub == "validators") {
            if (!poeV1_) {
                std::cerr << "PoE not ready\n";
                return 1;
            }
            auto vals = poeV1_->getStaticValidators();
            for (const auto& v : vals) {
                std::cout << crypto::toHex(v) << "\n";
            }
            if (vals.empty()) {
                std::cout << "(none)\n";
            }
            return 0;
        }
	        if (sub == "submit") {
	            std::unordered_map<std::string, std::string> opts;
	            for (size_t i = 2; i < args.size(); ++i) {
	                if (args[i].rfind("--", 0) != 0) continue;
                std::string k = args[i].substr(2);
                std::string v;
                if (i + 1 < args.size() && args[i + 1].rfind("--", 0) != 0) {
                    v = args[i + 1];
                    i++;
                }
                opts[k] = v;
            }

            std::string q = opts["question"];
            std::string a = opts["answer"];
            std::string s = opts["source"];
            if (q.empty() || a.empty()) {
                std::cerr << "Missing --question/--answer\n";
                return 1;
            }
            if (!poeV1_ || !transfer_ || !keys_ || !keys_->isValid() || address_.empty()) {
                std::cerr << "PoE/wallet not ready\n";
                return 1;
            }

            crypto::PrivateKey pk{};
            auto pkv = keys_->getPrivateKey();
            if (pkv.size() < pk.size()) {
                std::cerr << "Invalid private key\n";
                return 1;
            }
            std::memcpy(pk.data(), pkv.data(), pk.size());

            std::string body = a;
            if (!s.empty()) body += "\nsource: " + s;
            updatePoeValidatorsFromStake();
            auto submitRes = poeV1_->submit(core::poe_v1::ContentType::QA, q, body, {}, pk, true);
            if (!submitRes.ok) {
                std::cerr << "PoE submit failed: " << submitRes.error << "\n";
                return 1;
            }
            std::cout << "submitId=" << crypto::toHex(submitRes.submitId) << "\n";
            std::cout << "contentId=" << crypto::toHex(submitRes.contentId) << "\n";

            crypto::PublicKey authorPub = crypto::derivePublicKey(pk);
            std::string authorAddr = addressFromPubKey(authorPub);
            if (authorAddr.empty()) authorAddr = address_;

            uint64_t rewardAmt = 0;
            if (submitRes.finalized && submitRes.acceptanceReward > 0) {
                std::vector<uint8_t> ridBuf;
                const std::string tag = "poe_v1_accept";
                ridBuf.insert(ridBuf.end(), tag.begin(), tag.end());
                ridBuf.insert(ridBuf.end(), submitRes.submitId.begin(), submitRes.submitId.end());
                crypto::Hash256 rewardId = crypto::sha256(ridBuf.data(), ridBuf.size());
                if (transfer_->creditRewardDeterministic(authorAddr, rewardId, submitRes.acceptanceReward)) {
                    rewardAmt = submitRes.acceptanceReward;
                }
            }
            std::cout << "acceptanceReward=" << std::fixed << std::setprecision(8)
                      << (static_cast<double>(rewardAmt) / 100000000.0) << " NGT\n";

            {
                std::lock_guard<std::mutex> lock(invMtx_);
                knownPoeEntries_.insert(crypto::toHex(submitRes.submitId));
            }
            broadcastInv(synapse::InvType::POE_ENTRY, submitRes.submitId);
            for (const auto& vv : poeV1_->getVotesForSubmit(submitRes.submitId)) {
                crypto::Hash256 vid = vv.payloadHash();
                {
                    std::lock_guard<std::mutex> lock(invMtx_);
                    knownPoeVotes_.insert(crypto::toHex(vid));
                }
                broadcastInv(synapse::InvType::POE_VOTE, vid);
            }
	            return 0;
	        }

	        if (sub == "submit-code") {
	            std::unordered_map<std::string, std::string> opts;
	            for (size_t i = 2; i < args.size(); ++i) {
	                if (args[i].rfind("--", 0) != 0) continue;
	                std::string k = args[i].substr(2);
	                std::string v;
	                if (i + 1 < args.size() && args[i + 1].rfind("--", 0) != 0) {
	                    v = args[i + 1];
	                    i++;
	                }
	                opts[k] = v;
	            }

	            std::string title = opts["title"];
	            std::string patch = opts["patch"];
	            std::string patchFile = opts["patch-file"];
	            if (patch.empty() && !patchFile.empty()) {
	                std::ifstream in(patchFile, std::ios::binary);
	                if (!in) {
	                    std::cerr << "Failed to read --patch-file\n";
	                    return 1;
	                }
	                std::ostringstream ss;
	                ss << in.rdbuf();
	                patch = ss.str();
	            }

	            if (title.empty() || patch.empty()) {
	                std::cerr << "Missing --title and --patch/--patch-file\n";
	                return 1;
	            }
	            if (!poeV1_ || !transfer_ || !keys_ || !keys_->isValid() || address_.empty()) {
	                std::cerr << "PoE/wallet not ready\n";
	                return 1;
	            }

	            std::vector<crypto::Hash256> citations;
	            std::string cites = opts["citations"];
	            if (!cites.empty()) {
	                for (char& c : cites) if (c == ';') c = ',';
	                std::string cur;
	                for (size_t i = 0; i <= cites.size(); ++i) {
	                    if (i == cites.size() || cites[i] == ',') {
	                        std::string t = cur;
	                        auto isSpace = [](unsigned char c) { return std::isspace(c) != 0; };
	                        while (!t.empty() && isSpace(static_cast<unsigned char>(t.front()))) t.erase(t.begin());
	                        while (!t.empty() && isSpace(static_cast<unsigned char>(t.back()))) t.pop_back();
	                        if (!t.empty()) {
	                            crypto::Hash256 h{};
	                            if (!parseHash256(t, h)) {
	                                std::cerr << "Invalid --citations entry\n";
	                                return 1;
	                            }
	                            citations.push_back(h);
	                        }
	                        cur.clear();
	                    } else {
	                        cur.push_back(cites[i]);
	                    }
	                }
	            }

	            crypto::PrivateKey pk{};
	            auto pkv = keys_->getPrivateKey();
	            if (pkv.size() < pk.size()) {
	                std::cerr << "Invalid private key\n";
	                return 1;
	            }
	            std::memcpy(pk.data(), pkv.data(), pk.size());

	            updatePoeValidatorsFromStake();
	            auto submitRes = poeV1_->submit(core::poe_v1::ContentType::CODE, title, patch, citations, pk, true);
	            if (!submitRes.ok) {
	                std::cerr << "PoE submit failed: " << submitRes.error << "\n";
	                return 1;
	            }
	            std::cout << "submitId=" << crypto::toHex(submitRes.submitId) << "\n";
	            std::cout << "contentId=" << crypto::toHex(submitRes.contentId) << "\n";

	            crypto::PublicKey authorPub = crypto::derivePublicKey(pk);
	            std::string authorAddr = addressFromPubKey(authorPub);
	            if (authorAddr.empty()) authorAddr = address_;

	            uint64_t rewardAmt = 0;
	            if (submitRes.finalized && submitRes.acceptanceReward > 0) {
	                std::vector<uint8_t> ridBuf;
	                const std::string tag = "poe_v1_accept";
	                ridBuf.insert(ridBuf.end(), tag.begin(), tag.end());
	                ridBuf.insert(ridBuf.end(), submitRes.submitId.begin(), submitRes.submitId.end());
	                crypto::Hash256 rewardId = crypto::sha256(ridBuf.data(), ridBuf.size());
	                if (transfer_->creditRewardDeterministic(authorAddr, rewardId, submitRes.acceptanceReward)) {
	                    rewardAmt = submitRes.acceptanceReward;
	                }
	            }
	            std::cout << "acceptanceReward=" << std::fixed << std::setprecision(8)
	                      << (static_cast<double>(rewardAmt) / 100000000.0) << " NGT\n";

	            {
	                std::lock_guard<std::mutex> lock(invMtx_);
	                knownPoeEntries_.insert(crypto::toHex(submitRes.submitId));
	            }
	            broadcastInv(synapse::InvType::POE_ENTRY, submitRes.submitId);
	            for (const auto& vv : poeV1_->getVotesForSubmit(submitRes.submitId)) {
	                crypto::Hash256 vid = vv.payloadHash();
	                {
	                    std::lock_guard<std::mutex> lock(invMtx_);
	                    knownPoeVotes_.insert(crypto::toHex(vid));
	                }
	                broadcastInv(synapse::InvType::POE_VOTE, vid);
	            }
	            return 0;
	        }

	        if (sub == "list-code") {
	            if (!poeV1_) {
	                std::cerr << "PoE not ready\n";
	                return 1;
	            }
	            size_t limit = 25;
	            for (size_t i = 2; i < args.size(); ++i) {
	                if (args[i] == "--limit" && i + 1 < args.size()) {
	                    limit = static_cast<size_t>(std::max(1, std::stoi(args[i + 1])));
	                    i++;
	                }
	            }
	            auto ids = poeV1_->listEntryIds(0);
	            size_t shown = 0;
	            for (auto it = ids.rbegin(); it != ids.rend() && shown < limit; ++it) {
	                auto e = poeV1_->getEntry(*it);
	                if (!e) continue;
	                if (e->contentType != core::poe_v1::ContentType::CODE) continue;
	                std::cout << crypto::toHex(*it) << "  " << e->title << "\n";
	                shown++;
	            }
	            if (shown == 0) std::cout << "(none)\n";
	            return 0;
	        }

	        if (sub == "fetch-code") {
	            if (args.size() < 3) {
	                std::cerr << "Usage: synapsed poe fetch-code <submitIdHex|contentIdHex>\n";
	                return 1;
	            }
	            if (!poeV1_) {
	                std::cerr << "PoE not ready\n";
	                return 1;
	            }
	            crypto::Hash256 id{};
	            if (!parseHash256(args[2], id)) {
	                std::cerr << "Invalid id\n";
	                return 1;
	            }
	            auto entry = poeV1_->getEntry(id);
	            crypto::Hash256 submitId = id;
	            if (!entry) {
	                entry = poeV1_->getEntryByContentId(id);
	                if (entry) submitId = entry->submitId();
	            }
	            if (!entry) {
	                std::cerr << "not_found\n";
	                return 1;
	            }
	            if (entry->contentType != core::poe_v1::ContentType::CODE) {
	                std::cerr << "not_code_entry\n";
	                return 1;
	            }
	            std::cout << "submitId=" << crypto::toHex(submitId) << "\n";
	            std::cout << "contentId=" << crypto::toHex(entry->contentId()) << "\n";
	            std::cout << "timestamp=" << entry->timestamp << "\n";
	            std::cout << "title=" << entry->title << "\n";
	            std::cout << "finalized=" << (poeV1_->isFinalized(submitId) ? "true" : "false") << "\n";
	            std::cout << "patch:\n";
	            std::cout << entry->body << "\n";
	            return 0;
	        }

	        if (sub == "vote") {
	            if (args.size() < 3) {
	                std::cerr << "Usage: synapsed poe vote <submitIdHex>\n";
	                return 1;
            }
            if (!poeV1_ || !keys_ || !keys_->isValid()) {
                std::cerr << "PoE/wallet not ready\n";
                return 1;
            }
            crypto::Hash256 submitId{};
            if (!parseHash256(args[2], submitId)) {
                std::cerr << "Invalid submitId\n";
                return 1;
            }
            crypto::PrivateKey pk{};
            auto pkv = keys_->getPrivateKey();
            if (pkv.size() < pk.size()) {
                std::cerr << "Invalid private key\n";
                return 1;
            }
            std::memcpy(pk.data(), pkv.data(), pk.size());

            core::poe_v1::ValidationVoteV1 v;
            v.version = 1;
            v.submitId = submitId;
            v.prevBlockHash = poeV1_->chainSeed();
            v.flags = 0;
            v.scores = {100, 100, 100};
            core::poe_v1::signValidationVoteV1(v, pk);
            bool ok = poeV1_->addVote(v);
            crypto::Hash256 voteId = v.payloadHash();
            if (ok) {
                {
                    std::lock_guard<std::mutex> lock(invMtx_);
                    knownPoeVotes_.insert(crypto::toHex(voteId));
                }
                broadcastInv(synapse::InvType::POE_VOTE, voteId);
            }

            uint64_t credited = maybeCreditAcceptanceReward(submitId);
            std::cout << (ok ? "vote_added\n" : "vote_duplicate\n");
            if (credited > 0) {
                std::cout << "credited=" << std::fixed << std::setprecision(8)
                          << (static_cast<double>(credited) / 100000000.0) << " NGT\n";
            }
            return ok ? 0 : 1;
        }

        if (sub == "finalize") {
            if (args.size() < 3) {
                std::cerr << "Usage: synapsed poe finalize <submitIdHex>\n";
                return 1;
            }
            if (!poeV1_) {
                std::cerr << "PoE not ready\n";
                return 1;
            }
            crypto::Hash256 submitId{};
            if (!parseHash256(args[2], submitId)) {
                std::cerr << "Invalid submitId\n";
                return 1;
            }
            auto fin = poeV1_->finalize(submitId);
            if (!fin.has_value()) {
                std::cerr << "not_finalized\n";
                return 1;
            }
            std::cout << "finalized\n";
            uint64_t credited = maybeCreditAcceptanceReward(submitId);
            if (credited > 0) {
                std::cout << "credited=" << std::fixed << std::setprecision(8)
                          << (static_cast<double>(credited) / 100000000.0) << " NGT\n";
            }
            return 0;
        }

	        if (sub == "epoch") {
	            uint64_t budget = 0;
	            uint32_t iters = static_cast<uint32_t>(utils::Config::instance().getInt("poe.epoch_iterations", 20));
	            int64_t cfgBudget = utils::Config::instance().getInt64("poe.epoch_budget", 100000000LL);
            if (cfgBudget > 0) budget = static_cast<uint64_t>(cfgBudget);

            for (size_t i = 2; i < args.size(); ++i) {
                if (args[i] == "--budget" && i + 1 < args.size()) {
                    uint64_t v = 0;
                    if (!parseNgtAtomic(args[i + 1], v)) {
                        std::cerr << "Invalid --budget\n";
                        return 1;
                    }
                    budget = v;
                    i++;
                } else if (args[i] == "--iters" && i + 1 < args.size()) {
                    iters = static_cast<uint32_t>(std::max(1, std::stoi(args[i + 1])));
                    i++;
                }
            }

            if (!poeV1_ || !transfer_) {
                std::cerr << "PoE/transfer not ready\n";
                return 1;
            }
	            auto epochRes = poeV1_->runEpoch(budget, iters);
	            if (!epochRes.ok) {
	                std::cerr << "PoE epoch failed: " << epochRes.error << "\n";
	                return 1;
	            }

	            {
	                crypto::Hash256 hid = poeEpochInvHash(epochRes.epochId);
	                std::lock_guard<std::mutex> lock(invMtx_);
	                knownPoeEpochs_.insert(crypto::toHex(hid));
	            }
	            broadcastInv(synapse::InvType::POE_EPOCH, poeEpochInvHash(epochRes.epochId));

	            uint64_t mintedTotal = 0;
	            uint64_t mintedMine = 0;
	            uint64_t mintedCount = 0;
	            for (const auto& a : epochRes.allocations) {
                std::string addr = addressFromPubKey(a.authorPubKey);
                if (addr.empty()) continue;
                crypto::Hash256 rid = rewardIdForEpoch(epochRes.epochId, a.contentId);
                if (transfer_->creditRewardDeterministic(addr, rid, a.amount)) {
                    mintedTotal += a.amount;
                    mintedCount += 1;
                    if (!address_.empty() && addr == address_) mintedMine += a.amount;
                }
            }

            std::cout << "epochId=" << epochRes.epochId << "\n";
            std::cout << "allocationHash=" << crypto::toHex(epochRes.allocationHash) << "\n";
            std::cout << "minted=" << std::fixed << std::setprecision(8)
                      << (static_cast<double>(mintedTotal) / 100000000.0) << " NGT\n";
            std::cout << "mintedEntries=" << mintedCount << "\n";
            if (mintedMine > 0) {
                std::cout << "youEarned=" << std::fixed << std::setprecision(8)
                          << (static_cast<double>(mintedMine) / 100000000.0) << " NGT\n";
            }
            return 0;
        }

        if (sub == "export" || sub == "import") {
            if (args.size() < 3) {
                std::cerr << "Usage: synapsed poe " << sub << " <path>\n";
                return 1;
            }
            std::filesystem::path poeDb = std::filesystem::path(config_.dataDir) / "poe" / "poe.db";
            std::filesystem::path poeWal = poeDb;
            poeWal += "-wal";
            std::filesystem::path poeShm = poeDb;
            poeShm += "-shm";

            std::filesystem::path target = args[2];
            bool targetIsDir = std::filesystem::is_directory(target);
            if (sub == "export") {
                std::filesystem::path outDb = targetIsDir ? (target / "poe.db") : target;
                std::filesystem::create_directories(outDb.parent_path());
                std::error_code ec2;
                std::filesystem::copy_file(poeDb, outDb, std::filesystem::copy_options::overwrite_existing, ec2);
                if (ec2) {
                    std::cerr << "copy_failed\n";
                    return 1;
                }
                std::filesystem::path outWal = outDb;
                outWal += "-wal";
                std::filesystem::path outShm = outDb;
                outShm += "-shm";
                if (std::filesystem::exists(poeWal)) {
                    std::filesystem::copy_file(poeWal, outWal, std::filesystem::copy_options::overwrite_existing, ec2);
                }
                if (std::filesystem::exists(poeShm)) {
                    std::filesystem::copy_file(poeShm, outShm, std::filesystem::copy_options::overwrite_existing, ec2);
                }
                std::cout << "exported\n";
                return 0;
            } else {
                std::filesystem::path inDb = targetIsDir ? (target / "poe.db") : target;
                std::filesystem::path inWal = inDb;
                inWal += "-wal";
                std::filesystem::path inShm = inDb;
                inShm += "-shm";

                if (poeV1_) poeV1_->close();
                std::filesystem::create_directories(poeDb.parent_path());
                std::error_code ec2;
                std::filesystem::copy_file(inDb, poeDb, std::filesystem::copy_options::overwrite_existing, ec2);
                if (ec2) {
                    std::cerr << "copy_failed\n";
                    return 1;
                }
                if (std::filesystem::exists(inWal)) {
                    std::filesystem::copy_file(inWal, poeWal, std::filesystem::copy_options::overwrite_existing, ec2);
                }
                if (std::filesystem::exists(inShm)) {
                    std::filesystem::copy_file(inShm, poeShm, std::filesystem::copy_options::overwrite_existing, ec2);
                }
                std::cout << "imported\n";
                return 0;
            }
        }

        std::cerr << "Unknown poe subcommand: " << sub << "\n";
        return 1;
    }
    
    int run() {
        running_ = true;
        startTime_ = std::time(nullptr);
        
        utils::Logger::info("Node starting...");
        
        // Check if we're in Kiro environment or non-interactive terminal
        const char* kiro_env = std::getenv("KIRO_SESSION");
        bool in_kiro = (kiro_env != nullptr);
        bool interactive = isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
        
        if (config_.daemon || in_kiro || !interactive) {
            if (in_kiro) {
                std::cout << "Detected Kiro environment - starting in daemon mode..." << std::endl;
            } else if (!interactive) {
                std::cout << "Non-interactive terminal - starting in daemon mode..." << std::endl;
            } else {
                std::cout << "Starting in daemon mode..." << std::endl;
            }
            return runDaemon();
        }
        
        if (!config_.tui) std::cout << "Starting with TUI..." << std::endl;
        return runWithTUI();
    }
    
    void shutdown() {
        if (!running_) return;
        
        utils::Logger::info("Initiating shutdown sequence...");
        running_ = false;
        
	        if (network_) network_->stop();
	        if (discovery_) discovery_->stop();
	        if (rpc_) rpc_->stop();
	        {
	            std::lock_guard<std::mutex> lock(webMtx_);
	            if (webAi_) webAi_->shutdown();
	            if (webSearch_) webSearch_->shutdown();
	            webAi_.reset();
	            webSearch_.reset();
	            webDetector_.reset();
	            webExtractor_.reset();
	        }
	        if (privacy_) privacy_->shutdown();
	        if (quantumManager_) quantumManager_->shutdown();
	        if (db_) db_->close();
        
        stopThreads();
        
        saveState();
        
        utils::Config::instance().save(config_.dataDir + "/synapsenet.conf");
        utils::Logger::info("Shutdown complete");
        utils::Logger::shutdown();
    }
    
    void reload() {
        utils::Logger::info("Reloading configuration...");
        loadConfiguration();
    }
    
    NodeStats getStats() const {
        NodeStats stats;
        stats.uptime = std::time(nullptr) - startTime_;
        stats.peersConnected = network_ ? network_->peerCount() : 0;
	        stats.knowledgeEntries = poeV1_ ? poeV1_->totalEntries() : (knowledge_ ? knowledge_->totalEntries() : 0);
	        stats.syncProgress = syncProgress_;
	        stats.memoryUsage = getMemoryUsage();
	        stats.diskUsage = getDiskUsage();
	        stats.modelRequests = modelRequests_.load();
	        return stats;
	    }
    
    SystemInfo getSystemInfo() const {
        SystemInfo info;
        info.osName = "Unknown";
        info.cpuCores = std::thread::hardware_concurrency();
        return info;
    }
    
    bool isRunning() const { return running_; }
    const NodeConfig& getConfig() const { return config_; }
    
	private:
	    void saveState() {}

	    void setLogLevel(const std::string& level) {
	        if (level == "debug") utils::Logger::setLevel(utils::LogLevel::DEBUG);
	        else if (level == "info") utils::Logger::setLevel(utils::LogLevel::INFO);
	        else if (level == "warn") utils::Logger::setLevel(utils::LogLevel::WARN);
        else if (level == "error") utils::Logger::setLevel(utils::LogLevel::ERROR);
        else utils::Logger::setLevel(utils::LogLevel::INFO);
    }
    
    bool loadConfiguration() {
        std::string configPath = config_.configPath.empty() ? 
            config_.dataDir + "/synapsenet.conf" : config_.configPath;
        
        if (!utils::Config::instance().load(configPath)) {
            utils::Logger::info("No config file found, using defaults");
            utils::Config::instance().loadDefaults();
        }
        
        auto& cfg = utils::Config::instance();
        if (config_.port == 8333) {
            config_.port = cfg.getInt("port", 8333);
        }
        if (config_.rpcPort == 8332) {
            config_.rpcPort = cfg.getInt("rpcport", 8332);
        }
        config_.maxPeers = cfg.getInt("maxpeers", 125);
        config_.dbCacheSize = cfg.getInt("dbcache", 450);

        // Remote model routing (opt-in)
        remotePricePerRequestAtoms_ = static_cast<uint64_t>(
            std::max<int64_t>(0, cfg.getInt64("model.remote.price_per_request_atoms", 0))
        );
        {
            std::lock_guard<std::mutex> lock(remoteProvMtx_);
            if (localOfferId_.empty()) {
                localOfferId_ = cfg.getString("model.remote.offer_id", "");
                if (localOfferId_.empty()) localOfferId_ = randomHex16();
            }
        }
        
        return true;
    }
    
    bool initDatabase() {
        if (config_.amnesia) {
            utils::Logger::info("Amnesia mode: using in-memory database");
            return true;
        }
        
        std::string dbPath = config_.dataDir + "/chaindata";
        std::filesystem::create_directories(dbPath);
        
        db_ = std::make_unique<database::Database>();
        if (!db_->open(dbPath + "/chain.db")) {
            utils::Logger::error("Failed to open database at " + dbPath);
            return false;
        }
        
        utils::Logger::info("Database initialized: " + dbPath);
        return true;
    }
    
    bool initCrypto() {
        keys_ = std::make_unique<crypto::Keys>();
        
        std::string walletPath = config_.dataDir + "/wallet.dat";
        
        if (std::filesystem::exists(walletPath)) {
            if (!keys_->load(walletPath, "")) {
                utils::Logger::error("Failed to load wallet");
                return false;
            }
            utils::Logger::info("Wallet loaded successfully");
        } else if (config_.tui) {
            utils::Logger::info("Wallet not found, waiting for TUI creation");
            return true;
        } else {
            utils::Logger::info("Generating new wallet...");
            if (!keys_->generate()) {
                utils::Logger::error("Failed to generate keys");
                return false;
            }
            if (!keys_->save(walletPath, "")) {
                utils::Logger::error("Failed to save wallet");
                return false;
            }
            utils::Logger::info("New wallet created");
        }
        
        if (keys_->isValid()) {
            address_ = keys_->getAddress();
            utils::Logger::info("Wallet address: " + address_.substr(0, 16) + "...");
            updateSignerFromKeys();
        }
        return true;
    }
    
    bool initQuantumSecurity() {
        if (!config_.quantumSecurity && config_.securityLevel == "standard") {
            utils::Logger::info("Quantum security: disabled");
            return true;
        }
        
        quantumManager_ = std::make_unique<quantum::QuantumManager>();
        
        quantum::SecurityLevel level = quantum::SecurityLevel::STANDARD;
        if (config_.securityLevel == "high") {
            level = quantum::SecurityLevel::HIGH;
        } else if (config_.securityLevel == "paranoid") {
            level = quantum::SecurityLevel::PARANOID;
        }
        
        if (!quantumManager_->init(level)) {
            utils::Logger::error("Failed to initialize quantum security");
            return false;
        }
        
        utils::Logger::info("Quantum security initialized: " + config_.securityLevel);
        return true;
    }
    
    bool initNetwork() {
        network_ = std::make_unique<network::Network>();
        discovery_ = std::make_unique<network::Discovery>();
        
        network::NetworkConfig netCfg;
        netCfg.maxPeers = config_.maxPeers;
        netCfg.maxInbound = config_.maxInbound;
        netCfg.maxOutbound = config_.maxOutbound;
        network_->setConfig(netCfg);
        
        network::DiscoveryConfig discCfg;
        discCfg.maxPeers = config_.maxPeers;
        discCfg.minPeers = std::min<uint32_t>(8, config_.maxOutbound);
        discovery_->setConfig(discCfg);
        
        if (config_.testnet) {
            discovery_->addBootstrap("testnet-seed1.synapsenet.io", 18333);
            discovery_->addBootstrap("testnet-seed2.synapsenet.io", 18333);
            discovery_->addDnsSeed("testnet-seed1.synapsenet.io");
            discovery_->addDnsSeed("testnet-seed2.synapsenet.io");
        } else if (config_.regtest) {
            utils::Logger::info("Regtest mode: no bootstrap nodes");
        } else {
            discovery_->addBootstrap("seed1.synapsenet.io", 8333);
            discovery_->addBootstrap("seed2.synapsenet.io", 8333);
            discovery_->addBootstrap("seed3.synapsenet.io", 8333);
            discovery_->addBootstrap("seed4.synapsenet.io", 8333);
            discovery_->addDnsSeed("seed1.synapsenet.io");
            discovery_->addDnsSeed("seed2.synapsenet.io");
            discovery_->addDnsSeed("seed3.synapsenet.io");
            discovery_->addDnsSeed("seed4.synapsenet.io");
        }
        
        for (const auto& node : config_.seedNodes) {
            size_t colonPos = node.find(':');
            if (colonPos != std::string::npos) {
                std::string host = node.substr(0, colonPos);
                uint16_t port = std::stoi(node.substr(colonPos + 1));
                discovery_->addBootstrap(host, port);
                discovery_->addDnsSeed(host);
            }
        }
        
        network_->onMessage([this](const std::string& peerId, const network::Message& msg) {
            handleMessage(peerId, msg);
        });
        
        network_->onPeerConnected([this](const network::Peer& peer) {
            handlePeerConnected(peer);
        });
        
        network_->onPeerDisconnected([this](const network::Peer& peer) {
            handlePeerDisconnected(peer);
        });
        
        // Setup Discovery callbacks for peer exchange
        discovery_->setSendMessageCallback([this](const std::string& peerId, const std::string& command, const std::vector<uint8_t>& payload) -> bool {
            if (!network_) return false;
            auto msg = makeMessage(command, payload);
            return network_->send(peerId, msg);
        });
        
        discovery_->setGetConnectedPeersCallback([this]() -> std::vector<std::string> {
            if (!network_) return {};
            std::vector<std::string> peerIds;
            for (const auto& peer : network_->getPeers()) {
                if (peer.state == network::PeerState::CONNECTED) {
                    peerIds.push_back(peer.id);
                }
            }
            return peerIds;
        });
        
        // Try to determine external IP from version messages or config
        // For now, we'll rely on peers telling us our address via version messages
        // In the future, can add STUN or other methods here
        std::string externalIP = config_.bindAddress;
        if (externalIP == "0.0.0.0" || externalIP.empty()) {
            // Try to get from config or leave empty (will be discovered)
            externalIP = "";
        }
        if (!externalIP.empty()) {
            discovery_->setExternalAddress(externalIP);
        }
        
        uint16_t port = config_.testnet ? 18333 : config_.port;
        if (!network_->start(port)) {
            utils::Logger::info("Network offline mode - port " + std::to_string(port) + " unavailable");
            offlineMode_ = true;
        } else {
            offlineMode_ = false;
            uint16_t bound = network_->getPort();
            if (bound != 0) config_.port = bound;
            utils::Logger::info("Network started on port " + std::to_string(bound));
            discovery_->start(bound);
            // Kick DNS seeds immediately (avoid waiting refreshInterval seconds).
            discovery_->refreshFromDNS();
        }
        
        return true;
    }
    
    bool initCore() {
        if (!config_.tui) std::cout << "Creating core components..." << std::endl;
        ledger_ = std::make_unique<core::Ledger>();
        knowledge_ = std::make_unique<core::KnowledgeNetwork>();
        transfer_ = std::make_unique<core::TransferManager>();
        consensus_ = std::make_unique<core::Consensus>();
        poeV1_ = std::make_unique<core::PoeV1Engine>();
        
        if (!config_.tui) std::cout << "Creating directories..." << std::endl;
        std::string ledgerPath = config_.dataDir + "/ledger";
        std::string knowledgePath = config_.dataDir + "/knowledge";
        std::string transferPath = config_.dataDir + "/transfer";
        std::string consensusPath = config_.dataDir + "/consensus";
        std::string poePath = config_.dataDir + "/poe";
        std::filesystem::create_directories(ledgerPath);
        std::filesystem::create_directories(knowledgePath);
        std::filesystem::create_directories(transferPath);
        std::filesystem::create_directories(consensusPath);
        std::filesystem::create_directories(poePath);

        if (config_.resetNgt) {
            std::error_code ec;
            std::filesystem::remove(transferPath + "/transfer.db", ec);
            std::filesystem::remove(transferPath + "/transfer.db-wal", ec);
            std::filesystem::remove(transferPath + "/transfer.db-shm", ec);
            utils::Logger::info("NGT balances reset (transfer DB cleared)");
        }
        
        if (!config_.tui) std::cout << "Opening ledger..." << std::endl;
        if (!ledger_->open(ledgerPath + "/ledger.db")) {
            utils::Logger::error("Failed to open ledger");
            return false;
        }
        if (!config_.tui) std::cout << "Ledger opened successfully" << std::endl;
        
        if (!config_.tui) std::cout << "Opening knowledge DB..." << std::endl;
        if (!knowledge_->open(knowledgePath + "/knowledge.db")) {
            utils::Logger::error("Failed to open knowledge DB");
            return false;
        }
        
        if (!config_.tui) std::cout << "Opening transfer DB..." << std::endl;
        if (!transfer_->open(transferPath + "/transfer.db")) {
            utils::Logger::error("Failed to open transfer DB");
            return false;
        }
        
        if (!config_.tui) std::cout << "Opening consensus DB..." << std::endl;
        if (!consensus_->open(consensusPath + "/consensus.db")) {
            utils::Logger::error("Failed to open consensus DB");
            return false;
        }

        if (!config_.tui) std::cout << "Opening PoE v1 DB..." << std::endl;
        if (!poeV1_->open(poePath + "/poe.db")) {
            utils::Logger::error("Failed to open PoE v1 DB");
            return false;
        }

	        core::PoeV1Config poeCfg;
	        poeCfg.powBits = (config_.dev || config_.regtest) ? 12 : 16;
	        poeCfg.validatorsN = 1;
	        poeCfg.validatorsM = 1;
	        poeCfg.limits.minPowBits = poeCfg.powBits;
	        poeCfg.limits.maxPowBits = 28;
	        poeCfg.limits.maxTitleBytes = 512;
	        poeCfg.limits.maxBodyBytes = 65536;
	        poeV1_->setConfig(poeCfg);
        {
            std::vector<crypto::PublicKey> validators;

            crypto::PublicKey selfPub{};
            bool hasSelfPub = false;
            if (keys_ && keys_->isValid()) {
                auto pubV = keys_->getPublicKey();
                if (pubV.size() >= crypto::PUBLIC_KEY_SIZE) {
                    std::memcpy(selfPub.data(), pubV.data(), selfPub.size());
                    hasSelfPub = true;
                }
            }

            auto addValidatorHex = [&](const std::string& token) {
                std::string t = token;
                auto isSpace = [](unsigned char c) { return std::isspace(c) != 0; };
                while (!t.empty() && isSpace(static_cast<unsigned char>(t.front()))) t.erase(t.begin());
                while (!t.empty() && isSpace(static_cast<unsigned char>(t.back()))) t.pop_back();
                if (t.empty()) return;

                if (t == "self") {
                    if (hasSelfPub) validators.push_back(selfPub);
                    return;
                }

                if (t.rfind("0x", 0) == 0 || t.rfind("0X", 0) == 0) t = t.substr(2);
                auto bytes = crypto::fromHex(t);
                if (bytes.size() != crypto::PUBLIC_KEY_SIZE) {
                    utils::Logger::warn("Invalid poe validator pubkey (expected 32 bytes hex): " + t);
                    return;
                }
                crypto::PublicKey pk{};
                std::memcpy(pk.data(), bytes.data(), pk.size());
                validators.push_back(pk);
            };

            if (!config_.poeValidators.empty()) {
                std::string raw = config_.poeValidators;
                for (char& c : raw) {
                    if (c == ';') c = ',';
                }
                std::string cur;
                for (char c : raw) {
                    if (c == ',') {
                        addValidatorHex(cur);
                        cur.clear();
                    } else {
                        cur.push_back(c);
                    }
                }
                addValidatorHex(cur);
            }

            if (validators.empty() && hasSelfPub) {
                validators.push_back(selfPub);
            }

            if (!validators.empty()) {
                std::sort(validators.begin(), validators.end(), [](const crypto::PublicKey& a, const crypto::PublicKey& b) {
                    return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
                });
                validators.erase(std::unique(validators.begin(), validators.end(), [](const crypto::PublicKey& a, const crypto::PublicKey& b) {
                    return a == b;
                }), validators.end());
                poeV1_->setStaticValidators(validators);
            }
        }

        updatePoeValidatorsFromStake();
        
        if (!config_.tui) std::cout << "Setting up callbacks..." << std::endl;
        networkHeight_ = ledger_->height();

        if (keys_ && keys_->isValid()) {
            ledger_->setSigner([this](const crypto::Hash256& hash) {
                return signHash(hash);
            });
        }
        
        if (!config_.tui) std::cout << "Setting up knowledge callbacks..." << std::endl;
        knowledge_->onNewEntry([this](const core::KnowledgeEntry& entry) {
            std::string h = crypto::toHex(entry.hash);
            {
                std::lock_guard<std::mutex> lock(invMtx_);
                knowledgeByHash_[h] = entry.id;
                knownKnowledge_.insert(h);
            }
            if (suppressCallbacks_) return;
            broadcastInv(synapse::InvType::KNOWLEDGE, entry.hash);
            
            if (keys_ && keys_->isValid() && ledger_) {
                core::Event ev{};
                ev.timestamp = entry.timestamp;
                ev.type = core::EventType::KNOWLEDGE;
                ev.data = entry.serialize();
                auto pub = keys_->getPublicKey();
                if (pub.size() >= ev.author.size()) {
                    std::memcpy(ev.author.data(), pub.data(), ev.author.size());
                }
                ledger_->append(ev);
            }
        });
        
        if (!config_.tui) std::cout << "Setting up transfer callbacks..." << std::endl;
        transfer_->onNewTransaction([this](const core::Transaction& tx) {
            std::string h = crypto::toHex(tx.txid);
            {
                std::lock_guard<std::mutex> lock(invMtx_);
                knownTxs_.insert(h);
            }
            if (suppressCallbacks_) return;
            broadcastInv(synapse::InvType::TX, tx.txid);
            
            if (keys_ && keys_->isValid() && ledger_) {
                core::Event ev{};
                ev.timestamp = tx.timestamp;
                ev.type = core::EventType::TRANSFER;
                ev.data = tx.serialize();
                auto pub = keys_->getPublicKey();
                if (pub.size() >= ev.author.size()) {
                    std::memcpy(ev.author.data(), pub.data(), ev.author.size());
                }
                ledger_->append(ev);
            }
        });
        
        if (!config_.tui) std::cout << "Setting up ledger callbacks..." << std::endl;
        ledger_->onNewBlock([this](const core::Block& block) {
            {
                std::lock_guard<std::mutex> lock(invMtx_);
                knownBlocks_.insert(crypto::toHex(block.hash));
            }
            broadcastInv(synapse::InvType::BLOCK, block.hash);
        });
        
        utils::Logger::info("Core subsystems initialized");
        if (!config_.tui) std::cout << "Core initialization complete!" << std::endl;
        return true;
    }
    
	    bool initModel() {
	        modelLoader_ = std::make_unique<model::ModelLoader>();
	        modelAccess_ = std::make_unique<model::ModelAccess>();
            modelMarketplace_ = std::make_unique<model::ModelMarketplace>();

            // Load model access config (local-only; remote rentals are opt-in).
            try {
                std::string modeStr = utils::Config::instance().getString("model.access.mode", "PRIVATE");
                modelAccess_->setMode(parseAccessMode(modeStr));
            } catch (...) {
                modelAccess_->setMode(model::AccessMode::PRIVATE);
            }
            {
                int slots = utils::Config::instance().getInt("model.access.max_slots", 3);
                if (slots < 1) slots = 1;
                modelAccess_->setMaxSlots(static_cast<uint32_t>(slots));
            }
            {
                int64_t p = utils::Config::instance().getInt64("model.access.price_per_hour_atoms", 0);
                if (p < 0) p = 0;
                modelAccess_->setPrice(static_cast<uint64_t>(p));
            }

            // Ensure we have a stable listing id matching the remote offer id.
            {
                std::string listingId;
                {
                    std::lock_guard<std::mutex> lock(remoteProvMtx_);
                    listingId = localOfferId_;
                }
                if (!listingId.empty() && modelMarketplace_) {
                    // Start as inactive until a model is loaded & access mode isn't PRIVATE.
                    modelMarketplace_->upsertModel(
                        listingId,
                        address_,
                        "active",
                        "",
                        0,
                        "GGUF",
                        modelAccess_->getPrice(),
                        remotePricePerRequestAtoms_,
                        modelAccess_->getMaxSlots(),
                        false
                    );
                }
            }
        
        std::string modelDir = config_.dataDir + "/models";
        std::filesystem::create_directories(modelDir);
        
        auto models = modelLoader_->listModels(modelDir);
        if (!models.empty()) {
            utils::Logger::info("Found " + std::to_string(models.size()) + " local models");
        }
        
	        return true;
	    }

	    bool ensureWebSubsystem() {
	        std::lock_guard<std::mutex> lock(webMtx_);
	        if (webSearch_ && webAi_ && webDetector_ && webExtractor_) return true;

	        webSearch_ = std::make_unique<web::WebSearch>();
	        webDetector_ = std::make_unique<web::QueryDetector>();
	        webExtractor_ = std::make_unique<web::HtmlExtractor>();
	        webAi_ = std::make_unique<web::AIWrapper>();

	        if (!webAi_->init()) {
	            webAi_.reset();
	            webSearch_.reset();
	            webDetector_.reset();
	            webExtractor_.reset();
	            return false;
	        }

	        webAi_->setWebSearch(webSearch_.get());
	        webAi_->setDetector(webDetector_.get());
	        webAi_->setExtractor(webExtractor_.get());
	        webAi_->enableAutoSearch(true);
	        webAi_->enableContextInjection(true);

	        webSearch_->onSearchError([](const std::string& err) {
	            utils::Logger::warn("Web search: " + err);
	        });

	        web::SearchConfig cfg;
	        std::string webCfgPath = config_.dataDir + "/web_search.conf";
	        web::loadSearchConfig(webCfgPath, cfg);

	        cfg.enableClearnet = true;
	        cfg.enableDarknet = utils::Config::instance().getBool("web.inject.onion", false);
	        cfg.routeClearnetThroughTor = utils::Config::instance().getBool("web.inject.tor_clearnet", false);
	        webSearch_->init(cfg);
	        return true;
	    }
	    
	    bool initPrivacy() {
	        if (!config_.privacyMode) {
	            utils::Logger::info("Privacy mode: disabled");
	            return true;
        }
        
        privacy_ = std::make_unique<privacy::Privacy>();
        privacy::PrivacyConfig privConfig;
        privConfig.useTor = true;
        privConfig.circuitCount = 3;
        privConfig.rotateIdentity = true;
        privConfig.rotationInterval = 3600;
        privConfig.onionServiceDir = config_.dataDir + "/onion_service";
        uint16_t onionPort = network_ ? network_->getPort() : config_.port;
        privConfig.onionVirtualPort = onionPort;
        privConfig.onionTargetPort = onionPort;
        
        if (!privacy_->init(privConfig)) {
            utils::Logger::error("Failed to initialize privacy layer");
            return false;
        }
        
        if (!privacy_->enable(privacy::PrivacyMode::FULL)) {
            utils::Logger::error("Failed to enable Tor");
            return false;
        }
        
        std::string onion = privacy_->getOnionAddress();
        utils::Logger::info("Privacy mode enabled: " + onion);
        return true;
    }
    
    bool initRPC() {
        if (config_.rpcPort == 0) {
            utils::Logger::info("RPC server: disabled");
            return true;
        }
        
        rpc_ = std::make_unique<web::RpcServer>();
        if (!rpc_->start(config_.rpcPort)) {
            utils::Logger::error("Failed to start RPC server");
            return false;
        }

		        rpc_->registerMethod("poe.submit", [this](const std::string& params) {
		            return handleRpcPoeSubmit(params);
		        }, false, 2000);

		        rpc_->registerMethod("poe.submit_code", [this](const std::string& params) {
		            return handleRpcPoeSubmitCode(params);
		        }, false, 2000);

		        rpc_->registerMethod("poe.list_code", [this](const std::string& params) {
		            return handleRpcPoeListCode(params);
		        }, false, 2000);

		        rpc_->registerMethod("poe.fetch_code", [this](const std::string& params) {
		            return handleRpcPoeFetchCode(params);
		        }, false, 2000);

		        rpc_->registerMethod("poe.vote", [this](const std::string& params) {
		            return handleRpcPoeVote(params);
		        }, false, 5000);

	        rpc_->registerMethod("poe.finalize", [this](const std::string& params) {
	            return handleRpcPoeFinalize(params);
	        }, false, 2000);

	        rpc_->registerMethod("poe.epoch", [this](const std::string& params) {
	            return handleRpcPoeEpoch(params);
	        }, false, 200);

	        rpc_->registerMethod("poe.export", [this](const std::string& params) {
	            return handleRpcPoeExport(params);
	        }, false, 50);

	        rpc_->registerMethod("poe.import", [this](const std::string& params) {
	            return handleRpcPoeImport(params);
	        }, false, 50);

	        rpc_->registerMethod("wallet.address", [this](const std::string& params) {
	            return handleRpcWalletAddress(params);
	        }, false, 5000);

		        rpc_->registerMethod("wallet.balance", [this](const std::string& params) {
		            return handleRpcWalletBalance(params);
		        }, false, 5000);

		        rpc_->registerMethod("model.status", [this](const std::string& params) {
		            return handleRpcModelStatus(params);
		        }, false, 5000);

		        rpc_->registerMethod("model.list", [this](const std::string& params) {
		            return handleRpcModelList(params);
		        }, false, 2000);

		        rpc_->registerMethod("model.load", [this](const std::string& params) {
		            return handleRpcModelLoad(params);
		        }, false, 50);

		        rpc_->registerMethod("model.unload", [this](const std::string& params) {
		            return handleRpcModelUnload(params);
		        }, false, 50);

		        rpc_->registerMethod("model.access.get", [this](const std::string& params) {
		            return handleRpcModelAccessGet(params);
		        }, false, 2000);

		        rpc_->registerMethod("model.access.set", [this](const std::string& params) {
		            return handleRpcModelAccessSet(params);
		        }, false, 2000);

		        rpc_->registerMethod("market.listings", [this](const std::string& params) {
		            return handleRpcMarketListings(params);
		        }, false, 2000);

		        rpc_->registerMethod("market.stats", [this](const std::string& params) {
		            return handleRpcMarketStats(params);
		        }, false, 2000);

		        rpc_->registerMethod("model.remote.list", [this](const std::string& params) {
		            return handleRpcModelRemoteList(params);
		        }, false, 2000);

		        rpc_->registerMethod("model.remote.rent", [this](const std::string& params) {
		            return handleRpcModelRemoteRent(params);
		        }, false, 5000);

		        rpc_->registerMethod("model.remote.end", [this](const std::string& params) {
		            return handleRpcModelRemoteEnd(params);
		        }, false, 2000);

		        rpc_->registerMethod("ai.complete", [this](const std::string& params) {
		            return handleRpcAiComplete(params);
		        }, false, 200);

		        rpc_->registerMethod("ai.stop", [this](const std::string& params) {
		            return handleRpcAiStop(params);
		        }, false, 500);

		        rpc_->registerMethod("poe.validators", [this](const std::string& params) {
		            return handleRpcPoeValidators(params);
		        }, false, 2000);

	        rpc_->registerMethod("node.status", [this](const std::string& params) {
	            return handleRpcNodeStatus(params);
	        }, false, 5000);

	        rpc_->registerMethod("node.peers", [this](const std::string& params) {
	            return handleRpcNodePeers(params);
	        }, false, 5000);

	        rpc_->registerMethod("node.logs", [this](const std::string& params) {
	            return handleRpcNodeLogs(params);
	        }, false, 1000);

            rpc_->registerMethod("node.seeds", [this](const std::string& params) {
                return handleRpcNodeSeeds(params);
            }, false, 2000);

            rpc_->registerMethod("node.discovery.stats", [this](const std::string& params) {
                return handleRpcNodeDiscoveryStats(params);
            }, false, 2000);
	        
	        utils::Logger::info("RPC server started on port " + std::to_string(config_.rpcPort));
	        return true;
	    }
    
    bool initMempool() {
        if (transfer_) {
            transfer_->setMaxMempoolSize(static_cast<size_t>(config_.maxMempool) * 1024);
        }
        utils::Logger::info("Mempool initialized: " + std::to_string(config_.maxMempool) + " MB");
        return true;
    }

    int runWithTUI() {
#if !SYNAPSE_BUILD_TUI
        std::cerr << "TUI support was disabled at build time; reconfigure with -DBUILD_TUI=ON.\n";
        return runDaemon();
#else
        // Check terminal capabilities first
        const char* term = std::getenv("TERM");
        bool stdin_tty = isatty(STDIN_FILENO);
        bool stdout_tty = isatty(STDOUT_FILENO);
        
        if (!term) {
            std::cerr << "TERM environment variable not set. Try: export TERM=xterm-256color\n";
            return 1;
        }
        
        if (!stdin_tty || !stdout_tty) {
            std::cerr << "Not running in a proper terminal. TUI requires an interactive terminal.\n";
            std::cerr << "Running in daemon mode instead...\n";
            return runDaemon();
        }
        
        tui::TUI ui;
        if (!ui.init()) {
            utils::Logger::error("Failed to initialize TUI");
            std::cerr << "Failed to initialize TUI (ncurses). Possible issues:\n";
            std::cerr << "1. Terminal too small (minimum 80x24)\n";
            std::cerr << "2. TERM variable incorrect: " << term << "\n";
            std::cerr << "3. Not running in interactive terminal\n";
            std::cerr << "Falling back to daemon mode...\n";
            return runDaemon();
        }

        utils::Logger::enableConsole(false);
        
        if (network_ && network_->getPort() != 0) {
            ui.setNetworkPort(network_->getPort());
            ui.setNetworkOnline(true);
        } else {
            ui.setNetworkOnline(false);
        }
        
        startThreads();

        ui.onCommand([this, &ui](const std::string& cmd) {
            std::istringstream iss(cmd);
            std::string op;
            iss >> op;
            if (op == "send") {
                std::string to;
                std::string amountStr;
                iss >> to >> amountStr;
                if (to.empty() || amountStr.empty()) {
                    ui.showError("Invalid send arguments");
                    return;
                }
                if (!transfer_ || !keys_ || !keys_->isValid() || address_.empty()) {
                    ui.showError("Wallet/transfer not ready");
                    return;
                }
                uint64_t amount = 0;
                try {
                    amount = this->parseNgtAtomic(amountStr);
                } catch (const std::exception& e) {
                    ui.showError(e.what());
                    return;
                }
                if (amount == 0) {
                    ui.showError("Amount too small");
                    return;
                }
                if (!transfer_->hasSufficientBalance(address_, amount)) {
                    ui.showError("Insufficient balance");
                    return;
                }

                uint64_t fee = transfer_->estimateFee(0);
                core::Transaction tx;
                for (int i = 0; i < 5; ++i) {
                    tx = transfer_->createTransaction(address_, to, amount, fee);
                    uint64_t requiredFee = transfer_->estimateFee(tx.serialize().size());
                    if (requiredFee == fee) break;
                    fee = requiredFee;
                }

                uint64_t bal = transfer_->getBalance(address_);
                if (UINT64_MAX - amount < fee) {
                    ui.showError("Amount too large");
                    return;
                }
                uint64_t needed = amount + fee;
                if (bal < needed) {
                    ui.showError("Insufficient balance (including fee)");
                    return;
                }

                crypto::PrivateKey pk{};
                auto pkv = keys_->getPrivateKey();
                if (pkv.size() < pk.size()) {
                    ui.showError("Invalid private key");
                    return;
                }
                std::memcpy(pk.data(), pkv.data(), pk.size());
                if (!transfer_->signTransaction(tx, pk)) {
                    ui.showError("Failed to sign transaction");
                    return;
                }
                if (!transfer_->submitTransaction(tx)) {
                    ui.showError("Failed to submit transaction");
                    return;
                }
                ui.showMessage("Transaction submitted", tui::Color::GREEN);
	            } else if (op == "poe_submit") {
	                std::string q64;
	                std::string a64;
	                std::string s64;
                iss >> q64 >> a64 >> s64;
                if (q64.empty() || a64.empty()) {
                    ui.showError("Invalid knowledge arguments");
                    return;
                }
                if (!poeV1_ || !keys_ || !keys_->isValid()) {
                    ui.showError("PoE/wallet not ready");
                    return;
                }

                auto fromB64 = [](const std::string& s) -> std::string {
                    std::vector<uint8_t> in(s.begin(), s.end());
                    auto out = crypto::base64Decode(in);
                    return std::string(out.begin(), out.end());
                };

                std::string question = fromB64(q64);
                std::string answer = fromB64(a64);
                std::string source = s64.empty() ? "" : fromB64(s64);

                if (question.empty() || answer.empty()) {
                    ui.showError("Question/answer empty");
                    return;
                }

                crypto::PrivateKey pk{};
                auto pkv = keys_->getPrivateKey();
                if (pkv.size() < pk.size()) {
                    ui.showError("Invalid private key");
                    return;
                }
                std::memcpy(pk.data(), pkv.data(), pk.size());

                std::string body = answer;
                if (!source.empty()) {
                    body += "\nsource: " + source;
                }

                updatePoeValidatorsFromStake();
                ui.updateOperationStatus("Submitting knowledge", "IN_PROGRESS", "");
                auto submitRes = poeV1_->submit(core::poe_v1::ContentType::QA, question, body, {}, pk, true);
                if (!submitRes.ok) {
                    ui.updateOperationStatus("Submitting knowledge", "ERROR", submitRes.error);
                    ui.showError("PoE submit failed: " + submitRes.error);
                    return;
                }

                broadcastInv(synapse::InvType::POE_ENTRY, submitRes.submitId);
                for (const auto& v : poeV1_->getVotesForSubmit(submitRes.submitId)) {
                    broadcastInv(synapse::InvType::POE_VOTE, v.payloadHash());
                }

                auto entry = poeV1_->getEntry(submitRes.submitId);
                uint64_t expectedAtoms = entry ? poeV1_->calculateAcceptanceReward(*entry) : 0;
                uint32_t votes = static_cast<uint32_t>(poeV1_->getVotesForSubmit(submitRes.submitId).size());
                uint32_t requiredVotes = poeV1_->getConfig().validatorsM;

                maybeCreditAcceptanceReward(submitRes.submitId);
                bool paid = transfer_ ? transfer_->hasTransaction(rewardIdForAcceptance(submitRes.submitId)) : false;

                std::ostringstream oss;
                std::string sidShort = crypto::toHex(submitRes.submitId).substr(0, 8);
                if (poeV1_->isFinalized(submitRes.submitId)) {
                    ui.updateOperationStatus("Knowledge finalized", "SUCCESS", sidShort);
                    if (paid && expectedAtoms > 0) {
                        double rewardAmount = static_cast<double>(expectedAtoms) / 100000000.0;
                        std::ostringstream details;
                        details << "Accepted by " << requiredVotes << "/" << requiredVotes << " validators";
                        ui.showRewardNotification(rewardAmount, "knowledge contribution", sidShort, details.str());
                    } else {
                        oss << "Knowledge finalized (" << sidShort << "): reward pending";
                        ui.showMessage(oss.str(), tui::Color::GREEN);
                        ui.appendChatMessage("assistant", oss.str());
                    }
                } else {
                    std::ostringstream details;
                    details << votes << "/" << requiredVotes << " votes";
                    ui.updateOperationStatus("Validating entry", "IN_PROGRESS", details.str());
                    oss << "Knowledge submitted (" << sidShort << "): pending " << votes << "/" << requiredVotes;
                    if (expectedAtoms > 0) {
                        oss << " (+" << std::fixed << std::setprecision(8)
                            << (static_cast<double>(expectedAtoms) / 100000000.0) << " NGT on finalize)";
                    }
                    std::string msg = oss.str();
	                ui.showMessage(msg, tui::Color::GREEN);
	                ui.appendChatMessage("assistant", msg);
                }
		            } else if (op == "poe_submit_code") {
		                std::string t64;
		                std::string p64;
		                std::string c64;
		                iss >> t64 >> p64 >> c64;
		                if (t64.empty() || p64.empty()) {
		                    ui.showError("Invalid code arguments");
		                    return;
		                }
		                if (!poeV1_ || !keys_ || !keys_->isValid()) {
		                    ui.showError("PoE/wallet not ready");
		                    return;
		                }

		                auto fromB64 = [](const std::string& s) -> std::string {
		                    std::vector<uint8_t> in(s.begin(), s.end());
		                    auto out = crypto::base64Decode(in);
		                    return std::string(out.begin(), out.end());
		                };

		                std::string title = fromB64(t64);
		                std::string patch = fromB64(p64);
		                std::string citesRaw = c64.empty() ? "" : fromB64(c64);

		                if (title.empty() || patch.empty()) {
		                    ui.showError("Title/patch empty");
		                    return;
		                }

		                std::vector<crypto::Hash256> citations;
		                if (!citesRaw.empty()) {
		                    bool citationsOk = true;
		                    std::string raw = citesRaw;
		                    for (char& c : raw) if (c == ';') c = ',';
		                    std::string cur;
		                    auto flush = [&]() {
		                        std::string t = cur;
		                        auto isSpace = [](unsigned char c) { return std::isspace(c) != 0; };
		                        while (!t.empty() && isSpace(static_cast<unsigned char>(t.front()))) t.erase(t.begin());
		                        while (!t.empty() && isSpace(static_cast<unsigned char>(t.back()))) t.pop_back();
		                        if (t.empty()) return;
		                        try {
		                            citations.push_back(parseHash256Hex(t));
		                        } catch (...) {
		                            citationsOk = false;
		                        }
		                    };
		                    for (size_t i = 0; i <= raw.size(); ++i) {
		                        if (i == raw.size() || raw[i] == ',') {
		                            if (!cur.empty()) flush();
		                            cur.clear();
		                        } else {
		                            cur.push_back(raw[i]);
		                        }
		                    }
		                    if (!citationsOk) {
		                        ui.showError("Invalid citations");
		                        return;
		                    }
		                }

		                crypto::PrivateKey pk{};
		                auto pkv = keys_->getPrivateKey();
		                if (pkv.size() < pk.size()) {
		                    ui.showError("Invalid private key");
		                    return;
		                }
		                std::memcpy(pk.data(), pkv.data(), pk.size());

		                updatePoeValidatorsFromStake();
		                core::PoeSubmitResult submitRes;
		                ui.updateOperationStatus("Submitting code", "IN_PROGRESS", "");
		                try {
		                    submitRes = poeV1_->submit(core::poe_v1::ContentType::CODE, title, patch, citations, pk, true);
		                } catch (const std::exception& e) {
		                    ui.updateOperationStatus("Submitting code", "ERROR", e.what());
		                    ui.showError(e.what());
		                    return;
		                }
		                if (!submitRes.ok) {
		                    ui.updateOperationStatus("Submitting code", "ERROR", submitRes.error);
		                    ui.showError("PoE submit failed: " + submitRes.error);
		                    return;
		                }

		                broadcastInv(synapse::InvType::POE_ENTRY, submitRes.submitId);
		                for (const auto& v : poeV1_->getVotesForSubmit(submitRes.submitId)) {
		                    broadcastInv(synapse::InvType::POE_VOTE, v.payloadHash());
		                }

		                auto entry = poeV1_->getEntry(submitRes.submitId);
		                uint64_t expectedAtoms = entry ? poeV1_->calculateAcceptanceReward(*entry) : 0;
		                uint32_t votes = static_cast<uint32_t>(poeV1_->getVotesForSubmit(submitRes.submitId).size());
		                uint32_t requiredVotes = poeV1_->getConfig().validatorsM;

		                maybeCreditAcceptanceReward(submitRes.submitId);
		                bool paid = transfer_ ? transfer_->hasTransaction(rewardIdForAcceptance(submitRes.submitId)) : false;

		                std::ostringstream oss;
		                std::string sidShort = crypto::toHex(submitRes.submitId).substr(0, 8);
		                if (poeV1_->isFinalized(submitRes.submitId)) {
		                    ui.updateOperationStatus("Code finalized", "SUCCESS", sidShort);
		                    if (paid && expectedAtoms > 0) {
		                        double rewardAmount = static_cast<double>(expectedAtoms) / 100000000.0;
		                        std::ostringstream details;
		                        details << "Accepted by " << requiredVotes << "/" << requiredVotes << " validators";
		                        ui.showRewardNotification(rewardAmount, "code contribution", sidShort, details.str());
		                    } else {
		                        oss << "Code finalized (" << sidShort << "): reward pending";
		                        ui.showMessage(oss.str(), tui::Color::GREEN);
		                        ui.appendChatMessage("assistant", oss.str());
		                    }
		                } else {
		                    std::ostringstream details;
		                    details << votes << "/" << requiredVotes << " votes";
		                    ui.updateOperationStatus("Validating entry", "IN_PROGRESS", details.str());
		                    oss << "Code submitted (" << sidShort << "): pending " << votes << "/" << requiredVotes;
		                    if (expectedAtoms > 0) {
		                        oss << " (+" << std::fixed << std::setprecision(8)
		                            << (static_cast<double>(expectedAtoms) / 100000000.0) << " NGT on finalize)";
		                    }
		                    std::string msg = oss.str();
		                    ui.showMessage(msg, tui::Color::GREEN);
		                    ui.appendChatMessage("assistant", msg);
		                }
		            } else if (op == "poe_epoch") {
		                if (!poeV1_ || !transfer_) {
		                    ui.showError("PoE/transfer not ready");
		                    return;
	                }

                int64_t cfgBudget = utils::Config::instance().getInt64(
                    "poe.epoch_budget",
                    config_.dev ? 100000000LL : 1000000000LL);
                uint64_t budget = cfgBudget > 0 ? static_cast<uint64_t>(cfgBudget) : 0ULL;
                uint32_t iters = static_cast<uint32_t>(std::max(1, utils::Config::instance().getInt(
                    "poe.epoch_iterations",
                    config_.dev ? 10 : 20)));

                auto rewardIdForEpoch = [](uint64_t epochId, const crypto::Hash256& contentId) -> crypto::Hash256 {
                    std::vector<uint8_t> buf;
                    const std::string tag = "poe_v1_epoch";
                    buf.insert(buf.end(), tag.begin(), tag.end());
                    for (int i = 0; i < 8; ++i) buf.push_back(static_cast<uint8_t>((epochId >> (8 * i)) & 0xFF));
                    buf.insert(buf.end(), contentId.begin(), contentId.end());
                    return crypto::sha256(buf.data(), buf.size());
                };

                auto addressFromPubKey = [](const crypto::PublicKey& pubKey) -> std::string {
                    std::string hex = crypto::toHex(pubKey);
                    if (hex.size() < 52) return {};
                    return "ngt1" + hex.substr(0, 52);
                };

	                auto epochRes = poeV1_->runEpoch(budget, iters);
	                if (!epochRes.ok) {
	                    ui.showError("PoE epoch failed: " + epochRes.error);
	                    return;
	                }

	                {
	                    crypto::Hash256 hid = poeEpochInvHash(epochRes.epochId);
	                    std::lock_guard<std::mutex> lock(invMtx_);
	                    knownPoeEpochs_.insert(crypto::toHex(hid));
	                }
	                broadcastInv(synapse::InvType::POE_EPOCH, poeEpochInvHash(epochRes.epochId));

	                uint64_t mintedTotal = 0;
	                uint64_t mintedMine = 0;
	                uint64_t mintedCount = 0;
	                for (const auto& a : epochRes.allocations) {
                    std::string addr = addressFromPubKey(a.authorPubKey);
                    if (addr.empty()) continue;
                    crypto::Hash256 rid = rewardIdForEpoch(epochRes.epochId, a.contentId);
                    if (transfer_->creditRewardDeterministic(addr, rid, a.amount)) {
                        mintedTotal += a.amount;
                        mintedCount += 1;
                        if (!address_.empty() && addr == address_) mintedMine += a.amount;
                    }
                }

                std::ostringstream oss;
                oss << "Epoch #" << epochRes.epochId << " distributed " << std::fixed << std::setprecision(8)
                    << (static_cast<double>(mintedTotal) / 100000000.0) << " NGT";
                if (mintedMine > 0) {
                    oss << " (you: " << std::fixed << std::setprecision(8)
                        << (static_cast<double>(mintedMine) / 100000000.0) << " NGT)";
                }
                oss << " to " << mintedCount << " entries";

                std::string msg = oss.str();
                ui.showMessage(msg, tui::Color::GREEN);
                ui.appendChatMessage("assistant", msg);
            }
        });
        
        std::thread updateThread([this, &ui]() {
            std::unordered_set<std::string> notifiedKnowledgePaid;
            while (running_) {
                if (keys_ && !keys_->isValid()) {
                    std::string walletPath = config_.dataDir + "/wallet.dat";
                    if (std::filesystem::exists(walletPath)) {
                        if (keys_->load(walletPath, "")) {
                            address_ = keys_->getAddress();
                            updateSignerFromKeys();
                            if (poeV1_) {
                                auto current = poeV1_->getStaticValidators();
                                if (current.empty()) {
                                    auto pubV = keys_->getPublicKey();
                                    if (pubV.size() >= crypto::PUBLIC_KEY_SIZE) {
                                        crypto::PublicKey pk{};
                                        std::memcpy(pk.data(), pubV.data(), pk.size());
                                        poeV1_->setStaticValidators({pk});
                                    }
                                }
                            }
                        }
                    }
                }
                tui::NetworkInfo netInfo;
                netInfo.totalNodes = network_ ? network_->peerCount() : 0;
                netInfo.knowledgeEntries = poeV1_ ? poeV1_->totalEntries() : (knowledge_ ? knowledge_->totalEntries() : 0);
                netInfo.knowledgeFinalized = poeV1_ ? poeV1_->totalFinalized() : 0;
                netInfo.knowledgePending =
                    (netInfo.knowledgeEntries > netInfo.knowledgeFinalized) ? (netInfo.knowledgeEntries - netInfo.knowledgeFinalized) : 0;
                
                // Get real network size estimate from Discovery
                if (discovery_) {
                    auto discStats = discovery_->getStats();
                    netInfo.networkSize = static_cast<double>(discStats.networkSize);
                    netInfo.knownPeers = discStats.knownPeersCount;
                    netInfo.connectedPeers = discStats.connectedPeers;
                    netInfo.dnsQueries = discStats.dnsQueries;
                    netInfo.peerExchanges = discStats.peerExchanges;
                    netInfo.lastPeerRefresh = discStats.lastRefreshTime;
                    netInfo.lastAnnounce = discStats.lastAnnounceTime;
                    netInfo.bootstrapNodes = discovery_->getBootstrapNodes().size();
                    netInfo.dnsSeeds = discovery_->getDnsSeeds().size();
                } else {
                    netInfo.networkSize = 0.0;
                    netInfo.knownPeers = 0;
                    netInfo.connectedPeers = 0;
                    netInfo.dnsQueries = 0;
                    netInfo.peerExchanges = 0;
                    netInfo.lastPeerRefresh = 0;
                    netInfo.lastAnnounce = 0;
                    netInfo.bootstrapNodes = 0;
                    netInfo.dnsSeeds = 0;
                }
                
                netInfo.yourStorage = 0.0;
                netInfo.syncProgress = syncProgress_;
                netInfo.synced = (syncProgress_ >= 1.0);
                ui.updateNetworkInfo(netInfo);
                
                if (network_) {
                    ui.setPeerCount(network_->peerCount());
                    
                    std::vector<tui::NodeInfo> peers;
                    auto networkPeers = network_->getPeers();
                    for (const auto& peer : networkPeers) {
                        tui::NodeInfo nodeInfo;
                        nodeInfo.nodeId = peer.id;
                        nodeInfo.id = peer.id.substr(0, 16) + "...";
                        nodeInfo.address = peer.address;
                        nodeInfo.location = "Unknown";
                        nodeInfo.port = peer.port;
                        nodeInfo.latency = 50;
                        nodeInfo.ping = 50;
                        nodeInfo.version = std::to_string(peer.version);
                        nodeInfo.isInbound = !peer.isOutbound;
                        peers.push_back(nodeInfo);
                    }
                    ui.updatePeers(peers);
                }
                
                tui::AIModelInfo modelInfo;
                if (modelLoader_) {
                    auto models = modelLoader_->listModels(config_.dataDir + "/models");
                    if (!models.empty()) {
                        modelInfo.name = models[0].name;
                        modelInfo.status = "ACTIVE";
                        modelInfo.progress = 1.0;
                    } else {
                        modelInfo.name = "";
                        modelInfo.status = "NOT LOADED";
                        modelInfo.progress = 0.0;
                    }
                } else {
                    modelInfo.name = "";
                    modelInfo.status = "NOT LOADED";
                    modelInfo.progress = 0.0;
                }
                modelInfo.mode = "PRIVATE";
                modelInfo.slotsUsed = 0;
                modelInfo.slotsMax = 1;
                modelInfo.uptime = 0.0;
                modelInfo.earningsToday = 0.0;
                modelInfo.earningsWeek = 0.0;
                modelInfo.earningsTotal = 0.0;
                ui.updateModelInfo(modelInfo);
                
                tui::WalletInfo walletInfo;
                if (keys_ && keys_->isValid()) {
                    walletInfo.address = address_;
                    uint64_t bal = 0;
                    uint64_t pend = 0;
                    if (transfer_ && !address_.empty()) {
                        bal = transfer_->getBalance(address_);
                        pend = transfer_->getPendingBalance(address_);
                    }
                    walletInfo.balance = static_cast<double>(bal) / 100000000.0;
                    walletInfo.pending = static_cast<double>(pend) / 100000000.0;
                    walletInfo.staked = 0.0;
                    walletInfo.totalEarned = 0.0;
                } else {
                    walletInfo.address = "";
                    walletInfo.balance = 0.0;
                    walletInfo.pending = 0.0;
                    walletInfo.staked = 0.0;
                    walletInfo.totalEarned = 0.0;
                }
                ui.updateWalletInfo(walletInfo);

                std::vector<tui::KnowledgeEntrySummary> summaries;
                if (poeV1_) {
                    struct Tmp {
                        tui::KnowledgeEntrySummary s;
                        uint64_t ts = 0;
                        bool mine = false;
                    };
                    std::vector<Tmp> tmp;
                    auto ids = poeV1_->listEntryIds(50);
                    tmp.reserve(ids.size());
                    core::PoeV1Config cfg = poeV1_->getConfig();
	                    for (const auto& sid : ids) {
	                        auto entry = poeV1_->getEntry(sid);
	                        if (!entry) continue;
	                        Tmp t;
	                        t.ts = entry->timestamp;
	                        t.s.submitId = crypto::toHex(sid);
	                        t.s.title = entry->title;
	                        t.s.contentType = static_cast<uint8_t>(entry->contentType);
	                        t.s.finalized = poeV1_->isFinalized(sid);
	                        t.s.votes = static_cast<uint32_t>(poeV1_->getVotesForSubmit(sid).size());
	                        t.s.requiredVotes = cfg.validatorsM;
	                        uint64_t atoms = poeV1_->calculateAcceptanceReward(*entry);
	                        t.s.acceptanceReward = atomsToNgt(atoms);
                        t.s.acceptanceRewardCredited = transfer_ ? transfer_->hasTransaction(rewardIdForAcceptance(sid)) : false;
                        t.mine = (!address_.empty() && addressFromPubKey(entry->authorPubKey) == address_);
                        tmp.push_back(std::move(t));
                    }
                    std::sort(tmp.begin(), tmp.end(), [](const Tmp& a, const Tmp& b) { return a.ts > b.ts; });
                    if (tmp.size() > 20) tmp.resize(20);
                    summaries.reserve(tmp.size());
                    for (auto& t : tmp) {
                        summaries.push_back(t.s);
                    }

	                    for (const auto& t : tmp) {
	                        if (!t.mine) continue;
	                        if (!t.s.finalized) continue;
	                        if (!t.s.acceptanceRewardCredited) continue;
	                        if (!notifiedKnowledgePaid.insert(t.s.submitId).second) continue;
	                        std::string sidShort = t.s.submitId.size() > 8 ? t.s.submitId.substr(0, 8) : t.s.submitId;
	                        std::ostringstream msg;
	                        std::string kind = (t.s.contentType == static_cast<uint8_t>(core::poe_v1::ContentType::CODE))
	                            ? "Code"
	                            : "Knowledge";
	                        msg << kind << " reward (" << sidShort << "): +" << std::fixed << std::setprecision(8)
	                            << t.s.acceptanceReward << " NGT";
	                        ui.appendChatMessage("assistant", msg.str());
	                    }
	                }
                ui.updateKnowledgeEntries(summaries);

                tui::StatusInfo status{};
                status.blockHeight = ledger_ ? ledger_->height() : 0;
                status.peerCount = network_ ? network_->peerCount() : 0;
                status.knowledgeCount = poeV1_ ? poeV1_->totalEntries() : (knowledge_ ? knowledge_->totalEntries() : 0);
                status.balance = static_cast<uint64_t>(walletInfo.balance);
                status.walletAddress = walletInfo.address;
                status.modelName = modelInfo.name;
                status.modelStatus = modelInfo.status;
                status.syncProgress = syncProgress_;
                ui.updateStatus(status);
                
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        });
        
        ui.run();
        
        running_ = false;
        updateThread.join();
        stopThreads();
        ui.shutdown();
        utils::Logger::enableConsole(true);
        
        return 0;
#endif
    }
    
    int runDaemon() {
        utils::Logger::info("Running in daemon mode");
        
        std::cout << "\n=== SynapseNet Node Status ===\n";
        std::cout << "Mode: Daemon (no TUI)\n";
        std::cout << "Data Directory: " << config_.dataDir << "\n";
        std::cout << "Network Port: " << config_.port << "\n";
        std::cout << "RPC Port: " << config_.rpcPort << "\n";
        
        if (keys_ && keys_->isValid()) {
            std::cout << "Wallet Address: " << address_.substr(0, 16) << "...\n";
        } else {
            std::cout << "Wallet: Not loaded\n";
        }
        
        if (network_ && network_->getPort() != 0) {
            std::cout << "Network: Online\n";
        } else {
            std::cout << "Network: Offline\n";
        }
        
        std::cout << "\nNode is running. Press Ctrl+C to stop.\n";
        std::cout << "Logs are written to: " << config_.dataDir << "/synapsenet.log\n\n";
        
        startThreads();
        
        int statusCounter = 0;
        while (running_) {
            if (g_reloadConfig) {
                reload();
                g_reloadConfig = false;
            }
            
            // Print status every 30 seconds
            if (statusCounter % 30 == 0) {
                auto stats = getStats();
                std::cout << "[" << std::time(nullptr) << "] ";
                std::cout << "Uptime: " << formatUptime(stats.uptime) << ", ";
                std::cout << "Peers: " << stats.peersConnected << ", ";
                std::cout << "Knowledge: " << stats.knowledgeEntries << ", ";
                std::cout << "Sync: " << std::fixed << std::setprecision(1) << (stats.syncProgress * 100) << "%\n";
            }
            
            statusCounter++;
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        stopThreads();
        return 0;
    }
    
    void startThreads() {
        networkThread_ = std::thread([this]() { networkLoop(); });
        consensusThread_ = std::thread([this]() { consensusLoop(); });
        maintenanceThread_ = std::thread([this]() { maintenanceLoop(); });
        syncThread_ = std::thread([this]() { syncLoop(); });
    }
    
    void stopThreads() {
        if (networkThread_.joinable()) networkThread_.join();
        if (consensusThread_.joinable()) consensusThread_.join();
        if (maintenanceThread_.joinable()) maintenanceThread_.join();
        if (syncThread_.joinable()) syncThread_.join();
    }
    
    void networkLoop() {
        uint64_t lastAnnounce = 0;
        uint64_t lastPeerRefresh = 0;
        
        while (running_) {
            uint64_t now = std::time(nullptr);
            
            // Periodic peer exchange refresh
            if (discovery_ && now - lastPeerRefresh > 30) {
                discovery_->refreshFromPeers();
                lastPeerRefresh = now;
            }
            
            // Periodic announce
            if (discovery_ && now - lastAnnounce > 300) { // Every 5 minutes
                discovery_->announce();
                lastAnnounce = now;
            }
            
            if (config_.discovery && network_->peerCount() < config_.maxOutbound) {
                // Prioritize bootstrap nodes first (best chance to find network quickly)
                if (discovery_) {
                    auto boots = discovery_->getBootstrapNodes();
                    for (const auto& bn : boots) {
                        if (network_->peerCount() >= config_.maxOutbound) break;
                        network_->connect(bn.address, bn.port);
                    }
                }
                auto peers = discovery_->getRandomPeers(10);
                for (const auto& peer : peers) {
                    if (network_->peerCount() >= config_.maxOutbound) break;
                    network_->connect(peer.address, peer.port);
                }
            }
            
            std::unordered_set<std::string> connected;
            for (const auto& peer : network_->getPeers()) {
                connected.insert(peer.address + ":" + std::to_string(peer.port));
            }
            
            auto connectToNode = [this, &connected](const std::string& node) {
                size_t colonPos = node.find(':');
                if (colonPos != std::string::npos) {
                    std::string host = node.substr(0, colonPos);
                    uint16_t port = std::stoi(node.substr(colonPos + 1));
                    std::string id = host + ":" + std::to_string(port);
                    if (connected.count(id) == 0) {
                        network_->connect(host, port);
                    }
                }
            };
            
            for (const auto& node : config_.connectNodes) connectToNode(node);
            for (const auto& node : config_.addNodes) connectToNode(node);
            
            for (int i = 0; i < 300 && running_; ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    }
    
    void consensusLoop() {
        while (running_) {
            if (consensus_) {
                consensus_->processTimeouts();
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
		    void maintenanceLoop() {
		        uint64_t lastCompact = 0;
		        uint64_t lastQuantum = 0;
		        uint64_t lastBlock = 0;
                uint64_t lastOfferBroadcast = 0;
		        while (running_) {
		            uint64_t now = std::time(nullptr);
		            uint32_t limitEpochs = config_.dev ? 128 : 64;

		            struct PoeRetry {
		                std::string peerId;
		                PoeInvKind kind;
	                crypto::Hash256 after;
	                uint32_t limit;
	            };
		            std::vector<PoeRetry> retries;
		            {
		                std::lock_guard<std::mutex> lock(poeSyncMtx_);
		                for (auto& [peerId, st] : poeSync_) {
		                    if (st.entries.active && st.votes.active && st.entries.done && st.votes.done && !st.epochs.active) {
		                        st.epochs.active = true;
		                        st.epochs.inFlight = true;
		                        st.epochs.done = false;
		                        st.epochs.after = crypto::Hash256{};
		                        st.epochs.limit = limitEpochs;
		                        st.epochs.lastRequestAt = now;
		                        retries.push_back({peerId, PoeInvKind::EPOCH, st.epochs.after, st.epochs.limit});
		                    }
		                    if (st.entries.active && st.entries.inFlight && !st.entries.done &&
		                        now > st.entries.lastRequestAt + 3) {
		                        retries.push_back({peerId, PoeInvKind::ENTRY, st.entries.after, st.entries.limit});
		                        st.entries.lastRequestAt = now;
		                    }
		                    if (st.votes.active && st.votes.inFlight && !st.votes.done &&
		                        now > st.votes.lastRequestAt + 3) {
		                        retries.push_back({peerId, PoeInvKind::VOTE, st.votes.after, st.votes.limit});
		                        st.votes.lastRequestAt = now;
		                    }
		                    if (st.epochs.active && st.epochs.inFlight && !st.epochs.done &&
		                        now > st.epochs.lastRequestAt + 3) {
		                        retries.push_back({peerId, PoeInvKind::EPOCH, st.epochs.after, st.epochs.limit});
		                        st.epochs.lastRequestAt = now;
		                    }
		                }
		            }
		            for (const auto& r : retries) {
		                sendPoeGetInv(r.peerId, r.kind, r.after, r.limit);
	            }
	            
	            if (db_ && now - lastCompact >= 600) {
	                db_->compact();
	                lastCompact = now;
	            }
            
            if (quantumManager_ && now - lastQuantum >= 60) {
                quantumManager_->performMaintenance();
                lastQuantum = now;
            }
            
            if (ledger_ && now - lastBlock >= 15) {
                if (ledger_->getPendingEventCount() > 0) {
                    buildBlockFromPending();
                    lastBlock = now;
                }
            }

            // Expire remote provider sessions (slots + marketplace) deterministically by wall clock.
            if (modelAccess_) {
                modelAccess_->processExpiredSessions();
            }
            if (modelMarketplace_) {
                std::vector<std::pair<std::string, ProviderSession>> expired;
                {
                    std::lock_guard<std::mutex> lock(remoteProvMtx_);
                    for (const auto& [sid, s] : providerSessions_) {
                        if (s.expiresAt != 0 && s.expiresAt < now) {
                            expired.push_back({sid, s});
                        }
                    }
                    for (const auto& e : expired) {
                        providerSessions_.erase(e.first);
                    }
                }
                for (const auto& e : expired) {
                    (void)modelAccess_->endSession(e.second.renterId);
                    (void)modelMarketplace_->endRental(e.first);
                }
            }

            // Remote model routing: periodically broadcast offer (opt-in).
            if (network_ && modelAccess_ && modelLoader_ && now - lastOfferBroadcast >= 30) {
                if (remotePricePerRequestAtoms_ > 0 &&
                    modelLoader_->isLoaded() &&
                    modelAccess_->getMode() != model::AccessMode::PRIVATE) {
                    // Keep marketplace listing updated (stable id = offer id).
                    if (modelMarketplace_) {
                        auto info = modelLoader_->getInfo();
                        modelMarketplace_->upsertModel(
                            localOfferId_,
                            address_,
                            info.name.empty() ? "active" : info.name,
                            "",
                            info.sizeBytes,
                            "GGUF",
                            modelAccess_->getPrice(),
                            remotePricePerRequestAtoms_,
                            modelAccess_->getMaxSlots(),
                            true
                        );
                    }
                    auto offer = buildLocalOffer(now);
                    network_->broadcast(makeMessage("m_offer", offer.serialize()));
                    lastOfferBroadcast = now;
                }
            }
            
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    
    void syncLoop() {
        while (running_) {
            uint64_t localHeight = ledger_ ? ledger_->height() : 0;
            uint64_t netHeight = networkHeight_.load();
            if (netHeight == 0) {
                syncProgress_ = 1.0;
            } else {
                double progress = static_cast<double>(localHeight) / static_cast<double>(netHeight);
                syncProgress_ = progress > 1.0 ? 1.0 : progress;
            }
            
            if (!ledger_) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }
            
            if (network_ && netHeight > localHeight) {
                syncing_ = true;
                auto peers = network_->getPeers();
                if (!peers.empty()) {
                    uint64_t now = std::time(nullptr);
                    size_t inFlight = 0;
                    {
                        std::lock_guard<std::mutex> lock(syncMtx_);
                        for (auto it = requestedBlocks_.begin(); it != requestedBlocks_.end();) {
                            if (now - it->second > 10) {
                                it = requestedBlocks_.erase(it);
                            } else {
                                ++inFlight;
                                ++it;
                            }
                        }
                    }
                    
                    size_t maxInFlight = 16;
                    uint64_t nextHeight = localHeight;
                    while (nextHeight < netHeight && inFlight < maxInFlight) {
                        bool already = false;
                        {
                            std::lock_guard<std::mutex> lock(syncMtx_);
                            if (requestedBlocks_.count(nextHeight)) {
                                already = true;
                            } else {
                                requestedBlocks_[nextHeight] = now;
                            }
                        }
                        if (!already) {
                            const auto& peer = peers[nextHeight % peers.size()];
                            sendGetBlock(peer.id, nextHeight);
                            ++inFlight;
                        }
                        ++nextHeight;
                    }
                }
            } else {
                syncing_ = false;
            }
            
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    static std::vector<uint8_t> serializeU64(uint64_t val) {
        std::vector<uint8_t> out(8);
        for (int i = 0; i < 8; i++) out[i] = static_cast<uint8_t>((val >> (i * 8)) & 0xff);
        return out;
    }
    
    static uint64_t deserializeU64(const std::vector<uint8_t>& data) {
        if (data.size() < 8) return 0;
        uint64_t val = 0;
        for (int i = 0; i < 8; i++) val |= static_cast<uint64_t>(data[i]) << (i * 8);
        return val;
    }
    
    network::Message makeMessage(const std::string& command, const std::vector<uint8_t>& payload) {
        network::Message msg;
        msg.command = command;
        msg.payload = payload;
        msg.timestamp = std::time(nullptr);
        return msg;
    }
    
    crypto::Signature signHash(const crypto::Hash256& hash) {
        crypto::Signature sig{};
        if (!keys_ || !keys_->isValid()) return sig;
        auto privVec = keys_->getPrivateKey();
        if (privVec.size() < crypto::PRIVATE_KEY_SIZE) return sig;
        crypto::PrivateKey priv{};
        std::memcpy(priv.data(), privVec.data(), priv.size());
        sig = crypto::sign(hash, priv);
        return sig;
    }
    
    void updateSignerFromKeys() {
        if (keys_ && keys_->isValid() && ledger_) {
            ledger_->setSigner([this](const crypto::Hash256& hash) {
                return signHash(hash);
            });
        }
    }
    
    void buildBlockFromPending() {
        if (!ledger_) return;
        auto events = ledger_->getPendingEvents();
        if (events.empty()) return;
        core::Block block;
        block.height = ledger_->height();
        block.timestamp = std::time(nullptr);
        block.prevHash = ledger_->tipHash();
        block.events = std::move(events);
        block.difficulty = ledger_->currentDifficulty();
        block.merkleRoot = block.computeMerkleRoot();
        block.nonce = 0;
        block.hash = block.computeHash();
        while (!block.meetsTarget()) {
            block.nonce++;
            block.hash = block.computeHash();
        }
        if (!ledger_->appendBlockWithValidation(block)) {
            return;
        }

        if (transfer_) {
            std::vector<core::Transaction> blockTxs;
            for (const auto& ev : block.events) {
                if (ev.type != core::EventType::TRANSFER) continue;
                core::Transaction tx = core::Transaction::deserialize(ev.data);
                if (tx.txid == crypto::Hash256{}) continue;
                blockTxs.push_back(tx);
            }
            if (!blockTxs.empty()) {
                if (!transfer_->applyBlockTransactionsFromBlock(blockTxs, block.height, block.hash)) {
                    utils::Logger::error("Failed to apply block transfer events (local mined block)");
                }
            }
        }
    }
    
    void sendVersion(const std::string& peerId) {
        if (!network_) return;
        synapse::VersionMessage v{};
        v.version = 1;
        v.services = 0;
        v.timestamp = std::time(nullptr);
        v.nonce = static_cast<uint64_t>(std::random_device{}()) << 32 | std::random_device{}();
        v.userAgent = "SynapseNet:0.1";
        v.startHeight = ledger_ ? ledger_->height() : 0;
        v.relay = true;
        uint16_t port = network_->getPort();
        v.portRecv = port;
        v.portFrom = port;
        auto msg = makeMessage("version", v.serialize());
        network_->send(peerId, msg);
    }
    
    void sendVerack(const std::string& peerId) {
        if (!network_) return;
        auto msg = makeMessage("verack", {});
        network_->send(peerId, msg);
    }
    
    void sendGetAddr(const std::string& peerId) {
        if (!network_) return;
        auto msg = makeMessage("getaddr", {});
        network_->send(peerId, msg);
    }

    void sendMempoolRequest(const std::string& peerId) {
        if (!network_) return;
        auto msg = makeMessage("mempool", {});
        network_->send(peerId, msg);
    }
    
	    void sendGetBlock(const std::string& peerId, uint64_t height) {
	        if (!network_) return;
	        auto msg = makeMessage("getblock", serializeU64(height));
	        network_->send(peerId, msg);
	    }

		    static void writeU32LE(std::vector<uint8_t>& out, uint32_t v) {
		        out.push_back(static_cast<uint8_t>(v & 0xFF));
		        out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
		        out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
		        out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
		    }

		    static void writeU64LE(std::vector<uint8_t>& out, uint64_t v) {
		        for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
		    }

		    static uint32_t readU32LE(const std::vector<uint8_t>& data, size_t off) {
		        if (off + 4 > data.size()) return 0;
		        return static_cast<uint32_t>(data[off]) |
		               (static_cast<uint32_t>(data[off + 1]) << 8) |
	               (static_cast<uint32_t>(data[off + 2]) << 16) |
		               (static_cast<uint32_t>(data[off + 3]) << 24);
		    }

		    static uint64_t readU64LE(const std::vector<uint8_t>& data, size_t off) {
		        if (off + 8 > data.size()) return 0;
		        uint64_t v = 0;
		        for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(data[off + static_cast<size_t>(i)]) << (8 * i);
		        return v;
		    }

		    static bool hashLess(const crypto::Hash256& a, const crypto::Hash256& b) {
		        return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
		    }

		    static crypto::Hash256 poeEpochInvHash(uint64_t epochId) {
		        crypto::Hash256 out{};
		        for (int i = 0; i < 8; ++i) {
		            out[24 + static_cast<size_t>(i)] = static_cast<uint8_t>((epochId >> (8 * (7 - i))) & 0xFF);
		        }
		        return out;
		    }

		    static std::optional<uint64_t> epochIdFromPoeInvHash(const crypto::Hash256& h) {
		        for (size_t i = 0; i < 24; ++i) {
		            if (h[i] != 0) return std::nullopt;
		        }
		        uint64_t v = 0;
		        for (size_t i = 0; i < 8; ++i) {
		            v = (v << 8) | static_cast<uint64_t>(h[24 + i]);
		        }
		        if (v == 0) return std::nullopt;
		        return v;
		    }

		    static std::vector<uint8_t> serializePoeEpoch(const core::PoeEpochResult& epoch) {
		        std::vector<core::PoeEpochAllocation> allocs = epoch.allocations;
		        std::sort(allocs.begin(), allocs.end(), [](const core::PoeEpochAllocation& a, const core::PoeEpochAllocation& b) {
		            return std::lexicographical_compare(a.contentId.begin(), a.contentId.end(), b.contentId.begin(), b.contentId.end());
		        });

		        std::vector<uint8_t> out;
		        out.reserve(8 + 4 + crypto::SHA256_SIZE + 8 + crypto::SHA256_SIZE + 4 +
		                    allocs.size() * (crypto::SHA256_SIZE + crypto::SHA256_SIZE + crypto::PUBLIC_KEY_SIZE + 8 + 8));
		        writeU64LE(out, epoch.epochId);
		        writeU32LE(out, epoch.iterations);
		        out.insert(out.end(), epoch.epochSeed.begin(), epoch.epochSeed.end());
		        writeU64LE(out, epoch.totalBudget);
		        out.insert(out.end(), epoch.allocationHash.begin(), epoch.allocationHash.end());
		        writeU32LE(out, static_cast<uint32_t>(allocs.size()));
		        for (const auto& a : allocs) {
		            out.insert(out.end(), a.submitId.begin(), a.submitId.end());
		            out.insert(out.end(), a.contentId.begin(), a.contentId.end());
		            out.insert(out.end(), a.authorPubKey.begin(), a.authorPubKey.end());
		            writeU64LE(out, a.score);
		            writeU64LE(out, a.amount);
		        }
		        return out;
		    }

		    static std::optional<core::PoeEpochResult> deserializePoeEpoch(const std::vector<uint8_t>& payload) {
		        const size_t headerSize = 8 + 4 + crypto::SHA256_SIZE + 8 + crypto::SHA256_SIZE + 4;
		        if (payload.size() < headerSize) return std::nullopt;
		        size_t off = 0;
		        uint64_t epochId = readU64LE(payload, off);
		        off += 8;
		        uint32_t iterations = readU32LE(payload, off);
		        off += 4;
		        crypto::Hash256 epochSeed{};
		        std::memcpy(epochSeed.data(), payload.data() + off, epochSeed.size());
		        off += epochSeed.size();
		        uint64_t totalBudget = readU64LE(payload, off);
		        off += 8;
		        crypto::Hash256 allocHash{};
		        std::memcpy(allocHash.data(), payload.data() + off, allocHash.size());
		        off += allocHash.size();
		        uint32_t count = readU32LE(payload, off);
		        off += 4;

		        const size_t itemSize = crypto::SHA256_SIZE + crypto::SHA256_SIZE + crypto::PUBLIC_KEY_SIZE + 8 + 8;
		        size_t need = off + static_cast<size_t>(count) * itemSize;
		        if (need > payload.size()) return std::nullopt;

		        std::vector<core::PoeEpochAllocation> allocations;
		        allocations.reserve(count);
		        for (uint32_t i = 0; i < count; ++i) {
		            core::PoeEpochAllocation a;
		            std::memcpy(a.submitId.data(), payload.data() + off, a.submitId.size());
		            off += a.submitId.size();
		            std::memcpy(a.contentId.data(), payload.data() + off, a.contentId.size());
		            off += a.contentId.size();
		            std::memcpy(a.authorPubKey.data(), payload.data() + off, a.authorPubKey.size());
		            off += a.authorPubKey.size();
		            a.score = readU64LE(payload, off);
		            off += 8;
		            a.amount = readU64LE(payload, off);
		            off += 8;
		            allocations.push_back(a);
		        }

		        core::PoeEpochResult out;
		        out.ok = true;
		        out.epochId = epochId;
		        out.iterations = iterations;
		        out.epochSeed = epochSeed;
		        out.totalBudget = totalBudget;
		        out.allocationHash = allocHash;
		        out.allocations = std::move(allocations);
		        return out;
		    }

		    void sendPoeInventory(const std::string& peerId) {
		        if (!network_ || !poeV1_) return;

	        const size_t maxEntries = config_.dev ? 250 : 100;
	        const size_t maxVotes = config_.dev ? 500 : 200;
	        const size_t maxEpochs = config_.dev ? 128 : 64;

	        auto entries = poeV1_->listEntryIds(maxEntries);
	        auto votes = poeV1_->listVoteIds(maxVotes);
	        auto epochs = poeV1_->listEpochIds(maxEpochs);
	        if (entries.empty() && votes.empty() && epochs.empty()) return;

	        synapse::InvMessage inv;
	        inv.items.reserve(entries.size() + votes.size() + epochs.size());

        for (const auto& sid : entries) {
            synapse::InvItem item;
            item.type = synapse::InvType::POE_ENTRY;
            std::memcpy(item.hash.data(), sid.data(), sid.size());
            inv.items.push_back(item);
        }

	        for (const auto& vid : votes) {
	            synapse::InvItem item;
	            item.type = synapse::InvType::POE_VOTE;
	            std::memcpy(item.hash.data(), vid.data(), vid.size());
	            inv.items.push_back(item);
	        }

	        for (uint64_t epochId : epochs) {
	            synapse::InvItem item;
	            item.type = synapse::InvType::POE_EPOCH;
	            crypto::Hash256 hid = poeEpochInvHash(epochId);
	            std::memcpy(item.hash.data(), hid.data(), hid.size());
	            inv.items.push_back(item);
	        }

	        auto msg = makeMessage("inv", inv.serialize());
	        network_->send(peerId, msg);
	    }

	    void sendPoeGetInv(const std::string& peerId, PoeInvKind kind, const crypto::Hash256& after, uint32_t limit) {
	        if (!network_ || !poeV1_) return;
	        if (limit == 0) limit = 1;
	        if (limit > 2048) limit = 2048;
	        std::vector<uint8_t> payload;
	        payload.reserve(1 + crypto::SHA256_SIZE + 4);
	        payload.push_back(static_cast<uint8_t>(kind));
	        payload.insert(payload.end(), after.begin(), after.end());
	        writeU32LE(payload, limit);
	        auto msg = makeMessage("poe_getinv", payload);
	        network_->send(peerId, msg);
	    }

	    void startPoeSync(const std::string& peerId) {
	        if (!network_ || !poeV1_) return;

	        uint32_t limitEntries = config_.dev ? 512 : 256;
	        uint32_t limitVotes = config_.dev ? 1024 : 512;
	        uint64_t now = std::time(nullptr);

	        bool doEntries = false;
	        bool doVotes = false;
	        {
	            std::lock_guard<std::mutex> lock(poeSyncMtx_);
	            auto& st = poeSync_[peerId];
	            if (!st.entries.active) {
	                st.entries.active = true;
	                st.entries.inFlight = true;
	                st.entries.done = false;
	                st.entries.after = crypto::Hash256{};
	                st.entries.limit = limitEntries;
	                st.entries.lastRequestAt = now;
	                doEntries = true;
	            }
	            if (!st.votes.active) {
	                st.votes.active = true;
	                st.votes.inFlight = true;
	                st.votes.done = false;
	                st.votes.after = crypto::Hash256{};
	                st.votes.limit = limitVotes;
	                st.votes.lastRequestAt = now;
	                doVotes = true;
	            }
	        }

	        if (doEntries) sendPoeGetInv(peerId, PoeInvKind::ENTRY, crypto::Hash256{}, limitEntries);
	        if (doVotes) sendPoeGetInv(peerId, PoeInvKind::VOTE, crypto::Hash256{}, limitVotes);
	    }

	    std::vector<crypto::Hash256> selectPoeIdsPage(PoeInvKind kind, const crypto::Hash256& after, uint32_t limit) {
	        if (!poeV1_) return {};

	        std::vector<crypto::Hash256> all;
	        if (kind == PoeInvKind::ENTRY) {
	            all = poeV1_->listEntryIds(0);
	        } else if (kind == PoeInvKind::VOTE) {
	            all = poeV1_->listVoteIds(0);
	        } else if (kind == PoeInvKind::EPOCH) {
	            auto epochs = poeV1_->listEpochIds(0);
	            all.reserve(epochs.size());
	            for (uint64_t eid : epochs) {
	                all.push_back(poeEpochInvHash(eid));
	            }
	        } else {
	            return {};
	        }

	        auto it = std::upper_bound(all.begin(), all.end(), after, [](const crypto::Hash256& v, const crypto::Hash256& e) {
	            return hashLess(v, e);
	        });

	        std::vector<crypto::Hash256> page;
	        page.reserve(std::min<size_t>(static_cast<size_t>(limit), all.size()));
	        for (; it != all.end() && page.size() < limit; ++it) {
	            page.push_back(*it);
	        }
	        return page;
	    }

	    void handlePoeGetInvMessage(const std::string& peerId, const network::Message& msg) {
	        if (!network_ || !poeV1_) return;
	        if (msg.payload.size() < 1 + crypto::SHA256_SIZE + 4) return;

	        PoeInvKind kind = static_cast<PoeInvKind>(msg.payload[0]);
	        crypto::Hash256 after{};
	        std::memcpy(after.data(), msg.payload.data() + 1, after.size());
	        uint32_t limit = readU32LE(msg.payload, 1 + crypto::SHA256_SIZE);
	        if (limit == 0) limit = 1;
	        if (limit > 2048) limit = 2048;

	        auto page = selectPoeIdsPage(kind, after, limit);

	        std::vector<uint8_t> payload;
	        payload.reserve(1 + crypto::SHA256_SIZE + 4 + page.size() * crypto::SHA256_SIZE);
	        payload.push_back(static_cast<uint8_t>(kind));
	        payload.insert(payload.end(), after.begin(), after.end());
	        writeU32LE(payload, static_cast<uint32_t>(page.size()));
	        for (const auto& h : page) {
	            payload.insert(payload.end(), h.begin(), h.end());
	        }

	        auto reply = makeMessage("poe_inv", payload);
	        network_->send(peerId, reply);
	    }

	    void handlePoeInvMessage(const std::string& peerId, const network::Message& msg) {
	        if (!network_ || !poeV1_) return;
	        if (msg.payload.size() < 1 + crypto::SHA256_SIZE + 4) return;

	        PoeInvKind kind = static_cast<PoeInvKind>(msg.payload[0]);
	        crypto::Hash256 after{};
	        std::memcpy(after.data(), msg.payload.data() + 1, after.size());
	        uint32_t count = readU32LE(msg.payload, 1 + crypto::SHA256_SIZE);
	        size_t expected = 1 + crypto::SHA256_SIZE + 4 + static_cast<size_t>(count) * crypto::SHA256_SIZE;
	        if (expected > msg.payload.size()) return;

	        uint32_t limit = 0;
	        {
	            std::lock_guard<std::mutex> lock(poeSyncMtx_);
	            auto it = poeSync_.find(peerId);
	            if (it == poeSync_.end()) return;
	            PoeSyncState* st = nullptr;
	            if (kind == PoeInvKind::ENTRY) st = &it->second.entries;
	            else if (kind == PoeInvKind::VOTE) st = &it->second.votes;
	            else if (kind == PoeInvKind::EPOCH) st = &it->second.epochs;
	            if (!st) return;
	            if (!st->active || st->done) return;
	            if (!st->inFlight) return;
	            if (st->after != after) return;
	            limit = st->limit;
	        }

	        synapse::InvMessage inv;
	        inv.items.reserve(count);
	        const uint8_t* ptr = msg.payload.data() + 1 + crypto::SHA256_SIZE + 4;
	        for (uint32_t i = 0; i < count; ++i) {
	            synapse::InvItem item;
	            if (kind == PoeInvKind::ENTRY) item.type = synapse::InvType::POE_ENTRY;
	            else if (kind == PoeInvKind::VOTE) item.type = synapse::InvType::POE_VOTE;
	            else if (kind == PoeInvKind::EPOCH) item.type = synapse::InvType::POE_EPOCH;
	            else return;
	            std::memcpy(item.hash.data(), ptr, crypto::SHA256_SIZE);
	            ptr += crypto::SHA256_SIZE;
	            inv.items.push_back(item);
	        }

	        network::Message fakeInv = makeMessage("inv", inv.serialize());
	        handleInvMessage(peerId, fakeInv);

	        crypto::Hash256 nextAfter = after;
	        if (!inv.items.empty()) {
	            std::memcpy(nextAfter.data(), inv.items.back().hash.data(), nextAfter.size());
	        }

	        bool shouldContinue = (count == limit) && (nextAfter != after);
	        bool done = !shouldContinue;
	        uint64_t now = std::time(nullptr);

	        {
	            std::lock_guard<std::mutex> lock(poeSyncMtx_);
	            auto it = poeSync_.find(peerId);
	            if (it != poeSync_.end()) {
	                PoeSyncState* st = nullptr;
	                if (kind == PoeInvKind::ENTRY) st = &it->second.entries;
	                else if (kind == PoeInvKind::VOTE) st = &it->second.votes;
	                else if (kind == PoeInvKind::EPOCH) st = &it->second.epochs;
	                if (st) {
	                    st->inFlight = false;
	                    if (done) {
	                        st->done = true;
	                    } else {
	                        st->after = nextAfter;
	                        st->inFlight = true;
	                        st->lastRequestAt = now;
	                        st->pages += 1;
	                    }
	                }
	            }
	        }

	        if (shouldContinue) {
	            sendPoeGetInv(peerId, kind, nextAfter, limit);
	        }
	    }
	    
	    void broadcastInv(synapse::InvType type, const crypto::Hash256& hash) {
	        if (!network_) return;
	        synapse::InvMessage inv;
        synapse::InvItem item;
        item.type = type;
        std::memcpy(item.hash.data(), hash.data(), hash.size());
        inv.items.push_back(item);
        auto msg = makeMessage("inv", inv.serialize());
        network_->broadcast(msg);
    }
    
	    void handleMessage(const std::string& peerId, const network::Message& msg) {
	        if (msg.command == "ping") {
            network::Message pong;
            pong.command = "pong";
            pong.payload = msg.payload;
            network_->send(peerId, pong);
        } else if (msg.command == "pong") {
            handlePongMessage(peerId, msg);
        } else if (msg.command == "version") {
            handleVersionMessage(peerId, msg);
        } else if (msg.command == "verack") {
            handleVerackMessage(peerId, msg);
        } else if (msg.command == "getaddr") {
            handleGetAddrMessage(peerId, msg);
        } else if (msg.command == "addr") {
            handleAddrMessage(peerId, msg);
        } else if (msg.command == "getpeers") {
            handleGetPeersMessage(peerId, msg);
        } else if (msg.command == "peers") {
            handlePeersMessage(peerId, msg);
        } else if (msg.command == "inv") {
            handleInvMessage(peerId, msg);
        } else if (msg.command == "getdata") {
            handleGetDataMessage(peerId, msg);
        } else if (msg.command == "getblock") {
            handleGetBlockMessage(peerId, msg);
        } else if (msg.command == "block") {
            handleBlockMessage(peerId, msg);
	        } else if (msg.command == "knowledge") {
	            handleKnowledgeMessage(peerId, msg);
	        } else if (msg.command == "tx") {
	            handleTxMessage(peerId, msg);
	        } else if (msg.command == "mempool") {
	            handleMempoolMessage(peerId, msg);
	        } else if (msg.command == "poe_getinv") {
	            handlePoeGetInvMessage(peerId, msg);
	        } else if (msg.command == "poe_inv") {
	            handlePoeInvMessage(peerId, msg);
	        } else if (msg.command == "poe_entry") {
	            handlePoeEntryMessage(peerId, msg);
	        } else if (msg.command == "poe_vote") {
	            handlePoeVoteMessage(peerId, msg);
	        } else if (msg.command == "poe_epoch") {
	            handlePoeEpochMessage(peerId, msg);
	        } else if (msg.command == "m_offer") {
	            handleRemoteOfferMessage(peerId, msg);
	        } else if (msg.command == "m_rent") {
	            handleRemoteRentMessage(peerId, msg);
	        } else if (msg.command == "m_rentok") {
	            handleRemoteRentOkMessage(peerId, msg);
	        } else if (msg.command == "m_infer") {
	            handleRemoteInferMessage(peerId, msg);
	        } else if (msg.command == "m_out") {
	            handleRemoteOutMessage(peerId, msg);
	        }
	    }

    static std::string pubKeyHex33(const std::array<uint8_t, 33>& pk) {
        return crypto::toHex(pk.data(), pk.size());
    }

    static std::string randomHex16() {
        std::array<uint8_t, 16> b{};
        std::random_device rd;
        for (auto& v : b) v = static_cast<uint8_t>(rd());
        return crypto::toHex(b.data(), b.size());
    }

    synapse::RemoteModelOfferMessage buildLocalOffer(uint64_t now) {
        synapse::RemoteModelOfferMessage offer;
        {
            std::lock_guard<std::mutex> lock(remoteProvMtx_);
            offer.offerId = localOfferId_;
        }
        offer.providerAddress = address_;
        offer.pricePerRequestAtoms = remotePricePerRequestAtoms_;
        offer.maxSlots = modelAccess_ ? modelAccess_->getMaxSlots() : 0;
        offer.usedSlots = modelAccess_ ? modelAccess_->getActiveSlots() : 0;
        offer.expiresAt = now + 120;

        if (modelLoader_) {
            std::lock_guard<std::mutex> lock(modelMtx_);
            auto info = modelLoader_->getInfo();
            offer.modelId = info.name.empty() ? "active" : info.name;
        }
        if (offer.modelId.empty()) offer.modelId = "active";
        return offer;
    }

    bool verifyPaymentToSelf(const std::string& paymentTxidHex, uint64_t minAtoms, uint64_t& paidOut) const {
        paidOut = 0;
        if (!transfer_) return false;
        auto bytes = crypto::fromHex(paymentTxidHex);
        if (bytes.size() != 32) return false;
        crypto::Hash256 txid{};
        std::memcpy(txid.data(), bytes.data(), txid.size());
        if (!transfer_->hasTransaction(txid)) return false;
        core::Transaction tx = transfer_->getTransaction(txid);
        if (tx.outputs.empty()) return false;
        for (const auto& outp : tx.outputs) {
            if (outp.address == address_) {
                if (UINT64_MAX - paidOut < outp.amount) return false;
                paidOut += outp.amount;
            }
        }
        return paidOut >= minAtoms;
    }

    void handleRemoteOfferMessage(const std::string& peerId, const network::Message& msg) {
        if (msg.payload.empty()) return;
        synapse::RemoteModelOfferMessage offer;
        try {
            offer = synapse::RemoteModelOfferMessage::deserialize(msg.payload);
        } catch (...) {
            return;
        }
        if (offer.offerId.empty() || offer.modelId.empty() || offer.providerAddress.empty()) return;
        uint64_t now = std::time(nullptr);
        if (offer.expiresAt != 0 && offer.expiresAt < now) return;
        std::lock_guard<std::mutex> lock(remoteMtx_);
        RemoteOfferCache c;
        c.offer = offer;
        c.peerId = peerId;
        c.receivedAt = now;
        remoteOffers_[offer.offerId] = std::move(c);
    }

    void handleRemoteRentMessage(const std::string& peerId, const network::Message& msg) {
        if (msg.payload.empty()) return;
        if (!modelAccess_) return;
        synapse::RemoteModelRentMessage rent;
        try {
            rent = synapse::RemoteModelRentMessage::deserialize(msg.payload);
        } catch (...) {
            return;
        }
        if (rent.offerId.empty()) return;

        // Only honor rent requests for our currently advertised offer.
        std::string expectedOffer;
        {
            std::lock_guard<std::mutex> lock(remoteProvMtx_);
            expectedOffer = localOfferId_;
        }
        if (expectedOffer.empty() || rent.offerId != expectedOffer) return;

        const std::string renterId = pubKeyHex33(rent.renterPubKey);
        if (!modelAccess_->canAccess(renterId)) return;
        if (!modelAccess_->hasAvailableSlot()) return;

        const uint64_t now = std::time(nullptr);
        const uint64_t sessionTtl = config_.dev ? 900 : 3600;
        const uint64_t expiresAt = now + sessionTtl;

        if (!modelAccess_->startSession(renterId)) return;

        synapse::RemoteModelRentOkMessage ok;
        ok.offerId = rent.offerId;
        // Use marketplace session id as remote session id for unified accounting.
        if (!modelMarketplace_) return;
        ok.sessionId = modelMarketplace_->rentModel(ok.offerId, renterId);
        if (ok.sessionId.empty()) {
            // Roll back access session if marketplace can't allocate.
            (void)modelAccess_->endSession(renterId);
            return;
        }
        ok.providerAddress = address_;
        ok.pricePerRequestAtoms = remotePricePerRequestAtoms_;
        ok.expiresAt = expiresAt;

        {
            std::lock_guard<std::mutex> lock(remoteProvMtx_);
            ProviderSession ps;
            ps.renterId = renterId;
            ps.expiresAt = expiresAt;
            ps.pricePerRequestAtoms = remotePricePerRequestAtoms_;
            providerSessions_[ok.sessionId] = std::move(ps);
        }

        if (network_) {
            auto reply = makeMessage("m_rentok", ok.serialize());
            network_->send(peerId, reply);
        }
    }

    void handleRemoteRentOkMessage(const std::string& peerId, const network::Message& msg) {
        if (msg.payload.empty()) return;
        synapse::RemoteModelRentOkMessage ok;
        try {
            ok = synapse::RemoteModelRentOkMessage::deserialize(msg.payload);
        } catch (...) {
            return;
        }
        if (ok.offerId.empty() || ok.sessionId.empty() || ok.providerAddress.empty()) return;
        RemoteSessionInfo s;
        s.peerId = peerId;
        s.sessionId = ok.sessionId;
        s.providerAddress = ok.providerAddress;
        s.pricePerRequestAtoms = ok.pricePerRequestAtoms;
        s.expiresAt = ok.expiresAt;
        {
            std::lock_guard<std::mutex> lock(remoteMtx_);
            remoteSessions_[s.sessionId] = s;
            remoteRentOkByOffer_[ok.offerId] = ok;
        }
        remoteCv_.notify_all();
    }

    void handleRemoteInferMessage(const std::string& peerId, const network::Message& msg) {
        if (msg.payload.empty()) return;
        if (!modelLoader_ || !modelAccess_) return;
        synapse::RemoteModelInferMessage req;
        try {
            req = synapse::RemoteModelInferMessage::deserialize(msg.payload);
        } catch (...) {
            return;
        }
        if (req.sessionId.empty() || req.requestId.empty() || req.prompt.empty()) return;

        ProviderSession sess;
        {
            std::lock_guard<std::mutex> lock(remoteProvMtx_);
            auto it = providerSessions_.find(req.sessionId);
            if (it == providerSessions_.end()) return;
            sess = it->second;
        }
        const uint64_t now = std::time(nullptr);
        if (sess.expiresAt != 0 && sess.expiresAt < now) return;

        const std::string renterId = pubKeyHex33(req.renterPubKey);
        if (!renterId.empty() && renterId != sess.renterId) return;
        if (!modelAccess_->canAccess(sess.renterId)) return;
        if (modelAccess_->isRateLimited(sess.renterId)) return;

        // Enforce payment (mempool/confirmed). Provider address is our local address_.
        uint64_t paid = 0;
        bool paidOk = false;
        if (sess.pricePerRequestAtoms > 0) {
            paidOk = verifyPaymentToSelf(req.paymentTxidHex, sess.pricePerRequestAtoms, paid);
        } else {
            paidOk = true;
        }

        auto sendErr = [&](const std::string& errText) {
            synapse::RemoteModelOutMessage out;
            out.requestId = req.requestId;
            out.text = errText;
            out.tokensUsed = 0;
            out.latencyMs = 0;
            if (network_) {
                network_->send(peerId, makeMessage("m_out", out.serialize()));
            }
        };

        if (!paidOk) {
            sendErr("ERROR: payment_invalid_or_missing");
            return;
        }

        std::string resultText;
        uint64_t startMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());

        {
            std::lock_guard<std::mutex> lock(modelMtx_);
            if (!modelLoader_->isLoaded()) {
                sendErr("ERROR: model_not_loaded");
                return;
            }
            if (modelLoader_->isGenerating()) {
                sendErr("ERROR: model_busy");
                return;
            }
            model::GenerationParams gp;
            gp.maxTokens = std::max<uint32_t>(1, req.maxTokens);
            gp.temperature = std::max(0.0f, req.temperature);
            gp.topP = std::max(0.0f, req.topP);
            gp.topK = req.topK;
            resultText = modelLoader_->generate(req.prompt, gp);
        }

        uint64_t endMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        uint64_t latency = (endMs >= startMs) ? (endMs - startMs) : 0;

        if (paid > 0) {
            modelAccess_->recordPayment(sess.renterId, paid);
            if (modelMarketplace_) {
                (void)modelMarketplace_->recordPayment(req.sessionId, paid);
            }
        }
        modelAccess_->recordRequest(sess.renterId, 0, static_cast<double>(latency));
        if (modelMarketplace_) {
            (void)modelMarketplace_->recordRequest(req.sessionId, 0, latency);
        }

        synapse::RemoteModelOutMessage out;
        out.requestId = req.requestId;
        out.text = resultText;
        out.tokensUsed = 0;
        out.latencyMs = latency;
        if (network_) {
            network_->send(peerId, makeMessage("m_out", out.serialize()));
        }
    }

    void handleRemoteOutMessage(const std::string& peerId, const network::Message& msg) {
        (void)peerId;
        if (msg.payload.empty()) return;
        synapse::RemoteModelOutMessage out;
        try {
            out = synapse::RemoteModelOutMessage::deserialize(msg.payload);
        } catch (...) {
            return;
        }
        if (out.requestId.empty()) return;
        {
            std::lock_guard<std::mutex> lock(remoteMtx_);
            auto it = remotePending_.find(out.requestId);
            if (it != remotePending_.end()) {
                it->second.done = true;
                it->second.text = out.text;
                it->second.tokensUsed = out.tokensUsed;
                it->second.latencyMs = out.latencyMs;
            }
        }
        remoteCv_.notify_all();
    }
    
    void handleVersionMessage(const std::string& peerId, const network::Message& msg) {
        if (msg.payload.size() < 40) return;
        synapse::VersionMessage v = synapse::VersionMessage::deserialize(msg.payload);
        peerHeights_[peerId] = v.startHeight;
        if (v.startHeight > networkHeight_) {
            networkHeight_ = v.startHeight;
        }
        
        // Extract our external IP from version message if available
        // The remote peer's view of our address is in addrRecv
        if (discovery_ && v.addrRecv[10] == 0xff && v.addrRecv[11] == 0xff) {
            char ipStr[INET_ADDRSTRLEN];
            in_addr ipv4{};
            std::memcpy(&ipv4, v.addrRecv.data() + 12, 4);
            if (inet_ntop(AF_INET, &ipv4, ipStr, sizeof(ipStr))) {
                std::string ourIP = ipStr;
                // Only set if it's not localhost
                if (ourIP != "127.0.0.1" && ourIP != "0.0.0.0" && ourIP.find("127.") != 0) {
                    discovery_->setExternalAddress(ourIP);
                }
            }
        }
        
        sendVerack(peerId);
        sendGetAddr(peerId);
        sendMempoolRequest(peerId);
        sendPoeInventory(peerId);
        startPoeSync(peerId);
    }
    
    void handleVerackMessage(const std::string& peerId, const network::Message& msg) {
        (void)peerId;
        (void)msg;
    }
    
    void handlePongMessage(const std::string& peerId, const network::Message& msg) {
        (void)peerId;
        (void)msg;
    }
    
    void handleGetAddrMessage(const std::string& peerId, const network::Message& msg) {
        (void)msg;
        if (!discovery_) return;
        auto peers = discovery_->getKnownPeers(100);
        synapse::PeersMessage peersMsg;
        for (const auto& peer : peers) {
            synapse::PeerAddress addr{};
            addr.timestamp = peer.timestamp;
            addr.services = peer.services;
            addr.port = peer.port;
            addr.addr.fill(0);
            in_addr ipv4{};
            if (inet_pton(AF_INET, peer.address.c_str(), &ipv4) == 1) {
                addr.addr[10] = 0xff;
                addr.addr[11] = 0xff;
                std::memcpy(addr.addr.data() + 12, &ipv4, 4);
                peersMsg.peers.push_back(addr);
            }
        }
        auto reply = makeMessage("addr", peersMsg.serialize());
        network_->send(peerId, reply);
    }
    
    void handleAddrMessage(const std::string& peerId, const network::Message& msg) {
        (void)peerId;
        if (msg.payload.empty()) return;
        if (!discovery_) return;
        synapse::PeersMessage peersMsg = synapse::PeersMessage::deserialize(msg.payload);
        std::vector<network::PeerInfo> incoming;
        for (const auto& addr : peersMsg.peers) {
            if (addr.addr[10] == 0xff && addr.addr[11] == 0xff) {
                char ipStr[INET_ADDRSTRLEN];
                in_addr ipv4{};
                std::memcpy(&ipv4, addr.addr.data() + 12, 4);
                if (inet_ntop(AF_INET, &ipv4, ipStr, sizeof(ipStr))) {
                    network::PeerInfo info;
                    info.address = ipStr;
                    info.port = addr.port;
                    info.services = addr.services;
                    info.timestamp = addr.timestamp;
                    info.lastSeen = addr.timestamp;
                    incoming.push_back(info);
                }
            }
        }
        if (!incoming.empty()) {
            discovery_->processIncoming(incoming);
        }
    }
    
    void handleGetPeersMessage(const std::string& peerId, const network::Message& msg) {
        (void)msg;
        if (!discovery_ || !network_) return;
        
        // Rate limiting: check if we've sent to this peer recently
        static std::unordered_map<std::string, uint64_t> lastSent;
        uint64_t now = std::time(nullptr);
        auto it = lastSent.find(peerId);
        if (it != lastSent.end() && now - it->second < 60) {
            return; // Rate limit: max 1 response per minute per peer
        }
        lastSent[peerId] = now;
        
        // Get random peers (max 50, excluding the requesting peer)
        auto allPeers = discovery_->getRandomPeers(50);
        synapse::PeersMessage peersMsg;
        
        // Get requesting peer's address to exclude it
        std::string requestingPeerAddr;
        auto networkPeers = network_->getPeers();
        for (const auto& p : networkPeers) {
            if (p.id == peerId) {
                requestingPeerAddr = p.address;
                break;
            }
        }
        
        for (const auto& peer : allPeers) {
            // Don't send the requesting peer back to itself
            if (peer.address == requestingPeerAddr && peer.port == network_->getPort()) {
                continue;
            }
            
            // Skip banned peers
            if (discovery_->isBanned(peer.address)) {
                continue;
            }
            
            synapse::PeerAddress addr{};
            addr.timestamp = peer.timestamp;
            addr.services = peer.services;
            addr.port = peer.port;
            addr.addr.fill(0);
            
            in_addr ipv4{};
            if (inet_pton(AF_INET, peer.address.c_str(), &ipv4) == 1) {
                addr.addr[10] = 0xff;
                addr.addr[11] = 0xff;
                std::memcpy(addr.addr.data() + 12, &ipv4, 4);
                peersMsg.peers.push_back(addr);
            }
            
            if (peersMsg.peers.size() >= 50) break; // Max 50 peers per message
        }
        
        if (!peersMsg.peers.empty()) {
            auto reply = makeMessage("peers", peersMsg.serialize());
            network_->send(peerId, reply);
        }
    }
    
    void handlePeersMessage(const std::string& peerId, const network::Message& msg) {
        (void)peerId;
        if (msg.payload.empty()) return;
        if (!discovery_) return;
        
        synapse::PeersMessage peersMsg = synapse::PeersMessage::deserialize(msg.payload);
        std::vector<network::PeerInfo> incoming;
        
        for (const auto& addr : peersMsg.peers) {
            // Only handle IPv4 addresses (mapped IPv6 format)
            if (addr.addr[10] == 0xff && addr.addr[11] == 0xff) {
                char ipStr[INET_ADDRSTRLEN];
                in_addr ipv4{};
                std::memcpy(&ipv4, addr.addr.data() + 12, 4);
                if (inet_ntop(AF_INET, &ipv4, ipStr, sizeof(ipStr))) {
                    std::string ipString = ipStr;
                    
                    // Validate: skip localhost
                    if (ipString == "127.0.0.1" || ipString == "::1" || ipString.find("127.") == 0) {
                        continue;
                    }
                    
                    // Validate: skip banned
                    if (discovery_->isBanned(ipString)) {
                        continue;
                    }
                    
                    // Validate: skip our own address
                    if (network_) {
                        // Check if this is our own address/port
                        bool isSelf = false;
                        auto localAddr = network_->getLocalAddress();
                        if (localAddr == ipString && addr.port == network_->getPort()) {
                            isSelf = true;
                        }
                        // Also check against our known address
                        if (!isSelf && !address_.empty()) {
                            // Could add more checks here if needed
                        }
                        if (isSelf) {
                            continue;
                        }
                    }
                    
                    network::PeerInfo info;
                    info.address = ipString;
                    info.port = addr.port;
                    info.services = addr.services;
                    info.timestamp = addr.timestamp;
                    info.lastSeen = addr.timestamp;
                    info.state = network::DiscoveryPeerState::UNKNOWN;
                    info.attempts = 0;
                    incoming.push_back(info);
                }
            }
        }
        
        if (!incoming.empty()) {
            discovery_->processIncoming(incoming);
        }
    }
    
	    void handleInvMessage(const std::string& peerId, const network::Message& msg) {
	        if (msg.payload.empty()) return;
	        synapse::InvMessage inv = synapse::InvMessage::deserialize(msg.payload);
	        synapse::GetDataMessage req;
        
        for (const auto& item : inv.items) {
            bool known = false;
            std::string h = crypto::toHex(item.hash.data(), item.hash.size());
            
            if (item.type == synapse::InvType::TX) {
                {
                    std::lock_guard<std::mutex> lock(invMtx_);
                    if (knownTxs_.count(h) > 0) known = true;
                }
                if (!known && transfer_) {
                    crypto::Hash256 txid{};
                    std::memcpy(txid.data(), item.hash.data(), txid.size());
                    known = transfer_->hasTransaction(txid);
                }
            } else if (item.type == synapse::InvType::KNOWLEDGE) {
                std::lock_guard<std::mutex> lock(invMtx_);
                known = (knownKnowledge_.count(h) > 0) || (knowledgeByHash_.count(h) > 0);
            } else if (item.type == synapse::InvType::BLOCK) {
                {
                    std::lock_guard<std::mutex> lock(invMtx_);
                    if (knownBlocks_.count(h) > 0) known = true;
                }
                if (!known && ledger_) {
                    crypto::Hash256 bh{};
                    std::memcpy(bh.data(), item.hash.data(), bh.size());
                    known = ledger_->getBlockByHash(bh).hash != crypto::Hash256{};
                }
            } else if (item.type == synapse::InvType::POE_ENTRY) {
                {
                    std::lock_guard<std::mutex> lock(invMtx_);
                    if (knownPoeEntries_.count(h) > 0) known = true;
                }
                if (!known && poeV1_) {
                    crypto::Hash256 sid{};
                    std::memcpy(sid.data(), item.hash.data(), sid.size());
                    known = poeV1_->getEntry(sid).has_value();
                }
	            } else if (item.type == synapse::InvType::POE_VOTE) {
	                {
	                    std::lock_guard<std::mutex> lock(invMtx_);
	                    if (knownPoeVotes_.count(h) > 0) known = true;
	                }
	                if (!known && poeV1_) {
	                    crypto::Hash256 vid{};
	                    std::memcpy(vid.data(), item.hash.data(), vid.size());
	                    known = poeV1_->getVoteById(vid).has_value();
	                }
	            } else if (item.type == synapse::InvType::POE_EPOCH) {
	                {
	                    std::lock_guard<std::mutex> lock(invMtx_);
	                    if (knownPoeEpochs_.count(h) > 0) known = true;
	                }
	                if (!known && poeV1_) {
	                    crypto::Hash256 hid{};
	                    std::memcpy(hid.data(), item.hash.data(), hid.size());
	                    auto eid = epochIdFromPoeInvHash(hid);
	                    if (!eid) {
	                        known = true;
	                    } else {
	                        known = poeV1_->getEpoch(*eid).has_value();
	                    }
	                }
	            }
            
            if (!known) {
                req.items.push_back(item);
            }
        }
        
        if (!req.items.empty()) {
            auto request = makeMessage("getdata", req.serialize());
            network_->send(peerId, request);
        }
    }
    
	    void handleGetDataMessage(const std::string& peerId, const network::Message& msg) {
	        if (msg.payload.empty()) return;
	        synapse::GetDataMessage req = synapse::GetDataMessage::deserialize(msg.payload);
        
        for (const auto& item : req.items) {
            if (item.type == synapse::InvType::TX && transfer_) {
                crypto::Hash256 txid{};
                std::memcpy(txid.data(), item.hash.data(), txid.size());
                core::Transaction tx = transfer_->getTransaction(txid);
                if (tx.txid != crypto::Hash256{}) {
                    auto reply = makeMessage("tx", tx.serialize());
                    network_->send(peerId, reply);
                }
            } else if (item.type == synapse::InvType::KNOWLEDGE && knowledge_) {
                std::string h = crypto::toHex(item.hash.data(), item.hash.size());
                uint64_t id = 0;
                {
                    std::lock_guard<std::mutex> lock(invMtx_);
                    auto it = knowledgeByHash_.find(h);
                    if (it != knowledgeByHash_.end()) id = it->second;
                }
                if (id != 0) {
                    core::KnowledgeEntry entry = knowledge_->get(id);
                    if (entry.id != 0) {
                        auto reply = makeMessage("knowledge", entry.serialize());
                        network_->send(peerId, reply);
                    }
                }
            } else if (item.type == synapse::InvType::BLOCK && ledger_) {
                crypto::Hash256 bh{};
                std::memcpy(bh.data(), item.hash.data(), bh.size());
                core::Block block = ledger_->getBlockByHash(bh);
                if (block.hash != crypto::Hash256{}) {
                    auto reply = makeMessage("block", block.serialize());
                    network_->send(peerId, reply);
                }
            } else if (item.type == synapse::InvType::POE_ENTRY && poeV1_) {
                crypto::Hash256 sid{};
                std::memcpy(sid.data(), item.hash.data(), sid.size());
                auto entry = poeV1_->getEntry(sid);
                if (entry) {
                    auto reply = makeMessage("poe_entry", entry->serialize());
                    network_->send(peerId, reply);
                }
	            } else if (item.type == synapse::InvType::POE_VOTE && poeV1_) {
	                crypto::Hash256 vid{};
	                std::memcpy(vid.data(), item.hash.data(), vid.size());
	                auto vote = poeV1_->getVoteById(vid);
	                if (vote) {
	                    auto reply = makeMessage("poe_vote", vote->serialize());
	                    network_->send(peerId, reply);
	                }
	            } else if (item.type == synapse::InvType::POE_EPOCH && poeV1_) {
	                crypto::Hash256 hid{};
	                std::memcpy(hid.data(), item.hash.data(), hid.size());
	                auto eid = epochIdFromPoeInvHash(hid);
	                if (!eid) continue;
	                auto epoch = poeV1_->getEpoch(*eid);
	                if (epoch) {
	                    auto reply = makeMessage("poe_epoch", serializePoeEpoch(*epoch));
	                    network_->send(peerId, reply);
	                }
	            }
	        }
	    }
    
    void handleGetBlockMessage(const std::string& peerId, const network::Message& msg) {
        if (!ledger_) return;
        if (msg.payload.size() < 8) return;
        uint64_t height = deserializeU64(msg.payload);
        core::Block block = ledger_->getBlock(height);
        if (block.hash != crypto::Hash256{}) {
            auto reply = makeMessage("block", block.serialize());
            network_->send(peerId, reply);
        }
    }
    
    void handleBlockMessage(const std::string& peerId, const network::Message& msg) {
        (void)peerId;
        if (!ledger_) return;
        core::Block block = core::Block::deserialize(msg.payload);
        if (block.hash == crypto::Hash256{}) return;

        std::vector<core::Transaction> blockTxs;
        if (transfer_) {
            for (const auto& ev : block.events) {
                if (ev.type != core::EventType::TRANSFER) continue;
                core::Transaction tx = core::Transaction::deserialize(ev.data);
                if (tx.txid == crypto::Hash256{}) return;
                blockTxs.push_back(tx);
            }
            if (!blockTxs.empty()) {
                if (!transfer_->verifyTransactionsInBlockOrder(blockTxs)) return;
            }
        }

        if (!ledger_->appendBlockWithValidation(block)) return;
        
        {
            std::lock_guard<std::mutex> lock(syncMtx_);
            requestedBlocks_.erase(block.height);
        }
        {
            std::lock_guard<std::mutex> lock(invMtx_);
            knownBlocks_.insert(crypto::toHex(block.hash));
        }
        uint64_t impliedHeight = block.height + 1;
        if (impliedHeight > networkHeight_) {
            networkHeight_ = impliedHeight;
        }
        
        suppressCallbacks_ = true;
        for (const auto& ev : block.events) {
            if (ev.type == core::EventType::KNOWLEDGE && knowledge_) {
                core::KnowledgeEntry entry = core::KnowledgeEntry::deserialize(ev.data);
                knowledge_->importEntry(entry);
            } else if (ev.type == core::EventType::POE_ENTRY && poeV1_) {
                auto entry = core::poe_v1::KnowledgeEntryV1::deserialize(ev.data);
                if (entry) {
                    poeV1_->importEntry(*entry, nullptr);
                }
            } else if (ev.type == core::EventType::POE_VOTE && poeV1_) {
                auto vote = core::poe_v1::ValidationVoteV1::deserialize(ev.data);
                if (vote) {
                    poeV1_->addVote(*vote);
                }
            }
        }
        suppressCallbacks_ = false;

        if (transfer_ && !blockTxs.empty()) {
            if (!transfer_->applyBlockTransactionsFromBlock(blockTxs, block.height, block.hash)) {
                utils::Logger::error("Failed to apply block transfer events (received block)");
            }
        }
    }
    
    void handleKnowledgeMessage(const std::string& peerId, const network::Message& msg) {
        (void)peerId;
        if (!knowledge_) return;
        if (msg.payload.empty()) return;
        core::KnowledgeEntry entry = core::KnowledgeEntry::deserialize(msg.payload);
        knowledge_->importEntry(entry);
    }
    
    void handleTxMessage(const std::string& peerId, const network::Message& msg) {
        (void)peerId;
        if (!transfer_) return;
        if (msg.payload.empty()) return;
        core::Transaction tx = core::Transaction::deserialize(msg.payload);
        transfer_->submitTransaction(tx);
    }

    void handleMempoolMessage(const std::string& peerId, const network::Message& msg) {
        (void)msg;
        if (!network_ || !transfer_) return;

        auto pending = transfer_->getPending();
        if (pending.empty()) return;

        synapse::InvMessage inv;
        size_t limit = 5000;
        size_t count = 0;
        for (const auto& tx : pending) {
            if (count++ >= limit) break;
            synapse::InvItem item;
            item.type = synapse::InvType::TX;
            std::memcpy(item.hash.data(), tx.txid.data(), tx.txid.size());
            inv.items.push_back(item);
        }

        if (inv.items.empty()) return;
        auto reply = makeMessage("inv", inv.serialize());
        network_->send(peerId, reply);
    }

    uint64_t maybeCreditAcceptanceReward(const crypto::Hash256& submitId) {
        if (!poeV1_ || !transfer_) return 0;

        auto fin = poeV1_->finalize(submitId);
        if (!fin) return 0;

        auto entry = poeV1_->getEntry(submitId);
        if (!entry) return 0;

        std::string addr = addressFromPubKey(entry->authorPubKey);
        if (addr.empty()) return 0;

        uint64_t amount = poeV1_->calculateAcceptanceReward(*entry);
        if (amount == 0) return 0;

        crypto::Hash256 rewardId = rewardIdForAcceptance(submitId);
        if (transfer_->creditRewardDeterministic(addr, rewardId, amount)) {
            return amount;
        }
        return 0;
    }

    void maybeAutoVote(const crypto::Hash256& submitId) {
        if (!poeV1_ || !keys_ || !keys_->isValid()) return;

        auto entry = poeV1_->getEntry(submitId);
        if (!entry) return;
        if (poeV1_->isFinalized(submitId)) return;

        updatePoeValidatorsFromStake();
        core::PoeV1Config cfg = poeV1_->getConfig();
        auto validators = poeV1_->getStaticValidators();
        if (validators.empty()) return;

        auto pubV = keys_->getPublicKey();
        if (pubV.size() < crypto::PUBLIC_KEY_SIZE) return;
        crypto::PublicKey selfPub{};
        std::memcpy(selfPub.data(), pubV.data(), selfPub.size());

        auto selected = core::poe_v1::selectValidators(poeV1_->chainSeed(), submitId, validators, cfg.validatorsN);
        if (std::find(selected.begin(), selected.end(), selfPub) == selected.end()) return;

        auto votes = poeV1_->getVotesForSubmit(submitId);
        for (const auto& v : votes) {
            if (v.validatorPubKey == selfPub) return;
        }

        auto privV = keys_->getPrivateKey();
        if (privV.size() < crypto::PRIVATE_KEY_SIZE) return;
        crypto::PrivateKey priv{};
        std::memcpy(priv.data(), privV.data(), priv.size());

        core::poe_v1::ValidationVoteV1 vote;
        vote.version = 1;
        vote.submitId = submitId;
        vote.prevBlockHash = poeV1_->chainSeed();
        vote.flags = 0;
        vote.scores = {100, 100, 100};
        core::poe_v1::signValidationVoteV1(vote, priv);

        crypto::Hash256 vid = vote.payloadHash();
        std::string vidHex = crypto::toHex(vid);

        bool added = poeV1_->addVote(vote);
        if (!added) return;

        {
            std::lock_guard<std::mutex> lock(invMtx_);
            knownPoeVotes_.insert(vidHex);
        }
        broadcastInv(synapse::InvType::POE_VOTE, vid);
        maybeCreditAcceptanceReward(submitId);
    }

    void handlePoeEntryMessage(const std::string& peerId, const network::Message& msg) {
        (void)peerId;
        if (!poeV1_) return;
        if (msg.payload.empty()) return;

        auto entry = core::poe_v1::KnowledgeEntryV1::deserialize(msg.payload);
        if (!entry) return;

        std::string reason;
        bool added = poeV1_->importEntry(*entry, &reason);
        crypto::Hash256 sid = entry->submitId();
        std::string sidHex = crypto::toHex(sid);

        if (added || reason == "duplicate_submit") {
            std::lock_guard<std::mutex> lock(invMtx_);
            knownPoeEntries_.insert(sidHex);
        }

        if (added) {
            broadcastInv(synapse::InvType::POE_ENTRY, sid);
        }

        maybeAutoVote(sid);
        maybeCreditAcceptanceReward(sid);
    }

	    void handlePoeVoteMessage(const std::string& peerId, const network::Message& msg) {
	        (void)peerId;
	        if (!poeV1_) return;
	        if (msg.payload.empty()) return;

        auto vote = core::poe_v1::ValidationVoteV1::deserialize(msg.payload);
        if (!vote) return;

        crypto::Hash256 vid = vote->payloadHash();
        std::string vidHex = crypto::toHex(vid);

        bool added = poeV1_->addVote(*vote);
        if (added) {
            {
                std::lock_guard<std::mutex> lock(invMtx_);
                knownPoeVotes_.insert(vidHex);
            }
            broadcastInv(synapse::InvType::POE_VOTE, vid);
        }

	        maybeCreditAcceptanceReward(vote->submitId);
	    }

	    void handlePoeEpochMessage(const std::string& peerId, const network::Message& msg) {
	        (void)peerId;
	        if (!poeV1_ || !transfer_) return;
	        if (msg.payload.empty()) return;

	        auto epoch = deserializePoeEpoch(msg.payload);
	        if (!epoch) return;

	        crypto::Hash256 hid = poeEpochInvHash(epoch->epochId);
	        std::string hidHex = crypto::toHex(hid);

	        if (!poeV1_->importEpoch(*epoch)) return;

	        {
	            std::lock_guard<std::mutex> lock(invMtx_);
	            knownPoeEpochs_.insert(hidHex);
	        }
	        broadcastInv(synapse::InvType::POE_EPOCH, hid);

	        auto stored = poeV1_->getEpoch(epoch->epochId);
	        if (!stored) return;

	        for (const auto& a : stored->allocations) {
	            std::string addr = addressFromPubKey(a.authorPubKey);
	            if (addr.empty()) continue;
	            crypto::Hash256 rid = rewardIdForEpoch(stored->epochId, a.contentId);
	            transfer_->creditRewardDeterministic(addr, rid, a.amount);
	        }
	    }
    
    void handlePeerConnected(const network::Peer& peer) {
        utils::Logger::info("Peer connected: " + peer.id);
        sendVersion(peer.id);
        
        // Update discovery with successful connection
        if (discovery_) {
            discovery_->markPeerSuccess(peer.address);
        }
    }
    
	    void handlePeerDisconnected(const network::Peer& peer) {
	        utils::Logger::info("Peer disconnected: " + peer.id);
	        peerHeights_.erase(peer.id);
	        {
	            std::lock_guard<std::mutex> lock(poeSyncMtx_);
	            poeSync_.erase(peer.id);
	        }
	        
	        // Update discovery with failed connection
	        if (discovery_) {
	            discovery_->markPeerFailed(peer.address);
	        }
	        
	        uint64_t maxHeight = 0;
	        for (const auto& [id, height] : peerHeights_) {
	            if (height > maxHeight) maxHeight = height;
	        }
	        networkHeight_ = maxHeight;
	    }

    uint64_t getMemoryUsage() const {
        struct rusage usage;
        if (getrusage(RUSAGE_SELF, &usage) == 0) {
            return usage.ru_maxrss * 1024;
        }
        return 0;
    }
    
    uint64_t getDiskUsage() const {
        uint64_t total = 0;
        for (const auto& entry : std::filesystem::recursive_directory_iterator(config_.dataDir)) {
            if (entry.is_regular_file()) {
                total += entry.file_size();
            }
        }
        return total;
    }
    
    std::atomic<bool> running_;
    bool offlineMode_ = false;
    uint64_t startTime_;
    double syncProgress_;
    NodeConfig config_;
    std::string address_;
    
    std::unique_ptr<database::Database> db_;
    std::unique_ptr<crypto::Keys> keys_;
    std::unique_ptr<network::Network> network_;
    std::unique_ptr<network::Discovery> discovery_;
    std::unique_ptr<core::Ledger> ledger_;
    std::unique_ptr<core::KnowledgeNetwork> knowledge_;
    std::unique_ptr<core::TransferManager> transfer_;
	    std::unique_ptr<core::Consensus> consensus_;
	    std::unique_ptr<core::PoeV1Engine> poeV1_;
	    std::unique_ptr<model::ModelLoader> modelLoader_;
	    std::unique_ptr<model::ModelAccess> modelAccess_;
        std::unique_ptr<model::ModelMarketplace> modelMarketplace_;
	    std::mutex modelMtx_;
	    std::atomic<uint64_t> modelRequests_{0};
		    std::unique_ptr<privacy::Privacy> privacy_;
		    std::unique_ptr<quantum::QuantumManager> quantumManager_;
		    std::unique_ptr<web::RpcServer> rpc_;
		    std::unique_ptr<web::WebSearch> webSearch_;
		    std::unique_ptr<web::QueryDetector> webDetector_;
		    std::unique_ptr<web::HtmlExtractor> webExtractor_;
		    std::unique_ptr<web::AIWrapper> webAi_;
		    std::mutex webMtx_;
	    
	    std::unordered_map<std::string, uint64_t> peerHeights_;
    std::unordered_set<std::string> knownTxs_;
    std::unordered_set<std::string> knownKnowledge_;
	    std::unordered_set<std::string> knownBlocks_;
		    std::unordered_set<std::string> knownPoeEntries_;
		    std::unordered_set<std::string> knownPoeVotes_;
		    std::unordered_set<std::string> knownPoeEpochs_;
		    std::unordered_map<std::string, uint64_t> knowledgeByHash_;
		    std::mutex invMtx_;
		    std::mutex poeSyncMtx_;
		    std::unordered_map<std::string, PoePeerSyncState> poeSync_;
	    std::unordered_map<uint64_t, uint64_t> requestedBlocks_;
	    std::mutex syncMtx_;
    std::atomic<uint64_t> networkHeight_{0};
    std::atomic<bool> syncing_{false};
    std::atomic<bool> suppressCallbacks_{false};

        // Remote model routing (opt-in)
        std::mutex remoteMtx_;
        std::condition_variable remoteCv_;
        std::unordered_map<std::string, RemoteOfferCache> remoteOffers_;            // offerId -> offer
        std::unordered_map<std::string, RemoteSessionInfo> remoteSessions_;        // sessionId -> session
        std::unordered_map<std::string, RemotePending> remotePending_;             // requestId -> result
        std::unordered_map<std::string, synapse::RemoteModelRentOkMessage> remoteRentOkByOffer_; // offerId -> ok

        std::mutex remoteProvMtx_;
        std::string localOfferId_;
        uint64_t remotePricePerRequestAtoms_ = 0;
        std::unordered_map<std::string, ProviderSession> providerSessions_;        // sessionId -> session
    
    std::thread networkThread_;
    std::thread consensusThread_;
    std::thread maintenanceThread_;
    std::thread syncThread_;
};

static SynapseNet* g_node = nullptr;

void signalHandler(int signal) {
    if (signal == SIGINT || signal == SIGTERM || (!g_daemonMode && signal == SIGHUP)) {
        if (g_node) g_node->shutdown();
        g_running = false;
    } else if (signal == SIGHUP) {
        g_reloadConfig = true;
    }
}

void printBanner() {
    std::cout << R"(
  ____                              _   _      _   
 / ___| _   _ _ __   __ _ _ __  ___| \ | | ___| |_ 
 \___ \| | | | '_ \ / _` | '_ \/ __|  \| |/ _ \ __|
  ___) | |_| | | | | (_| | |_) \__ \ |\  |  __/ |_ 
 |____/ \__, |_| |_|\__,_| .__/|___/_| \_|\___|\__|
        |___/            |_|                       
)" << std::endl;
    std::cout << "  Decentralized AI Knowledge Network v0.1.0" << std::endl;
    std::cout << "  ==========================================" << std::endl;
    std::cout << std::endl;
}

void printHelp(const char* progName) {
    std::cout << "SynapseNet v0.1.0 - Decentralized Knowledge Network\n\n";
    std::cout << "Usage: " << progName << " [command] [options]\n\n";
    std::cout << "Commands:\n";
    std::cout << "  (none)              Start node with TUI\n";
    std::cout << "  status              Show node status\n";
    std::cout << "  peers               List connected peers\n";
    std::cout << "  submit <file>       Contribute knowledge\n";
    std::cout << "  send <addr> <amt>   Transfer NGT\n";
    std::cout << "  query <text>        Search knowledge network\n";
    std::cout << "  balance             Show wallet balance\n";
    std::cout << "  address             Show wallet address\n";
    std::cout << "  logs                Show recent activity\n";
    std::cout << "  seeds               Show bootstrap/DNS seeds\n";
    std::cout << "  discovery           Show discovery diagnostics\n";
    std::cout << "\nOptions:\n";
    std::cout << "  -h, --help          Show this help\n";
    std::cout << "  -v, --version       Show version\n";
    std::cout << "  -d, --daemon        Run as daemon (no TUI)\n";
    std::cout << "  -c, --config FILE   Use custom config file\n";
    std::cout << "  -D, --datadir DIR   Data directory\n";
    std::cout << "  -p, --port PORT     P2P port (default: 8333)\n";
    std::cout << "  -r, --rpcport PORT  RPC port (default: 8332)\n";
    std::cout << "  --testnet           Connect to testnet\n";
    std::cout << "  --regtest           Run in regression test mode\n";
    std::cout << "  --privacy           Enable privacy mode (Tor)\n";
    std::cout << "  --amnesia           RAM-only mode, zero traces\n";
    std::cout << "  --dev               Developer mode (fast PoE params)\n";
    std::cout << "  --reset-ngt         Clear all NGT balances (transfer DB)\n";
    std::cout << "  --poe-validators X  Comma-separated validator pubkeys (hex)\n";
    std::cout << "  --poe-validator-mode MODE  Validator mode: static|stake (default: static)\n";
    std::cout << "  --poe-min-stake NGT         Minimum stake for stake-mode validators (default: 0)\n";
    std::cout << "  --quantum           Enable quantum security\n";
    std::cout << "  --security LEVEL    Security level (standard/high/paranoid)\n";
    std::cout << "  --connect HOST:PORT Connect to specific node\n";
    std::cout << "  --addnode HOST:PORT Add node to connection list\n";
    std::cout << "  --seednode HOST:PORT Add seed node\n";
    std::cout << "  --maxpeers N        Maximum peer connections\n";
    std::cout << "  --dbcache N         Database cache size in MB\n";
    std::cout << "  --loglevel LEVEL    Log level (debug/info/warn/error)\n";
}

void printVersion() {
    std::cout << "SynapseNet v0.1.0-alpha\n";
    std::cout << "Protocol version: 1\n";
    std::cout << "Build: " << __DATE__ << " " << __TIME__ << "\n";
    std::cout << "Crypto: Built-in implementation\n";
}

static bool rpcHttpPost(uint16_t port, const std::string& body, std::string& responseBodyOut, std::string& errorOut, int timeoutSeconds) {
    responseBodyOut.clear();
    errorOut.clear();

    int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        errorOut = "socket() failed";
        return false;
    }

    struct timeval tv;
    tv.tv_sec = timeoutSeconds;
    tv.tv_usec = 0;
    ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (::connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(sock);
        errorOut = "connect() failed";
        return false;
    }

    std::ostringstream req;
    req << "POST / HTTP/1.1\r\n";
    req << "Host: 127.0.0.1\r\n";
    req << "Content-Type: application/json\r\n";
    req << "Content-Length: " << body.size() << "\r\n";
    req << "Connection: close\r\n";
    req << "\r\n";
    req << body;
    std::string reqStr = req.str();

    size_t sent = 0;
    while (sent < reqStr.size()) {
        ssize_t n = ::send(sock, reqStr.data() + sent, reqStr.size() - sent, 0);
        if (n <= 0) {
            ::close(sock);
            errorOut = "send() failed";
            return false;
        }
        sent += static_cast<size_t>(n);
    }

    std::string resp;
    resp.reserve(8192);
    char buf[4096];
    while (true) {
        ssize_t n = ::recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) break;
        resp.append(buf, buf + n);
        if (resp.size() > 8 * 1024 * 1024) {
            ::close(sock);
            errorOut = "response too large";
            return false;
        }
        size_t headerEnd = resp.find("\r\n\r\n");
        if (headerEnd == std::string::npos) continue;

        size_t clPos = resp.find("Content-Length:");
        if (clPos == std::string::npos) continue;
        size_t clEnd = resp.find("\r\n", clPos);
        if (clEnd == std::string::npos) continue;
        std::string clStr = resp.substr(clPos + 15, clEnd - (clPos + 15));
        size_t contentLength = 0;
        try {
            contentLength = static_cast<size_t>(std::stoul(clStr));
        } catch (...) {
            ::close(sock);
            errorOut = "invalid Content-Length";
            return false;
        }

        size_t bodyStart = headerEnd + 4;
        if (resp.size() >= bodyStart + contentLength) {
            responseBodyOut = resp.substr(bodyStart, contentLength);
            ::close(sock);
            return true;
        }
    }

    ::close(sock);
    errorOut = "no response";
    return false;
}

static bool rpcCall(uint16_t port, const std::string& method, const json& params, json& resultOut, std::string& errorOut, int timeoutSeconds) {
    json req;
    req["jsonrpc"] = "2.0";
    req["id"] = 1;
    req["method"] = method;
    req["params"] = params;

    std::string respBody;
    if (!rpcHttpPost(port, req.dump(), respBody, errorOut, timeoutSeconds)) {
        return false;
    }

    json resp;
    try {
        resp = json::parse(respBody);
    } catch (const std::exception& e) {
        errorOut = std::string("invalid JSON response: ") + e.what();
        return false;
    }

    if (resp.contains("error") && !resp["error"].is_null()) {
        try {
            int code = resp["error"].value("code", -1);
            std::string msg = resp["error"].value("message", "RPC error");
            errorOut = "rpc_error(" + std::to_string(code) + "): " + msg;
        } catch (...) {
            errorOut = "rpc_error";
        }
        return false;
    }
    if (!resp.contains("result")) {
        errorOut = "missing result field";
        return false;
    }
    resultOut = resp["result"];
    return true;
}

static bool isRpcTransportError(const std::string& err) {
    if (err == "socket() failed" || err == "connect() failed" || err == "send() failed" || err == "no response") {
        return true;
    }
    if (err.rfind("invalid JSON response:", 0) == 0) {
        return true;
    }
    return err == "missing result field";
}

static std::optional<int> runCliViaRpc(const NodeConfig& config) {
    if (config.commandArgs.empty()) return 0;

    const std::string cmd = config.commandArgs[0];
    const uint16_t rpcPort = config.rpcPort;

    auto call = [&](const std::string& method, const json& params, json& out, std::string& errOut) -> bool {
        errOut.clear();
        bool longOp = false;
        if (method.rfind("ai.", 0) == 0) longOp = true;
        if (method.rfind("poe.", 0) == 0) longOp = true;
        if (method == "model.load") longOp = true;
        int timeoutSeconds = longOp ? 300 : 3;
        return rpcCall(rpcPort, method, params, out, errOut, timeoutSeconds);
    };

    if (cmd == "address") {
        json out;
        std::string err;
        if (!call("wallet.address", json::object(), out, err)) {
            std::cerr << "RPC failed: " << err << "\n";
            return 1;
        }
        std::cout << out.value("address", "") << "\n";
        return 0;
    }

    if (cmd == "balance") {
        json out;
        std::string err;
        if (!call("wallet.balance", json::object(), out, err)) {
            std::cerr << "RPC failed: " << err << "\n";
            return 1;
        }
        std::cout << "address=" << out.value("address", "") << "\n";
        std::cout << "balance=" << std::fixed << std::setprecision(8) << out.value("balance", 0.0) << " NGT\n";
        return 0;
    }

    if (cmd == "poe") {
	        if (config.commandArgs.size() == 1 || config.commandArgs[1] == "help") {
	            std::cout << "Usage:\n";
	            std::cout << "  synapsed poe submit --question Q --answer A [--source S]\n";
	            std::cout << "  synapsed poe submit-code --title T (--patch P | --patch-file PATH)\n";
	            std::cout << "  synapsed poe list-code [--limit N]\n";
	            std::cout << "  synapsed poe fetch-code <submitIdHex|contentIdHex>\n";
	            std::cout << "  synapsed poe vote <submitIdHex>\n";
	            std::cout << "  synapsed poe finalize <submitIdHex>\n";
	            std::cout << "  synapsed poe epoch [--budget NGT] [--iters N]\n";
	            std::cout << "  synapsed poe export <path>\n";
            std::cout << "  synapsed poe import <path>\n";
            std::cout << "  synapsed poe pubkey\n";
            std::cout << "  synapsed poe validators\n";
            return 0;
        }

        const std::string sub = config.commandArgs[1];

        if (sub == "pubkey") {
            json out;
            std::string err;
            if (!call("wallet.address", json::object(), out, err)) {
                if (isRpcTransportError(err)) return std::nullopt;
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            std::cout << out.value("pubkey", "") << "\n";
            return 0;
        }

        if (sub == "validators") {
            json out;
            std::string err;
            if (!call("poe.validators", json::object(), out, err)) {
                if (isRpcTransportError(err)) return std::nullopt;
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            if (out.is_array()) {
                for (const auto& v : out) {
                    if (v.is_string()) std::cout << v.get<std::string>() << "\n";
                }
                if (out.empty()) std::cout << "(none)\n";
            } else {
                std::cout << "(none)\n";
            }
            return 0;
        }

	        if (sub == "submit") {
	            std::unordered_map<std::string, std::string> opts;
	            for (size_t i = 2; i < config.commandArgs.size(); ++i) {
	                if (config.commandArgs[i].rfind("--", 0) != 0) continue;
                std::string k = config.commandArgs[i].substr(2);
                std::string v;
                if (i + 1 < config.commandArgs.size() && config.commandArgs[i + 1].rfind("--", 0) != 0) {
                    v = config.commandArgs[i + 1];
                    i++;
                }
                opts[k] = v;
            }

            std::string q = opts["question"];
            std::string a = opts["answer"];
            std::string s = opts["source"];
            if (q.empty() || a.empty()) {
                std::cerr << "Missing --question/--answer\n";
                return 1;
            }

            json params;
            params["question"] = q;
            params["answer"] = a;
            if (!s.empty()) params["source"] = s;
            params["auto_finalize"] = true;

            json out;
            std::string err;
            if (!call("poe.submit", params, out, err)) {
                if (isRpcTransportError(err)) return std::nullopt;
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            std::cout << "submitId=" << out.value("submitId", "") << "\n";
            std::cout << "contentId=" << out.value("contentId", "") << "\n";
            double credited = out.value("credited", 0.0);
            if (credited > 0.0) {
                std::cout << "acceptanceReward=" << std::fixed << std::setprecision(8) << credited << " NGT\n";
            } else {
                std::cout << "acceptanceReward=0.00000000 NGT\n";
            }
	            return 0;
	        }

	        if (sub == "submit-code") {
	            std::unordered_map<std::string, std::string> opts;
	            for (size_t i = 2; i < config.commandArgs.size(); ++i) {
	                if (config.commandArgs[i].rfind("--", 0) != 0) continue;
	                std::string k = config.commandArgs[i].substr(2);
	                std::string v;
	                if (i + 1 < config.commandArgs.size() && config.commandArgs[i + 1].rfind("--", 0) != 0) {
	                    v = config.commandArgs[i + 1];
	                    i++;
	                }
	                opts[k] = v;
	            }

	            std::string title = opts["title"];
	            std::string patch = opts["patch"];
	            std::string patchFile = opts["patch-file"];
	            if (patch.empty() && !patchFile.empty()) {
	                std::ifstream in(patchFile, std::ios::binary);
	                if (!in) {
	                    std::cerr << "Failed to read --patch-file\n";
	                    return 1;
	                }
	                std::ostringstream ss;
	                ss << in.rdbuf();
	                patch = ss.str();
	            }

	            if (title.empty() || patch.empty()) {
	                std::cerr << "Missing --title and --patch/--patch-file\n";
	                return 1;
	            }

	            json params;
	            params["title"] = title;
	            params["patch"] = patch;
	            std::string cites = opts["citations"];
	            if (!cites.empty()) {
	                for (char& c : cites) if (c == ';') c = ',';
	                json arr = json::array();
	                std::string cur;
	                for (size_t i = 0; i <= cites.size(); ++i) {
	                    if (i == cites.size() || cites[i] == ',') {
	                        std::string t = cur;
	                        auto isSpace = [](unsigned char c) { return std::isspace(c) != 0; };
	                        while (!t.empty() && isSpace(static_cast<unsigned char>(t.front()))) t.erase(t.begin());
	                        while (!t.empty() && isSpace(static_cast<unsigned char>(t.back()))) t.pop_back();
	                        if (!t.empty()) arr.push_back(t);
	                        cur.clear();
	                    } else {
	                        cur.push_back(cites[i]);
	                    }
	                }
	                if (!arr.empty()) params["citations"] = arr;
	            }
	            params["auto_finalize"] = true;

	            json out;
	            std::string err;
	            if (!call("poe.submit_code", params, out, err)) {
	                if (isRpcTransportError(err)) return std::nullopt;
	                std::cerr << "RPC failed: " << err << "\n";
	                return 1;
	            }
	            std::cout << "submitId=" << out.value("submitId", "") << "\n";
	            std::cout << "contentId=" << out.value("contentId", "") << "\n";
	            double credited = out.value("credited", 0.0);
	            if (credited > 0.0) {
	                std::cout << "acceptanceReward=" << std::fixed << std::setprecision(8) << credited << " NGT\n";
	            } else {
	                std::cout << "acceptanceReward=0.00000000 NGT\n";
	            }
	            return 0;
	        }

	        if (sub == "list-code") {
	            size_t limit = 25;
	            for (size_t i = 2; i < config.commandArgs.size(); ++i) {
	                if (config.commandArgs[i] == "--limit" && i + 1 < config.commandArgs.size()) {
	                    limit = static_cast<size_t>(std::max(1, std::stoi(config.commandArgs[i + 1])));
	                    i++;
	                }
	            }
	            json params;
	            params["limit"] = limit;
	            json out;
	            std::string err;
	            if (!call("poe.list_code", params, out, err)) {
	                if (isRpcTransportError(err)) return std::nullopt;
	                std::cerr << "RPC failed: " << err << "\n";
	                return 1;
	            }
	            if (!out.is_array() || out.empty()) {
	                std::cout << "(none)\n";
	                return 0;
	            }
	            for (const auto& item : out) {
	                std::string sid = item.value("submitId", "");
	                std::string title = item.value("title", "");
	                if (!sid.empty()) std::cout << sid << "  " << title << "\n";
	            }
	            return 0;
	        }

	        if (sub == "fetch-code") {
	            if (config.commandArgs.size() < 3) {
	                std::cerr << "Usage: synapsed poe fetch-code <submitIdHex|contentIdHex>\n";
	                return 1;
	            }
	            json params;
	            params["id"] = config.commandArgs[2];
	            json out;
	            std::string err;
	            if (!call("poe.fetch_code", params, out, err)) {
	                if (isRpcTransportError(err)) return std::nullopt;
	                std::cerr << "RPC failed: " << err << "\n";
	                return 1;
	            }
	            std::cout << "submitId=" << out.value("submitId", "") << "\n";
	            std::cout << "contentId=" << out.value("contentId", "") << "\n";
	            std::cout << "timestamp=" << out.value("timestamp", 0) << "\n";
	            std::cout << "title=" << out.value("title", "") << "\n";
	            std::cout << "finalized=" << (out.value("finalized", false) ? "true" : "false") << "\n";
	            std::cout << "patch:\n";
	            std::cout << out.value("patch", "") << "\n";
	            return 0;
	        }

	        if (sub == "vote") {
	            if (config.commandArgs.size() < 3) {
	                std::cerr << "Usage: synapsed poe vote <submitIdHex>\n";
	                return 1;
            }
            json params;
            params["submitId"] = config.commandArgs[2];
            json out;
            std::string err;
            if (!call("poe.vote", params, out, err)) {
                if (isRpcTransportError(err)) return std::nullopt;
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            std::string status = out.value("status", "");
            bool added = out.value("added", false);
            if (!status.empty()) std::cout << status << "\n";
            double credited = out.value("credited", 0.0);
            if (credited > 0.0) {
                std::cout << "credited=" << std::fixed << std::setprecision(8) << credited << " NGT\n";
            }
            return added ? 0 : 1;
        }

        if (sub == "finalize") {
            if (config.commandArgs.size() < 3) {
                std::cerr << "Usage: synapsed poe finalize <submitIdHex>\n";
                return 1;
            }
            json params;
            params["submitId"] = config.commandArgs[2];
            json out;
            std::string err;
            if (!call("poe.finalize", params, out, err)) {
                if (isRpcTransportError(err)) return std::nullopt;
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            bool finalized = out.value("finalized", false);
            if (!finalized) {
                std::cerr << "not_finalized\n";
                return 1;
            }
            std::cout << "finalized\n";
            double credited = out.value("credited", 0.0);
            if (credited > 0.0) {
                std::cout << "credited=" << std::fixed << std::setprecision(8) << credited << " NGT\n";
            }
            return 0;
        }

        if (sub == "epoch") {
            auto parseNgtAtomic = [](const std::string& s, uint64_t& out) -> bool {
                if (s.empty()) return false;
                std::string t = s;
                for (auto& c : t) if (c == ',') c = '.';
                size_t dot = t.find('.');
                std::string intPart = dot == std::string::npos ? t : t.substr(0, dot);
                std::string fracPart = dot == std::string::npos ? "" : t.substr(dot + 1);
                if (intPart.empty()) intPart = "0";
                if (fracPart.size() > 8) return false;
                for (char c : intPart) if (c < '0' || c > '9') return false;
                for (char c : fracPart) if (c < '0' || c > '9') return false;
                unsigned __int128 iv = 0;
                for (char c : intPart) iv = iv * 10 + static_cast<unsigned>(c - '0');
                unsigned __int128 fv = 0;
                for (char c : fracPart) fv = fv * 10 + static_cast<unsigned>(c - '0');
                for (size_t i = fracPart.size(); i < 8; ++i) fv *= 10;
                unsigned __int128 total = iv * 100000000ULL + fv;
                if (total > std::numeric_limits<uint64_t>::max()) return false;
                out = static_cast<uint64_t>(total);
                return true;
            };

            uint64_t budgetAtoms = 0;
            uint32_t iters = 20;
            for (size_t i = 2; i < config.commandArgs.size(); ++i) {
                if (config.commandArgs[i] == "--budget" && i + 1 < config.commandArgs.size()) {
                    uint64_t v = 0;
                    if (!parseNgtAtomic(config.commandArgs[i + 1], v)) {
                        std::cerr << "Invalid --budget\n";
                        return 1;
                    }
                    budgetAtoms = v;
                    i++;
                } else if (config.commandArgs[i] == "--iters" && i + 1 < config.commandArgs.size()) {
                    iters = static_cast<uint32_t>(std::max(1, std::stoi(config.commandArgs[i + 1])));
                    i++;
                }
            }

            json params;
            if (budgetAtoms > 0) params["budget_atoms"] = budgetAtoms;
            params["iters"] = iters;
            json out;
            std::string err;
            if (!call("poe.epoch", params, out, err)) {
                if (isRpcTransportError(err)) return std::nullopt;
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            std::cout << "epochId=" << out.value("epochId", 0) << "\n";
            std::cout << "allocationHash=" << out.value("allocationHash", "") << "\n";
            std::cout << "minted=" << std::fixed << std::setprecision(8) << out.value("minted", 0.0) << " NGT\n";
            std::cout << "mintedEntries=" << out.value("mintedEntries", 0) << "\n";
            double you = out.value("youEarned", 0.0);
            if (you > 0.0) {
                std::cout << "youEarned=" << std::fixed << std::setprecision(8) << you << " NGT\n";
            }
            return 0;
        }

        if (sub == "export") {
            if (config.commandArgs.size() < 3) {
                std::cerr << "Usage: synapsed poe export <path>\n";
                return 1;
            }
            json params;
            params["path"] = config.commandArgs[2];
            json out;
            std::string err;
            if (!call("poe.export", params, out, err)) {
                if (isRpcTransportError(err)) return std::nullopt;
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            std::cout << out.dump() << "\n";
            return 0;
        }

        if (sub == "import") {
            if (config.commandArgs.size() < 3) {
                std::cerr << "Usage: synapsed poe import <path>\n";
                return 1;
            }
            json params;
            params["path"] = config.commandArgs[2];
            json out;
            std::string err;
            if (!call("poe.import", params, out, err)) {
                if (isRpcTransportError(err)) return std::nullopt;
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            std::cout << out.dump() << "\n";
            return 0;
        }

	        std::cerr << "Unknown poe subcommand: " << sub << "\n";
	        return 1;
	    }

	    if (cmd == "model") {
	        if (config.commandArgs.size() == 1 || config.commandArgs[1] == "help") {
	            std::cout << "Usage:\n";
	            std::cout << "  synapsed model status\n";
	            std::cout << "  synapsed model list [--dir PATH]\n";
	            std::cout << "  synapsed model load (--path PATH | --name FILENAME)\n";
	            std::cout << "    [--context N] [--threads N] [--gpu-layers N] [--use-gpu 0|1] [--mmap 0|1]\n";
	            std::cout << "  synapsed model unload\n";
                std::cout << "  synapsed model access get\n";
                std::cout << "  synapsed model access set --mode (PRIVATE|SHARED|PAID|COMMUNITY) [--max-slots N]\n";
                std::cout << "    [--price-per-hour-atoms N] [--price-per-request-atoms N]\n";
                std::cout << "  synapsed model remote list\n";
                std::cout << "  synapsed model remote rent --offer OFFER_ID\n";
                std::cout << "  synapsed model remote end --session SESSION_ID\n";
	            return 0;
	        }

	        const std::string sub = config.commandArgs[1];

	        if (sub == "status") {
	            json out;
	            std::string err;
	            if (!call("model.status", json::object(), out, err)) {
	                if (isRpcTransportError(err)) return std::nullopt;
	                std::cerr << "RPC failed: " << err << "\n";
	                return 1;
	            }
	            std::cout << out.dump(2) << "\n";
	            return 0;
	        }

		        if (sub == "list") {
		            json params = json::object();
		            for (size_t i = 2; i < config.commandArgs.size(); ++i) {
		                if (config.commandArgs[i] == "--dir" && i + 1 < config.commandArgs.size()) {
		                    params["dir"] = config.commandArgs[i + 1];
		                    i++;
		                }
	            }
	            json out;
	            std::string err;
	            if (!call("model.list", params, out, err)) {
	                if (isRpcTransportError(err)) return std::nullopt;
	                std::cerr << "RPC failed: " << err << "\n";
	                return 1;
	            }
	            std::cout << out.dump(2) << "\n";
	            return 0;
	        }

		        if (sub == "load") {
		            json params = json::object();
		            for (size_t i = 2; i < config.commandArgs.size(); ++i) {
		                if (config.commandArgs[i] == "--path" && i + 1 < config.commandArgs.size()) {
		                    params["path"] = config.commandArgs[i + 1];
		                    i++;
	                } else if (config.commandArgs[i] == "--name" && i + 1 < config.commandArgs.size()) {
	                    params["name"] = config.commandArgs[i + 1];
	                    i++;
	                } else if (config.commandArgs[i] == "--context" && i + 1 < config.commandArgs.size()) {
	                    params["contextSize"] = std::stoi(config.commandArgs[i + 1]);
	                    i++;
	                } else if (config.commandArgs[i] == "--threads" && i + 1 < config.commandArgs.size()) {
	                    params["threads"] = std::stoi(config.commandArgs[i + 1]);
	                    i++;
	                } else if (config.commandArgs[i] == "--gpu-layers" && i + 1 < config.commandArgs.size()) {
	                    params["gpuLayers"] = std::stoi(config.commandArgs[i + 1]);
	                    i++;
	                } else if (config.commandArgs[i] == "--use-gpu" && i + 1 < config.commandArgs.size()) {
	                    params["useGpu"] = (std::stoi(config.commandArgs[i + 1]) != 0);
	                    i++;
	                } else if (config.commandArgs[i] == "--mmap" && i + 1 < config.commandArgs.size()) {
	                    params["useMmap"] = (std::stoi(config.commandArgs[i + 1]) != 0);
	                    i++;
	                }
	            }
	            json out;
	            std::string err;
	            if (!call("model.load", params, out, err)) {
	                if (isRpcTransportError(err)) return std::nullopt;
	                std::cerr << "RPC failed: " << err << "\n";
	                return 1;
	            }
	            std::cout << out.dump(2) << "\n";
	            return out.value("ok", false) ? 0 : 1;
	        }

	        if (sub == "unload") {
	            json out;
	            std::string err;
	            if (!call("model.unload", json::object(), out, err)) {
	                if (isRpcTransportError(err)) return std::nullopt;
	                std::cerr << "RPC failed: " << err << "\n";
	                return 1;
	            }
	            std::cout << out.dump(2) << "\n";
	            return out.value("ok", false) ? 0 : 1;
	        }

            // Convenience shortcuts (align with interface spec).
            if (sub == "private" || sub == "shared" || sub == "paid" || sub == "community") {
                json params = json::object();
                params["mode"] = sub;
                json out;
                std::string err;
                if (!call("model.access.set", params, out, err)) {
                    if (isRpcTransportError(err)) return std::nullopt;
                    std::cerr << "RPC failed: " << err << "\n";
                    return 1;
                }
                std::cout << out.dump(2) << "\n";
                return 0;
            }

            if (sub == "price") {
                if (config.commandArgs.size() < 3) {
                    std::cerr << "Usage: synapsed model price <pricePerHourAtoms>\n";
                    return 1;
                }
                json params = json::object();
                params["pricePerHourAtoms"] = std::stoll(config.commandArgs[2]);
                json out;
                std::string err;
                if (!call("model.access.set", params, out, err)) {
                    if (isRpcTransportError(err)) return std::nullopt;
                    std::cerr << "RPC failed: " << err << "\n";
                    return 1;
                }
                std::cout << out.dump(2) << "\n";
                return 0;
            }

            if (sub == "slots") {
                if (config.commandArgs.size() < 3) {
                    std::cerr << "Usage: synapsed model slots <maxSlots>\n";
                    return 1;
                }
                json params = json::object();
                params["maxSlots"] = std::stoll(config.commandArgs[2]);
                json out;
                std::string err;
                if (!call("model.access.set", params, out, err)) {
                    if (isRpcTransportError(err)) return std::nullopt;
                    std::cerr << "RPC failed: " << err << "\n";
                    return 1;
                }
                std::cout << out.dump(2) << "\n";
                return 0;
            }

            if (sub == "access") {
                const std::string sub2 = (config.commandArgs.size() >= 3) ? config.commandArgs[2] : "help";
                if (sub2 == "get") {
                    json out;
                    std::string err;
                    if (!call("model.access.get", json::object(), out, err)) {
                        if (isRpcTransportError(err)) return std::nullopt;
                        std::cerr << "RPC failed: " << err << "\n";
                        return 1;
                    }
                    std::cout << out.dump(2) << "\n";
                    return 0;
                }
                if (sub2 == "set") {
                    json params = json::object();
                    for (size_t i = 3; i < config.commandArgs.size(); ++i) {
                        if (config.commandArgs[i] == "--mode" && i + 1 < config.commandArgs.size()) {
                            params["mode"] = config.commandArgs[i + 1];
                            i++;
                        } else if (config.commandArgs[i] == "--max-slots" && i + 1 < config.commandArgs.size()) {
                            params["maxSlots"] = std::stoll(config.commandArgs[i + 1]);
                            i++;
                        } else if (config.commandArgs[i] == "--price-per-hour-atoms" && i + 1 < config.commandArgs.size()) {
                            params["pricePerHourAtoms"] = std::stoll(config.commandArgs[i + 1]);
                            i++;
                        } else if (config.commandArgs[i] == "--price-per-request-atoms" && i + 1 < config.commandArgs.size()) {
                            params["remotePricePerRequestAtoms"] = std::stoll(config.commandArgs[i + 1]);
                            i++;
                        }
                    }
                    json out;
                    std::string err;
                    if (!call("model.access.set", params, out, err)) {
                        if (isRpcTransportError(err)) return std::nullopt;
                        std::cerr << "RPC failed: " << err << "\n";
                        return 1;
                    }
                    std::cout << out.dump(2) << "\n";
                    return 0;
                }
                std::cerr << "Usage: synapsed model access get|set ...\n";
                return 1;
            }

            if (sub == "remote") {
                const std::string sub2 = (config.commandArgs.size() >= 3) ? config.commandArgs[2] : "help";
                if (sub2 == "list") {
                    json out;
                    std::string err;
                    if (!call("model.remote.list", json::object(), out, err)) {
                        if (isRpcTransportError(err)) return std::nullopt;
                        std::cerr << "RPC failed: " << err << "\n";
                        return 1;
                    }
                    std::cout << out.dump(2) << "\n";
                    return 0;
                }
                if (sub2 == "rent") {
                    json params = json::object();
                    for (size_t i = 3; i < config.commandArgs.size(); ++i) {
                        if (config.commandArgs[i] == "--offer" && i + 1 < config.commandArgs.size()) {
                            params["offerId"] = config.commandArgs[i + 1];
                            i++;
                        }
                    }
                    if (!params.contains("offerId")) {
                        std::cerr << "Usage: synapsed model remote rent --offer OFFER_ID\n";
                        return 1;
                    }
                    json out;
                    std::string err;
                    if (!call("model.remote.rent", params, out, err)) {
                        if (isRpcTransportError(err)) return std::nullopt;
                        std::cerr << "RPC failed: " << err << "\n";
                        return 1;
                    }
                    std::cout << out.dump(2) << "\n";
                    return 0;
                }
                if (sub2 == "end") {
                    json params = json::object();
                    for (size_t i = 3; i < config.commandArgs.size(); ++i) {
                        if (config.commandArgs[i] == "--session" && i + 1 < config.commandArgs.size()) {
                            params["sessionId"] = config.commandArgs[i + 1];
                            i++;
                        }
                    }
                    if (!params.contains("sessionId")) {
                        std::cerr << "Usage: synapsed model remote end --session SESSION_ID\n";
                        return 1;
                    }
                    json out;
                    std::string err;
                    if (!call("model.remote.end", params, out, err)) {
                        if (isRpcTransportError(err)) return std::nullopt;
                        std::cerr << "RPC failed: " << err << "\n";
                        return 1;
                    }
                    std::cout << out.dump(2) << "\n";
                    return 0;
                }
                std::cerr << "Usage: synapsed model remote list|rent|end ...\n";
                return 1;
            }

            if (sub == "market") {
                const std::string sub2 = (config.commandArgs.size() >= 3) ? config.commandArgs[2] : "help";
                if (sub2 == "listings") {
                    json params = json::object();
                    for (size_t i = 3; i < config.commandArgs.size(); ++i) {
                        if (config.commandArgs[i] == "--all") {
                            params["includeInactive"] = true;
                        }
                    }
                    json out;
                    std::string err;
                    if (!call("market.listings", params, out, err)) {
                        if (isRpcTransportError(err)) return std::nullopt;
                        std::cerr << "RPC failed: " << err << "\n";
                        return 1;
                    }
                    std::cout << out.dump(2) << "\n";
                    return 0;
                }
                if (sub2 == "stats") {
                    json out;
                    std::string err;
                    if (!call("market.stats", json::object(), out, err)) {
                        if (isRpcTransportError(err)) return std::nullopt;
                        std::cerr << "RPC failed: " << err << "\n";
                        return 1;
                    }
                    std::cout << out.dump(2) << "\n";
                    return 0;
                }
                std::cerr << "Usage: synapsed model market listings [--all] | stats\n";
                return 1;
            }

	        std::cerr << "Unknown model subcommand: " << sub << "\n";
	        return 1;
	    }

	    if (cmd == "ai") {
	        if (config.commandArgs.size() == 1 || config.commandArgs[1] == "help") {
	            std::cout << "Usage:\n";
	            std::cout << "  synapsed ai complete --prompt TEXT [--max-tokens N] [--temperature X] [--remote-session SESSION_ID]\n";
	            std::cout << "  synapsed ai stop\n";
	            return 0;
	        }

	        const std::string sub = config.commandArgs[1];

	        if (sub == "stop") {
	            json out;
	            std::string err;
	            if (!call("ai.stop", json::object(), out, err)) {
	                if (isRpcTransportError(err)) return std::nullopt;
	                std::cerr << "RPC failed: " << err << "\n";
	                return 1;
	            }
	            std::cout << out.dump(2) << "\n";
	            return 0;
	        }

	        if (sub == "complete") {
	            json params;
	            for (size_t i = 2; i < config.commandArgs.size(); ++i) {
	                if (config.commandArgs[i] == "--prompt" && i + 1 < config.commandArgs.size()) {
	                    params["prompt"] = config.commandArgs[i + 1];
	                    i++;
	                } else if (config.commandArgs[i] == "--max-tokens" && i + 1 < config.commandArgs.size()) {
	                    params["maxTokens"] = std::stoi(config.commandArgs[i + 1]);
	                    i++;
	                } else if (config.commandArgs[i] == "--temperature" && i + 1 < config.commandArgs.size()) {
	                    params["temperature"] = std::stod(config.commandArgs[i + 1]);
	                    i++;
                    } else if (config.commandArgs[i] == "--remote-session" && i + 1 < config.commandArgs.size()) {
                        params["remote"] = true;
                        params["remoteSessionId"] = config.commandArgs[i + 1];
                        i++;
	                }
	            }
	            json out;
	            std::string err;
	            if (!call("ai.complete", params, out, err)) {
	                if (isRpcTransportError(err)) return std::nullopt;
	                std::cerr << "RPC failed: " << err << "\n";
	                return 1;
	            }
	            std::cout << out.dump(2) << "\n";
	            return 0;
	        }

	        std::cerr << "Unknown ai subcommand: " << sub << "\n";
	        return 1;
	    }

	    if (cmd == "status" || cmd == "peers" || cmd == "logs") {
	        json out;
	        std::string err;
	        if (!call("node." + cmd, json::object(), out, err)) {
            std::cerr << "RPC failed: " << err << "\n";
            return 1;
        }
        std::cout << out.dump(2) << "\n";
        return 0;
    }

        if (cmd == "seeds") {
            json out;
            std::string err;
            if (!call("node.seeds", json::object(), out, err)) {
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            std::cout << out.dump(2) << "\n";
            return 0;
        }

        if (cmd == "discovery") {
            json out;
            std::string err;
            if (!call("node.discovery.stats", json::object(), out, err)) {
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            std::cout << out.dump(2) << "\n";
            return 0;
        }

    std::cerr << "Unknown command: " << cmd << "\n";
    return 1;
}

bool parseArgs(int argc, char* argv[], NodeConfig& config) {
    static struct option longOptions[] = {
        {"help", no_argument, nullptr, 'h'},
        {"version", no_argument, nullptr, 'v'},
        {"daemon", no_argument, nullptr, 'd'},
        {"config", required_argument, nullptr, 'c'},
        {"datadir", required_argument, nullptr, 'D'},
        {"port", required_argument, nullptr, 'p'},
        {"rpcport", required_argument, nullptr, 'r'},
        {"testnet", no_argument, nullptr, 't'},
        {"regtest", no_argument, nullptr, 'R'},
        {"privacy", no_argument, nullptr, 'P'},
        {"amnesia", no_argument, nullptr, 'A'},
        {"dev", no_argument, nullptr, 'E'},
        {"reset-ngt", no_argument, nullptr, 'Z'},
        {"poe-validators", required_argument, nullptr, 'V'},
        {"poe-validator-mode", required_argument, nullptr, 'M'},
        {"poe-min-stake", required_argument, nullptr, 'T'},
        {"quantum", no_argument, nullptr, 'Q'},
        {"security", required_argument, nullptr, 'S'},
        {"connect", required_argument, nullptr, 'C'},
        {"addnode", required_argument, nullptr, 'N'},
        {"seednode", required_argument, nullptr, 's'},
        {"maxpeers", required_argument, nullptr, 'm'},
        {"dbcache", required_argument, nullptr, 'b'},
        {"loglevel", required_argument, nullptr, 'l'},
        {nullptr, 0, nullptr, 0}
    };
    
    int opt;
    int optionIndex = 0;
    
	    while ((opt = getopt_long(argc, argv, "+hvdc:D:p:r:tRPAEZV:M:T:QS:C:N:s:m:b:l:", 
	                              longOptions, &optionIndex)) != -1) {
        switch (opt) {
            case 'h':
                config.showHelp = true;
                return true;
            case 'v':
                config.showVersion = true;
                return true;
            case 'd':
                config.daemon = true;
                config.tui = false;
                break;
            case 'c':
                config.configPath = optarg;
                break;
            case 'D':
                config.dataDir = optarg;
                break;
            case 'p':
                config.port = std::stoi(optarg);
                break;
            case 'r':
                config.rpcPort = std::stoi(optarg);
                break;
            case 't':
                config.testnet = true;
                config.networkType = "testnet";
                break;
            case 'R':
                config.regtest = true;
                config.networkType = "regtest";
                config.discovery = false;
                break;
            case 'P':
                config.privacyMode = true;
                break;
            case 'A':
                config.amnesia = true;
                break;
            case 'E':
                config.dev = true;
                config.networkType = "dev";
                break;
            case 'Z':
                config.resetNgt = true;
                break;
            case 'V':
                config.poeValidators = optarg;
                break;
            case 'M':
                config.poeValidatorMode = optarg;
                break;
            case 'T':
                config.poeMinStake = optarg;
                break;
            case 'Q':
                config.quantumSecurity = true;
                break;
            case 'S':
                config.securityLevel = optarg;
                break;
            case 'C':
                config.connectNodes.push_back(optarg);
                break;
            case 'N':
                config.addNodes.push_back(optarg);
                break;
            case 's':
                config.seedNodes.push_back(optarg);
                break;
            case 'm':
                config.maxPeers = std::stoi(optarg);
                break;
            case 'b':
                config.dbCacheSize = std::stoi(optarg);
                break;
            case 'l':
                config.logLevel = optarg;
                break;
            default:
                return false;
        }
    }
    
	    if (optind < argc) {
	        std::string command = argv[optind];
	        if (command == "poe" || command == "status" || command == "peers" ||
	            command == "balance" || command == "address" || command == "logs" ||
	            command == "model" || command == "ai") {
	            config.cli = true;
	            config.tui = false;
	            config.daemon = false;
	            config.commandArgs.clear();
            for (int i = optind; i < argc; ++i) {
                config.commandArgs.emplace_back(argv[i]);
            }
            return true;
        }
    }
	    
	    return true;
}

void ensureDirectories(const NodeConfig& config) {
    std::filesystem::create_directories(config.dataDir);
    std::filesystem::create_directories(config.dataDir + "/blocks");
    std::filesystem::create_directories(config.dataDir + "/chaindata");
    std::filesystem::create_directories(config.dataDir + "/wallet");
    std::filesystem::create_directories(config.dataDir + "/models");
    std::filesystem::create_directories(config.dataDir + "/logs");
    std::filesystem::create_directories(config.dataDir + "/ledger");
    std::filesystem::create_directories(config.dataDir + "/knowledge");
    std::filesystem::create_directories(config.dataDir + "/transfer");
    std::filesystem::create_directories(config.dataDir + "/consensus");
}

std::string formatBytes(uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double size = static_cast<double>(bytes);
    
    while (size >= 1024 && unit < 4) {
        size /= 1024;
        unit++;
    }
    
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << size << " " << units[unit];
    return oss.str();
}

std::string formatUptime(uint64_t seconds) {
    uint64_t days = seconds / 86400;
    uint64_t hours = (seconds % 86400) / 3600;
    uint64_t mins = (seconds % 3600) / 60;
    uint64_t secs = seconds % 60;
    
    std::ostringstream oss;
    if (days > 0) oss << days << "d ";
    if (hours > 0 || days > 0) oss << hours << "h ";
    if (mins > 0 || hours > 0 || days > 0) oss << mins << "m ";
    oss << secs << "s";
    return oss.str();
}

bool checkDiskSpace(const std::string& path, uint64_t requiredBytes) {
    struct statvfs stat;
    if (statvfs(path.c_str(), &stat) != 0) {
        return false;
    }
    uint64_t available = stat.f_bavail * stat.f_frsize;
    return available >= requiredBytes;
}

bool checkSystemRequirements() {
    uint32_t cores = std::thread::hardware_concurrency();
    if (cores < 2) {
        std::cerr << "Warning: System has only " << cores << " CPU core(s)\n";
    }
    return true;
}

void registerSignalHandlers() {
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
#ifndef _WIN32
    std::signal(SIGHUP, signalHandler);
    std::signal(SIGPIPE, SIG_IGN);
#endif
}

void daemonize() {
#ifndef _WIN32
    pid_t pid = fork();
    if (pid < 0) {
        std::cerr << "Failed to fork daemon process\n";
        exit(1);
    }
    if (pid > 0) {
        exit(0);
    }
    
    if (setsid() < 0) {
        exit(1);
    }
    
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    int nullfd = ::open("/dev/null", O_RDWR);
    if (nullfd >= 0) {
        ::dup2(nullfd, STDIN_FILENO);
        ::dup2(nullfd, STDOUT_FILENO);
        ::dup2(nullfd, STDERR_FILENO);
        if (nullfd > STDERR_FILENO) ::close(nullfd);
    }
#endif
}

}

int main(int argc, char* argv[]) {
    synapse::registerSignalHandlers();
    
    synapse::NodeConfig config;
    
    const char* home = std::getenv("HOME");
    config.dataDir = home ? std::string(home) + "/.synapsenet" : ".synapsenet";
    
    if (!synapse::parseArgs(argc, argv, config)) {
        return 1;
    }

    synapse::g_daemonMode = config.daemon;
    
    if (config.showHelp) {
        synapse::printHelp(argv[0]);
        return 0;
    }
    
    if (config.showVersion) {
        synapse::printVersion();
        return 0;
    }
    
    if (!config.daemon && !config.tui && !config.cli) {
        synapse::printBanner();
    }
    
    if (!synapse::checkSystemRequirements()) {
        return 1;
    }
    
    synapse::ensureDirectories(config);
    
    if (!synapse::checkDiskSpace(config.dataDir, 1024 * 1024 * 100)) {
        std::cerr << "Warning: Low disk space in " << config.dataDir << "\n";
    }
    
    if (config.daemon) {
        synapse::daemonize();
    }

    if (config.cli) {
        auto rc = synapse::runCliViaRpc(config);
        if (rc.has_value()) {
            return *rc;
        }
    }

    std::string instanceErr;
    auto instanceLock = synapse::utils::SingleInstanceLock::acquire(config.dataDir, &instanceErr);
    if (!instanceLock) {
        std::cerr << "SynapseNet: " << instanceErr << "\n";
        return 1;
    }
    
    synapse::SynapseNet node;
    synapse::g_node = &node;
    
    if (!node.initialize(config)) {
        std::cerr << "Failed to initialize node\n";
        return 1;
    }

    int result = 0;
    if (config.cli) {
        result = node.runCommand(config.commandArgs);
    } else {
        result = node.run();
    }
    
    node.shutdown();
    synapse::g_node = nullptr;
    
    return result;
}
