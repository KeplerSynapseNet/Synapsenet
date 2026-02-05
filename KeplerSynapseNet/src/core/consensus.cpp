#include "core/consensus.h"
#include "database/database.h"
#include <unordered_map>
#include <mutex>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <random>
#include <cmath>
#include <fstream>

namespace synapse {
namespace core {

static void writeU64(std::vector<uint8_t>& out, uint64_t val) {
    for (int i = 0; i < 8; i++) out.push_back((val >> (i * 8)) & 0xff);
}

static uint64_t readU64(const uint8_t* p) {
    uint64_t val = 0;
    for (int i = 0; i < 8; i++) val |= static_cast<uint64_t>(p[i]) << (i * 8);
    return val;
}

static void writeU32(std::vector<uint8_t>& out, uint32_t val) {
    for (int i = 0; i < 4; i++) out.push_back((val >> (i * 8)) & 0xff);
}

static uint32_t readU32(const uint8_t* p) {
    uint32_t val = 0;
    for (int i = 0; i < 4; i++) val |= static_cast<uint32_t>(p[i]) << (i * 8);
    return val;
}

std::vector<uint8_t> Vote::serialize() const {
    std::vector<uint8_t> out;
    writeU64(out, eventId);
    out.insert(out.end(), validator.begin(), validator.end());
    out.push_back(static_cast<uint8_t>(type));
    uint64_t scoreBits;
    std::memcpy(&scoreBits, &scoreGiven, sizeof(double));
    writeU64(out, scoreBits);
    writeU64(out, timestamp);
    out.insert(out.end(), signature.begin(), signature.end());
    return out;
}

Vote Vote::deserialize(const std::vector<uint8_t>& data) {
    Vote v;
    if (data.size() < 8 + 33 + 1 + 8 + 8 + 64) return v;
    const uint8_t* p = data.data();
    v.eventId = readU64(p); p += 8;
    std::memcpy(v.validator.data(), p, 33); p += 33;
    v.type = static_cast<VoteType>(*p++);
    uint64_t scoreBits = readU64(p); p += 8;
    std::memcpy(&v.scoreGiven, &scoreBits, sizeof(double));
    v.timestamp = readU64(p); p += 8;
    std::memcpy(v.signature.data(), p, 64);
    return v;
}

crypto::Hash256 Vote::computeHash() const {
    std::vector<uint8_t> buf;
    writeU64(buf, eventId);
    buf.insert(buf.end(), validator.begin(), validator.end());
    buf.push_back(static_cast<uint8_t>(type));
    uint64_t scoreBits;
    std::memcpy(&scoreBits, &scoreGiven, sizeof(double));
    writeU64(buf, scoreBits);
    writeU64(buf, timestamp);
    return crypto::doubleSha256(buf.data(), buf.size());
}

bool Vote::verify() const {
    crypto::Hash256 hash = computeHash();
    return crypto::verify(hash, signature, validator);
}

struct Consensus::Impl {
    database::Database db;
    std::unordered_map<uint64_t, ValidationResult> results;
    std::unordered_map<std::string, Validator> validators;
    ConsensusConfig config;
    mutable std::mutex mtx;
    std::function<void(uint64_t, ConsensusState)> stateCallback;
    std::function<void(const ValidationResult&)> completeCallback;
    uint64_t validationCounter = 0;
};

Consensus::Consensus() : impl_(std::make_unique<Impl>()) {}
Consensus::~Consensus() { close(); }

bool Consensus::open(const std::string& dbPath) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (!impl_->db.open(dbPath)) return false;
    
    auto counterData = impl_->db.get("meta:validationCounter");
    if (!counterData.empty()) {
        impl_->validationCounter = readU64(counterData.data());
    }
    return true;
}

void Consensus::close() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->db.close();
}

void Consensus::setConfig(const ConsensusConfig& config) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->config = config;
}

uint64_t Consensus::submitForValidation(uint64_t eventId, const crypto::PublicKey& submitter) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    ValidationResult result;
    result.eventId = eventId;
    result.state = ConsensusState::PENDING;
    result.approveVotes = 0;
    result.rejectVotes = 0;
    result.totalVotes = 0;
    result.requiredVotes = impl_->config.minValidators;
    result.averageScore = 0.0;
    result.startTime = std::time(nullptr);
    result.endTime = 0;
    result.reward = 0.0;
    
    impl_->results[eventId] = result;
    impl_->validationCounter++;
    
    std::vector<uint8_t> counterBuf;
    writeU64(counterBuf, impl_->validationCounter);
    impl_->db.put("meta:validationCounter", counterBuf);
    
    if (impl_->stateCallback) {
        impl_->stateCallback(eventId, ConsensusState::PENDING);
    }
    
    return eventId;
}

bool Consensus::vote(const Vote& vote) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    auto it = impl_->results.find(vote.eventId);
    if (it == impl_->results.end()) return false;
    
    if (it->second.state != ConsensusState::PENDING && 
        it->second.state != ConsensusState::VALIDATING) {
        return false;
    }
    
    if (!vote.verify()) return false;
    
    std::string validatorAddr = crypto::toHex(vote.validator);
    auto valIt = impl_->validators.find(validatorAddr);
    if (valIt == impl_->validators.end() || !valIt->second.eligible) {
        return false;
    }
    
    for (const auto& v : it->second.votes) {
        if (v.validator == vote.validator) return false;
    }
    
    it->second.votes.push_back(vote);
    it->second.totalVotes++;
    
    if (vote.type == VoteType::APPROVE) {
        it->second.approveVotes++;
        double totalScore = it->second.averageScore * (it->second.totalVotes - 1) + vote.scoreGiven;
        it->second.averageScore = totalScore / it->second.totalVotes;
    } else if (vote.type == VoteType::REJECT) {
        it->second.rejectVotes++;
    }
    
    if (it->second.state == ConsensusState::PENDING) {
        it->second.state = ConsensusState::VALIDATING;
        if (impl_->stateCallback) {
            impl_->stateCallback(vote.eventId, ConsensusState::VALIDATING);
        }
    }
    
    valIt->second.validationsCompleted++;
    valIt->second.lastActive = std::time(nullptr);
    
    if (it->second.totalVotes >= it->second.requiredVotes) {
        finalizeValidation(vote.eventId);
    }
    
    return true;
}

bool Consensus::finalizeValidation(uint64_t eventId) {
    auto it = impl_->results.find(eventId);
    if (it == impl_->results.end()) return false;
    
    ValidationResult& result = it->second;
    result.endTime = std::time(nullptr);
    
    double approveRatio = static_cast<double>(result.approveVotes) / result.totalVotes;
    
    if (approveRatio >= impl_->config.majorityThreshold) {
        result.state = ConsensusState::ACCEPTED;
        result.reward = calculateReward(result);
        
        for (const auto& vote : result.votes) {
            if (vote.type == VoteType::APPROVE) {
                std::string addr = crypto::toHex(vote.validator);
                auto valIt = impl_->validators.find(addr);
                if (valIt != impl_->validators.end()) {
                    valIt->second.reputation = std::min(1.0, valIt->second.reputation + 0.01);
                }
            }
        }
    } else {
        result.state = ConsensusState::REJECTED;
        
        for (const auto& vote : result.votes) {
            if (vote.type == VoteType::REJECT) {
                std::string addr = crypto::toHex(vote.validator);
                auto valIt = impl_->validators.find(addr);
                if (valIt != impl_->validators.end()) {
                    valIt->second.reputation = std::min(1.0, valIt->second.reputation + 0.01);
                }
            }
        }
    }
    
    if (impl_->stateCallback) {
        impl_->stateCallback(eventId, result.state);
    }
    
    if (impl_->completeCallback) {
        impl_->completeCallback(result);
    }
    
    return true;
}

ConsensusState Consensus::getState(uint64_t eventId) const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    auto it = impl_->results.find(eventId);
    return it != impl_->results.end() ? it->second.state : ConsensusState::PENDING;
}

ValidationResult Consensus::getResult(uint64_t eventId) const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    auto it = impl_->results.find(eventId);
    return it != impl_->results.end() ? it->second : ValidationResult{};
}

std::vector<uint64_t> Consensus::getPending() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    std::vector<uint64_t> pending;
    for (const auto& [id, result] : impl_->results) {
        if (result.state == ConsensusState::PENDING) {
            pending.push_back(id);
        }
    }
    return pending;
}

std::vector<uint64_t> Consensus::getValidating() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    std::vector<uint64_t> validating;
    for (const auto& [id, result] : impl_->results) {
        if (result.state == ConsensusState::VALIDATING) {
            validating.push_back(id);
        }
    }
    return validating;
}

std::vector<Vote> Consensus::getVotesFor(uint64_t eventId) const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    auto it = impl_->results.find(eventId);
    return it != impl_->results.end() ? it->second.votes : std::vector<Vote>{};
}

bool Consensus::registerValidator(const Validator& validator) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    if (validator.stake < impl_->config.minStake) return false;
    if (validator.reputation < impl_->config.minReputation) return false;
    
    std::string addr = crypto::toHex(validator.pubKey);
    impl_->validators[addr] = validator;
    impl_->validators[addr].eligible = true;
    
    return true;
}

bool Consensus::updateValidatorStake(const crypto::PublicKey& pubKey, uint64_t newStake) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    std::string addr = crypto::toHex(pubKey);
    auto it = impl_->validators.find(addr);
    if (it == impl_->validators.end()) return false;
    
    it->second.stake = newStake;
    it->second.eligible = (newStake >= impl_->config.minStake && 
                           it->second.reputation >= impl_->config.minReputation);
    return true;
}

bool Consensus::updateValidatorReputation(const crypto::PublicKey& pubKey, double delta) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    std::string addr = crypto::toHex(pubKey);
    auto it = impl_->validators.find(addr);
    if (it == impl_->validators.end()) return false;
    
    it->second.reputation = std::max(0.0, std::min(1.0, it->second.reputation + delta));
    it->second.eligible = (it->second.stake >= impl_->config.minStake && 
                           it->second.reputation >= impl_->config.minReputation);
    return true;
}

Validator Consensus::getValidator(const crypto::PublicKey& pubKey) const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    std::string addr = crypto::toHex(pubKey);
    auto it = impl_->validators.find(addr);
    return it != impl_->validators.end() ? it->second : Validator{};
}

std::vector<Validator> Consensus::getEligibleValidators() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    std::vector<Validator> eligible;
    for (const auto& [addr, val] : impl_->validators) {
        if (val.eligible) eligible.push_back(val);
    }
    return eligible;
}

std::vector<Validator> Consensus::selectValidators(uint64_t eventId, uint32_t count) const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    std::vector<Validator> eligible;
    for (const auto& [addr, val] : impl_->validators) {
        if (val.eligible) eligible.push_back(val);
    }
    
    if (eligible.size() <= count) return eligible;
    
    std::seed_seq seed{static_cast<uint32_t>(eventId), 
                       static_cast<uint32_t>(eventId >> 32)};
    std::mt19937 rng(seed);
    
    std::vector<double> weights;
    double totalWeight = 0;
    for (const auto& val : eligible) {
        double weight = std::sqrt(static_cast<double>(val.stake)) * val.reputation;
        weights.push_back(weight);
        totalWeight += weight;
    }
    
    std::vector<Validator> selected;
    std::vector<bool> used(eligible.size(), false);
    
    for (uint32_t i = 0; i < count && i < eligible.size(); i++) {
        double r = std::uniform_real_distribution<double>(0, totalWeight)(rng);
        double cumulative = 0;
        for (size_t j = 0; j < eligible.size(); j++) {
            if (used[j]) continue;
            cumulative += weights[j];
            if (r <= cumulative) {
                selected.push_back(eligible[j]);
                totalWeight -= weights[j];
                used[j] = true;
                break;
            }
        }
    }
    
    return selected;
}

bool Consensus::isEligibleValidator(const crypto::PublicKey& pubKey) const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    std::string addr = crypto::toHex(pubKey);
    auto it = impl_->validators.find(addr);
    return it != impl_->validators.end() && it->second.eligible;
}

double Consensus::calculateReward(const ValidationResult& result) const {
    double baseReward = 1.0;
    double scoreMultiplier = 1.0 + result.averageScore;
    double consensusBonus = result.approveVotes > result.rejectVotes ? 0.5 : 0.0;
    return baseReward * scoreMultiplier + consensusBonus;
}

double Consensus::calculatePenalty(const ValidationResult& result) const {
    if (result.state == ConsensusState::REJECTED) {
        return impl_->config.submissionStake;
    }
    return 0.0;
}

void Consensus::onStateChange(std::function<void(uint64_t, ConsensusState)> callback) {
    impl_->stateCallback = callback;
}

void Consensus::onValidationComplete(std::function<void(const ValidationResult&)> callback) {
    impl_->completeCallback = callback;
}

void Consensus::processTimeouts() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    uint64_t now = std::time(nullptr);
    
    for (auto& [id, result] : impl_->results) {
        if (result.state == ConsensusState::PENDING || 
            result.state == ConsensusState::VALIDATING) {
            if (now - result.startTime > impl_->config.validationTimeout) {
                result.state = ConsensusState::EXPIRED;
                result.endTime = now;
                if (impl_->stateCallback) {
                    impl_->stateCallback(id, ConsensusState::EXPIRED);
                }
            }
        }
    }
}

size_t Consensus::pendingCount() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    size_t count = 0;
    for (const auto& [id, result] : impl_->results) {
        if (result.state == ConsensusState::PENDING || 
            result.state == ConsensusState::VALIDATING) {
            count++;
        }
    }
    return count;
}

size_t Consensus::validatorCount() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->validators.size();
}

Consensus::ConsensusStats Consensus::getStats() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    Consensus::ConsensusStats stats{};
    stats.totalValidations = impl_->validationCounter;
    stats.pendingValidations = 0;
    stats.approvedValidations = 0;
    stats.rejectedValidations = 0;
    stats.totalValidators = impl_->validators.size();
    stats.activeValidators = 0;
    
    for (const auto& [id, result] : impl_->results) {
        if (result.state == ConsensusState::PENDING || 
            result.state == ConsensusState::VALIDATING) {
            stats.pendingValidations++;
        } else if (result.state == ConsensusState::APPROVED) {
            stats.approvedValidations++;
        } else if (result.state == ConsensusState::REJECTED) {
            stats.rejectedValidations++;
        }
    }
    
    uint64_t now = std::time(nullptr);
    for (const auto& [addr, val] : impl_->validators) {
        if (now - val.lastActive < 3600) stats.activeValidators++;
    }
    
    return stats;
}

std::vector<Validator> Consensus::getValidators() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    std::vector<Validator> result;
    for (const auto& [addr, val] : impl_->validators) {
        result.push_back(val);
    }
    return result;
}

std::vector<Validator> Consensus::getTopValidators(size_t count) const {
    auto validators = getValidators();
    std::sort(validators.begin(), validators.end(), 
              [](const Validator& a, const Validator& b) {
                  return a.stake > b.stake;
              });
    if (validators.size() > count) {
        validators.resize(count);
    }
    return validators;
}

ValidationResult Consensus::getValidationResult(uint64_t validationId) const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    auto it = impl_->results.find(validationId);
    if (it != impl_->results.end()) {
        return it->second;
    }
    return ValidationResult{};
}

std::vector<ValidationResult> Consensus::getRecentResults(size_t count) const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    std::vector<ValidationResult> results;
    
    std::vector<std::pair<uint64_t, ValidationResult>> sorted;
    for (const auto& [id, result] : impl_->results) {
        sorted.emplace_back(result.startTime, result);
    }
    std::sort(sorted.begin(), sorted.end(),
              [](const auto& a, const auto& b) { return a.first > b.first; });
    
    for (size_t i = 0; i < count && i < sorted.size(); i++) {
        results.push_back(sorted[i].second);
    }
    return results;
}

ConsensusConfig Consensus::getConfig() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->config;
}

uint64_t Consensus::getTotalStake() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    uint64_t total = 0;
    for (const auto& [addr, val] : impl_->validators) {
        total += val.stake;
    }
    return total;
}

double Consensus::getApprovalRate() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    size_t approved = 0, total = 0;
    for (const auto& [id, result] : impl_->results) {
        if (result.state == ConsensusState::APPROVED) approved++;
        if (result.state != ConsensusState::PENDING && 
            result.state != ConsensusState::VALIDATING) total++;
    }
    return total > 0 ? static_cast<double>(approved) / total : 0.0;
}

bool Consensus::slashValidator(const std::string& address, uint64_t amount) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    auto it = impl_->validators.find(address);
    if (it == impl_->validators.end()) return false;
    
    if (it->second.stake <= amount) {
        impl_->validators.erase(it);
    } else {
        it->second.stake -= amount;
    }
    return true;
}

bool Consensus::rewardValidator(const std::string& address, uint64_t amount) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    auto it = impl_->validators.find(address);
    if (it == impl_->validators.end()) return false;
    
    it->second.stake += amount;
    it->second.totalRewards += amount;
    return true;
}

std::vector<std::string> Consensus::getActiveValidatorAddresses() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    std::vector<std::string> result;
    uint64_t now = std::time(nullptr);
    
    for (const auto& [addr, val] : impl_->validators) {
        if (now - val.lastActive < 3600) {
            result.push_back(addr);
        }
    }
    return result;
}

uint64_t Consensus::getValidatorStake(const std::string& address) const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    auto it = impl_->validators.find(address);
    if (it == impl_->validators.end()) return 0;
    return it->second.stake;
}

void Consensus::setMinStake(uint64_t amount) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->config.minStake = amount;
}

void Consensus::setQuorum(double quorum) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->config.quorum = std::max(0.5, std::min(quorum, 1.0));
}

bool Consensus::exportValidators(const std::string& path) const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    std::ofstream f(path);
    if (!f.is_open()) return false;
    
    f << "[\n";
    bool first = true;
    for (const auto& [addr, val] : impl_->validators) {
        if (!first) f << ",\n";
        f << "  {\"address\": \"" << addr << "\", \"stake\": " << val.stake << "}";
        first = false;
    }
    f << "\n]";
    return true;
}

void Consensus::clearExpiredResults() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    uint64_t now = std::time(nullptr);
    
    for (auto it = impl_->results.begin(); it != impl_->results.end(); ) {
        if (it->second.state == ConsensusState::EXPIRED &&
            now - it->second.endTime > 86400) {
            it = impl_->results.erase(it);
        } else {
            ++it;
        }
    }
}

bool Consensus::isValidatorActive(const std::string& address) const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    auto it = impl_->validators.find(address);
    if (it == impl_->validators.end()) return false;
    
    uint64_t now = std::time(nullptr);
    return now - it->second.lastActive < 3600;
}

void Consensus::updateValidatorActivity(const std::string& address) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    auto it = impl_->validators.find(address);
    if (it != impl_->validators.end()) {
        it->second.lastActive = std::time(nullptr);
    }
}

std::string Consensus::selectProposer() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (impl_->validators.empty()) return "";
    
    uint64_t totalStake = 0;
    for (const auto& [addr, val] : impl_->validators) {
        totalStake += val.stake;
    }
    
    uint64_t random = rand() % totalStake;
    uint64_t cumulative = 0;
    
    for (const auto& [addr, val] : impl_->validators) {
        cumulative += val.stake;
        if (random < cumulative) return addr;
    }
    
    return impl_->validators.begin()->first;
}

void Consensus::setVotingTimeout(uint32_t seconds) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->config.votingTimeout = seconds;
}

bool Consensus::importValidators(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return false;
    return true;
}

void Consensus::setOnProposalCallback(std::function<void(const std::string&)> callback) {
}

void Consensus::setOnVoteCallback(std::function<void(const std::string&, bool)> callback) {
}

bool Consensus::proposeBlock(const Block& block, const std::string& proposer) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    auto it = impl_->validators.find(proposer);
    if (it == impl_->validators.end()) return false;
    return true;
}

bool Consensus::voteOnProposal(const std::string& proposalId, 
                                const std::string& validator, 
                                bool approve) {
    return true;
}

void Consensus::setOnValidatorJoined(std::function<void(const std::string&)> callback) {
}

void Consensus::setOnValidatorLeft(std::function<void(const std::string&)> callback) {
}

std::vector<std::string> Consensus::getActiveValidators() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    std::vector<std::string> result;
    for (const auto& [addr, val] : impl_->validators) {
        if (val.active) {
            result.push_back(addr);
        }
    }
    return result;
}

void Consensus::setBlockFinality(uint32_t blocks) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->config.blockFinality = blocks;
}

uint32_t Consensus::getBlockFinality() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->config.blockFinality;
}

bool Consensus::isBlockFinalized(uint64_t height) const {
    return true;
}

}
}
