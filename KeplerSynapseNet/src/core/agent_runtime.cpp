#include "core/agent_runtime.h"
#include <algorithm>
#include <limits>

namespace synapse::core {

namespace {

static int32_t clampI32(int32_t value, int32_t minValue, int32_t maxValue) {
    if (value < minValue) return minValue;
    if (value > maxValue) return maxValue;
    return value;
}

}

AgentRuntimeSandbox::AgentRuntimeSandbox() = default;

AgentRuntimeSandbox::AgentRuntimeSandbox(const SandboxPolicy& policy) : policy_(policy) {}

void AgentRuntimeSandbox::setPolicy(const SandboxPolicy& policy) {
    policy_ = policy;
}

SandboxPolicy AgentRuntimeSandbox::getPolicy() const {
    return policy_;
}

bool AgentRuntimeSandbox::isAllowed(AgentCapability capability) const {
    return std::find(policy_.allowlist.begin(), policy_.allowlist.end(), capability) != policy_.allowlist.end();
}

RuntimeActionResult AgentRuntimeSandbox::authorize(
    AgentCapability capability,
    bool hasSideEffects,
    bool explicitSideEffectFlag
) const {
    if (!isAllowed(capability)) return RuntimeActionResult::DENIED_CAPABILITY;
    if (!hasSideEffects) return RuntimeActionResult::ALLOWED;
    if (!policy_.allowSideEffects) return RuntimeActionResult::DENIED_SIDE_EFFECTS;
    if (!explicitSideEffectFlag) return RuntimeActionResult::DENIED_EXPLICIT_FLAG;
    return RuntimeActionResult::ALLOWED;
}

AgentScoreCard::AgentScoreCard(const AgentScoreConfig& cfg) : cfg_(cfg) {
    if (cfg_.minScore > cfg_.maxScore) std::swap(cfg_.minScore, cfg_.maxScore);
    cfg_.baseScore = clampI32(cfg_.baseScore, cfg_.minScore, cfg_.maxScore);
    cfg_.quarantineThreshold = clampI32(cfg_.quarantineThreshold, cfg_.minScore, cfg_.maxScore);
    if (cfg_.decayPerInterval < 0) cfg_.decayPerInterval = 0;
}

AgentScoreConfig AgentScoreCard::config() const {
    return cfg_;
}

int32_t AgentScoreCard::score() const {
    return clampI32(cfg_.baseScore - penaltyPoints_, cfg_.minScore, cfg_.maxScore);
}

int32_t AgentScoreCard::penalty() const {
    return penaltyPoints_;
}

bool AgentScoreCard::quarantined() const {
    return score() < cfg_.quarantineThreshold;
}

void AgentScoreCard::applyDecay(uint64_t nowTimestamp) {
    if (cfg_.decayIntervalSeconds == 0 || cfg_.decayPerInterval == 0) {
        if (lastDecayTs_ == 0) lastDecayTs_ = nowTimestamp;
        return;
    }

    if (lastDecayTs_ == 0) {
        lastDecayTs_ = nowTimestamp;
        return;
    }

    if (nowTimestamp <= lastDecayTs_) return;

    uint64_t elapsed = nowTimestamp - lastDecayTs_;
    uint64_t steps = elapsed / cfg_.decayIntervalSeconds;
    if (steps == 0) return;

    int64_t decayAmount64 = static_cast<int64_t>(steps) * static_cast<int64_t>(cfg_.decayPerInterval);
    int32_t decayAmount = decayAmount64 > static_cast<int64_t>(std::numeric_limits<int32_t>::max())
        ? std::numeric_limits<int32_t>::max()
        : static_cast<int32_t>(decayAmount64);
    penaltyPoints_ = std::max<int32_t>(0, penaltyPoints_ - decayAmount);
    lastDecayTs_ += steps * cfg_.decayIntervalSeconds;
}

void AgentScoreCard::applyPenalty(int32_t amount, uint64_t atTimestamp) {
    applyDecay(atTimestamp);
    if (amount <= 0) return;

    int64_t nextPenalty = static_cast<int64_t>(penaltyPoints_) + static_cast<int64_t>(amount);
    if (nextPenalty > static_cast<int64_t>(cfg_.baseScore - cfg_.minScore)) {
        penaltyPoints_ = cfg_.baseScore - cfg_.minScore;
    } else {
        penaltyPoints_ = static_cast<int32_t>(nextPenalty);
    }
}

void AgentScoreCard::applyReward(int32_t amount, uint64_t atTimestamp) {
    applyDecay(atTimestamp);
    if (amount <= 0) return;
    penaltyPoints_ = std::max<int32_t>(0, penaltyPoints_ - amount);
}

}
