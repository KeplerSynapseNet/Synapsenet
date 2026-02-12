#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace synapse::core {

enum class AgentCapability : uint8_t {
    READ_LEDGER = 0,
    READ_NETWORK = 1,
    FETCH_EXTERNAL = 2,
    PROPOSE_KNOWLEDGE = 3,
    PUBLISH_UPDATE = 4,
    INSTALL_UPDATE = 5
};

struct SandboxPolicy {
    bool allowSideEffects = false;
    std::vector<AgentCapability> allowlist;
};

enum class RuntimeActionResult : uint8_t {
    ALLOWED = 0,
    DENIED_CAPABILITY = 1,
    DENIED_SIDE_EFFECTS = 2,
    DENIED_EXPLICIT_FLAG = 3
};

class AgentRuntimeSandbox {
public:
    AgentRuntimeSandbox();
    explicit AgentRuntimeSandbox(const SandboxPolicy& policy);

    void setPolicy(const SandboxPolicy& policy);
    SandboxPolicy getPolicy() const;

    bool isAllowed(AgentCapability capability) const;
    RuntimeActionResult authorize(AgentCapability capability, bool hasSideEffects, bool explicitSideEffectFlag) const;

private:
    SandboxPolicy policy_;
};

struct AgentScoreConfig {
    int32_t baseScore = 1000;
    int32_t minScore = 0;
    int32_t maxScore = 2000;
    int32_t quarantineThreshold = 400;
    uint32_t decayIntervalSeconds = 60;
    int32_t decayPerInterval = 5;
};

class AgentScoreCard {
public:
    explicit AgentScoreCard(const AgentScoreConfig& cfg = AgentScoreConfig{});

    AgentScoreConfig config() const;
    int32_t score() const;
    int32_t penalty() const;
    bool quarantined() const;

    void applyPenalty(int32_t amount, uint64_t atTimestamp);
    void applyReward(int32_t amount, uint64_t atTimestamp);
    void applyDecay(uint64_t nowTimestamp);

private:
    AgentScoreConfig cfg_{};
    int32_t penaltyPoints_ = 0;
    uint64_t lastDecayTs_ = 0;
};

}
