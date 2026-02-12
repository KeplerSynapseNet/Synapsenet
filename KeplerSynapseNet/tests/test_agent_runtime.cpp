#include "core/agent_runtime.h"
#include <cassert>
#include <cstdint>

static void testSandboxDefaultDeny() {
    synapse::core::AgentRuntimeSandbox sandbox;
    auto result = sandbox.authorize(synapse::core::AgentCapability::READ_LEDGER, false, false);
    assert(result == synapse::core::RuntimeActionResult::DENIED_CAPABILITY);
}

static void testSandboxAllowlistAndSideEffectRules() {
    synapse::core::SandboxPolicy policy;
    policy.allowSideEffects = false;
    policy.allowlist = {
        synapse::core::AgentCapability::READ_LEDGER,
        synapse::core::AgentCapability::PROPOSE_KNOWLEDGE
    };
    synapse::core::AgentRuntimeSandbox sandbox(policy);

    auto readResult = sandbox.authorize(synapse::core::AgentCapability::READ_LEDGER, false, false);
    assert(readResult == synapse::core::RuntimeActionResult::ALLOWED);

    auto sideEffectDenied = sandbox.authorize(synapse::core::AgentCapability::PROPOSE_KNOWLEDGE, true, true);
    assert(sideEffectDenied == synapse::core::RuntimeActionResult::DENIED_SIDE_EFFECTS);

    policy.allowSideEffects = true;
    sandbox.setPolicy(policy);
    auto explicitDenied = sandbox.authorize(synapse::core::AgentCapability::PROPOSE_KNOWLEDGE, true, false);
    assert(explicitDenied == synapse::core::RuntimeActionResult::DENIED_EXPLICIT_FLAG);

    auto explicitAllowed = sandbox.authorize(synapse::core::AgentCapability::PROPOSE_KNOWLEDGE, true, true);
    assert(explicitAllowed == synapse::core::RuntimeActionResult::ALLOWED);
}

static void testAgentScoreQuarantineAndDecay() {
    synapse::core::AgentScoreConfig cfg;
    cfg.baseScore = 1000;
    cfg.quarantineThreshold = 400;
    cfg.decayIntervalSeconds = 60;
    cfg.decayPerInterval = 10;
    synapse::core::AgentScoreCard score(cfg);

    score.applyPenalty(700, 100);
    assert(score.score() == 300);
    assert(score.quarantined());

    score.applyDecay(700);
    assert(score.score() == 400);
    assert(!score.quarantined());

    score.applyReward(50, 700);
    assert(score.score() == 450);
}

int main() {
    testSandboxDefaultDeny();
    testSandboxAllowlistAndSideEffectRules();
    testAgentScoreQuarantineAndDecay();
    return 0;
}
