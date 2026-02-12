#include "core/implant_compatibility.h"
#include "core/update_bundle.h"
#include "crypto/crypto.h"
#include <cassert>
#include <string>

static synapse::core::UpdateManifest makeValidManifest(uint32_t protocolMin, uint32_t protocolMax) {
    auto keyPair = synapse::crypto::generateKeyPair();

    synapse::core::UpdateManifest manifest;
    synapse::core::UpdateChunk c1;
    c1.hash = synapse::crypto::sha256("implant_chunk_1");
    c1.size = 1024;
    synapse::core::UpdateChunk c2;
    c2.hash = synapse::crypto::sha256("implant_chunk_2");
    c2.size = 2048;
    manifest.chunks = {c1, c2};
    manifest.target = "implant/driver";
    manifest.protocolMin = protocolMin;
    manifest.protocolMax = protocolMax;
    bool ok = synapse::core::signUpdateManifest(manifest, keyPair.privateKey, nullptr);
    assert(ok);
    return manifest;
}

static void testFrameValidation() {
    synapse::core::ImplantCompatibilityPolicy policy;
    policy.protocolMin = 1;
    policy.protocolMax = 3;
    policy.halVersion = 1;

    synapse::core::ImplantHalFrameV1 frame;
    frame.version = 1;
    frame.protocolVersion = 2;
    frame.timestamp = 100;
    frame.sequence = 1;
    frame.payloadSize = 4096;
    frame.capabilities = {
        synapse::core::ImplantCapability::FEATURE_STREAM,
        synapse::core::ImplantCapability::INTENT_STREAM
    };

    std::string reason;
    assert(synapse::core::ImplantCompatibility::validateFrame(frame, policy, &reason));

    frame.protocolVersion = 7;
    assert(!synapse::core::ImplantCompatibility::validateFrame(frame, policy, &reason));
    assert(reason == "protocol_mismatch");
}

static void testIntentValidationAndPermissionModel() {
    synapse::core::ImplantCompatibilityPolicy policy;
    policy.intentSchemaVersion = 1;

    synapse::core::PermissionModelV1 permissions;
    permissions.defaultDeny = true;
    permissions.allowedPermissions = {
        synapse::core::PermissionScope::INTENTS,
        synapse::core::PermissionScope::FEATURES
    };

    synapse::core::IntentV1 intent;
    intent.schemaVersion = 1;
    intent.type = synapse::core::IntentType::COMMAND;
    intent.source = "implant_hub";
    intent.payloadHash = synapse::crypto::sha256("intent_payload");
    intent.requestedPermissions = {synapse::core::PermissionScope::INTENTS};
    intent.timestamp = 200;

    std::string reason;
    assert(synapse::core::ImplantCompatibility::validateIntent(intent, permissions, policy, &reason));

    intent.requestedPermissions = {synapse::core::PermissionScope::DRIVER_INSTALL};
    assert(!synapse::core::ImplantCompatibility::validateIntent(intent, permissions, policy, &reason));
    assert(reason == "permission_denied");
}

static void testInstallCompatibilityMatrix() {
    synapse::core::ImplantCompatibilityPolicy policy;
    policy.protocolMin = 2;
    policy.protocolMax = 4;
    policy.requireSafetyGate = true;

    std::string reason;
    auto compatibleManifest = makeValidManifest(3, 4);
    assert(synapse::core::ImplantCompatibility::canInstallManifest(compatibleManifest, true, policy, &reason));

    assert(!synapse::core::ImplantCompatibility::canInstallManifest(compatibleManifest, false, policy, &reason));
    assert(reason == "safety_gate_required");

    auto incompatibleManifest = makeValidManifest(5, 6);
    assert(!synapse::core::ImplantCompatibility::canInstallManifest(incompatibleManifest, true, policy, &reason));
    assert(reason == "protocol_incompatible");
}

int main() {
    testFrameValidation();
    testIntentValidationAndPermissionModel();
    testInstallCompatibilityMatrix();
    return 0;
}
