#include "core/poe_v1.h"
#include "core/poe_v1_objects.h"
#include "core/poe_v1_engine.h"
#include "crypto/crypto.h"
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <vector>

using synapse::core::poe_v1::canonicalizeText;
using synapse::core::poe_v1::canonicalizeCode;
using synapse::core::poe_v1::canonicalizeCodeForSimhash;
using synapse::core::poe_v1::hammingDistance64;
using synapse::core::poe_v1::hasLeadingZeroBits;
using synapse::core::poe_v1::minhash16;
using synapse::core::poe_v1::minhashEqualCount;
using synapse::core::poe_v1::selectValidators;
using synapse::core::poe_v1::simhash64;

static synapse::crypto::PublicKey makePk(uint8_t tag) {
    synapse::crypto::PublicKey pk{};
    pk[0] = tag;
    for (size_t i = 1; i < pk.size(); ++i) pk[i] = static_cast<uint8_t>(tag + i);
    return pk;
}

static synapse::crypto::PrivateKey makeSk(uint8_t tag) {
    synapse::crypto::PrivateKey sk{};
    for (size_t i = 0; i < sk.size(); ++i) sk[i] = static_cast<uint8_t>(tag + i);
    return sk;
}

static void testCanonicalize() {
    std::string in = "  Hello\tWORLD\r\n\nTest  ";
    std::string out = canonicalizeText(in);
    assert(out == "hello world test");
}

static void testCodeCanonicalize() {
    std::string in = "Foo\r\nBar\rBaz";
    std::string out = canonicalizeCode(in);
    assert(out == "Foo\nBarBaz");

    std::string sim = canonicalizeCodeForSimhash("  Foo\tBAR\r\nBaz  ");
    assert(sim == "Foo BAR Baz");
}

static void testCodeVsTextHashing() {
    synapse::crypto::PrivateKey sk = makeSk(1);
    synapse::crypto::PublicKey pk = synapse::crypto::derivePublicKey(sk);

    synapse::core::poe_v1::KnowledgeEntryV1 a;
    a.version = 1;
    a.timestamp = 123;
    a.authorPubKey = pk;
    a.contentType = synapse::core::poe_v1::ContentType::CODE;
    a.title = "Patch";
    a.body = "Foo";
    a.powBits = 12;

    synapse::core::poe_v1::KnowledgeEntryV1 b = a;
    b.body = "foo";

    assert(a.contentId() != b.contentId());

    synapse::core::poe_v1::KnowledgeEntryV1 q1 = a;
    q1.contentType = synapse::core::poe_v1::ContentType::QA;
    synapse::core::poe_v1::KnowledgeEntryV1 q2 = q1;
    q2.body = "foo";
    assert(q1.contentId() == q2.contentId());
}

static void testSimhashDeterminism() {
    std::string a = canonicalizeText("HELLO   world");
    std::string b = canonicalizeText(" hello world ");
    uint64_t ha = simhash64(a);
    uint64_t hb = simhash64(b);
    assert(ha == hb);
    assert(hammingDistance64(ha, hb) == 0);

    std::string c = canonicalizeText("completely different text");
    uint64_t hc = simhash64(c);
    assert(hammingDistance64(ha, hc) > 0);
}

static void testMinhashDeterminism() {
    std::string a = canonicalizeText("HELLO   world");
    std::string b = canonicalizeText(" hello world ");
    auto ha = minhash16(a);
    auto hb = minhash16(b);
    assert(ha == hb);
    assert(minhashEqualCount(ha, hb) == 16);

    std::string c = canonicalizeText("completely different text");
    auto hc = minhash16(c);
    assert(minhashEqualCount(ha, hc) < 16);
}

static void testLeadingZeros() {
    synapse::crypto::Hash256 h{};
    assert(hasLeadingZeroBits(h, 0));
    assert(hasLeadingZeroBits(h, 256));
    h[0] = 0x00;
    h[1] = 0x0F;
    assert(hasLeadingZeroBits(h, 12));
    h[1] = 0x8F;
    assert(!hasLeadingZeroBits(h, 12));
}

static void testValidatorSelectionDeterminism() {
    synapse::crypto::Hash256 prev = synapse::crypto::sha256(std::string("prev"));
    synapse::crypto::Hash256 sid = synapse::crypto::sha256(std::string("sid"));

    std::vector<synapse::crypto::PublicKey> validators = {
        makePk(3), makePk(1), makePk(9), makePk(2), makePk(7)
    };

    auto a = selectValidators(prev, sid, validators, 3);
    auto b = selectValidators(prev, sid, validators, 3);
    assert(a == b);
    assert(a.size() == 3);
    assert(a[0] != a[1] && a[0] != a[2] && a[1] != a[2]);

    std::reverse(validators.begin(), validators.end());
    auto c = selectValidators(prev, sid, validators, 3);
    assert(a == c);
}

static void testKnowledgeEntryV1Roundtrip() {
    synapse::crypto::PrivateKey sk = makeSk(42);
    synapse::crypto::PublicKey pk = synapse::crypto::derivePublicKey(sk);

    synapse::core::poe_v1::LimitsV1 limits;
    limits.minPowBits = 8;
    limits.maxPowBits = 28;

    synapse::core::poe_v1::KnowledgeEntryV1 e;
    e.version = 1;
    e.timestamp = 12345;
    e.authorPubKey = pk;
    e.contentType = synapse::core::poe_v1::ContentType::QA;
    e.title = "Hello";
    e.body = "World";
    e.powBits = 8;

    for (uint64_t nonce = 0;; ++nonce) {
        e.powNonce = nonce;
        if (hasLeadingZeroBits(e.submitId(), e.powBits)) break;
    }

    synapse::core::poe_v1::signKnowledgeEntryV1(e, sk);
    std::string reason;
    assert(e.verifyAll(limits, &reason));

    auto ser = e.serialize();
    auto d = synapse::core::poe_v1::KnowledgeEntryV1::deserialize(ser);
    assert(d.has_value());
    assert(d->version == e.version);
    assert(d->timestamp == e.timestamp);
    assert(d->authorPubKey == e.authorPubKey);
    assert(d->contentType == e.contentType);
    assert(d->title == e.title);
    assert(d->body == e.body);
    assert(d->powNonce == e.powNonce);
    assert(d->powBits == e.powBits);
    assert(d->authorSig == e.authorSig);
    assert(d->submitId() == e.submitId());
}

static void testValidationVoteV1Roundtrip() {
    synapse::crypto::PrivateKey sk = makeSk(7);
    synapse::core::poe_v1::ValidationVoteV1 v;
    v.version = 1;
    v.submitId = synapse::crypto::sha256(std::string("s"));
    v.prevBlockHash = synapse::crypto::sha256(std::string("p"));
    v.flags = 0;
    v.scores = {10, 20, 30};
    synapse::core::poe_v1::signValidationVoteV1(v, sk);
    assert(v.verifySignature());

    auto ser = v.serialize();
    auto d = synapse::core::poe_v1::ValidationVoteV1::deserialize(ser);
    assert(d.has_value());
    assert(d->version == v.version);
    assert(d->submitId == v.submitId);
    assert(d->prevBlockHash == v.prevBlockHash);
    assert(d->validatorPubKey == v.validatorPubKey);
    assert(d->flags == v.flags);
    assert(d->scores == v.scores);
    assert(d->signature == v.signature);
    assert(d->verifySignature());
}

static void testAcceptanceRewardDeterminism() {
    synapse::core::PoeV1Engine engine;
    synapse::core::PoeV1Config cfg;
    cfg.limits.minPowBits = 12;
    cfg.powBits = 12;
    cfg.acceptanceBaseReward = 10000000ULL;
    cfg.acceptanceMinReward = 1000000ULL;
    cfg.acceptanceMaxReward = 100000000ULL;
    cfg.acceptanceBonusPerPowBit = 1000000U;
    cfg.acceptanceSizePenaltyBytes = 2048;
    cfg.acceptancePenaltyPerChunk = 1000000U;
    engine.setConfig(cfg);

    synapse::core::poe_v1::KnowledgeEntryV1 e;
    e.version = 1;
    e.timestamp = 1;
    e.authorPubKey = makePk(1);
    e.contentType = synapse::core::poe_v1::ContentType::TEXT;
    e.title = "t";
    e.body = std::string(100, 'a');
    e.powBits = 12;
    uint64_t r1 = engine.calculateAcceptanceReward(e);
    uint64_t r2 = engine.calculateAcceptanceReward(e);
    assert(r1 == r2);
    assert(r1 >= cfg.acceptanceMinReward && r1 <= cfg.acceptanceMaxReward);
}

static void testEpochDeterminism() {
    auto uniq = std::to_string(static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count()));
    auto tmpDir = std::filesystem::temp_directory_path() / ("synapsenet_poe_epoch_" + uniq);
    std::error_code ec;
    std::filesystem::remove_all(tmpDir, ec);
    std::filesystem::create_directories(tmpDir, ec);
    std::string dbPath = (tmpDir / "poe.db").string();

    synapse::core::PoeV1Engine engine;
    assert(engine.open(dbPath));

    synapse::core::PoeV1Config cfg;
    cfg.powBits = 8;
    cfg.limits.minPowBits = cfg.powBits;
    cfg.limits.maxPowBits = 28;
    cfg.validatorsN = 2;
    cfg.validatorsM = 1;
    engine.setConfig(cfg);

    synapse::crypto::PrivateKey sk1 = makeSk(1);
    synapse::crypto::PrivateKey sk2 = makeSk(2);
    synapse::crypto::PublicKey pk1 = synapse::crypto::derivePublicKey(sk1);
    synapse::crypto::PublicKey pk2 = synapse::crypto::derivePublicKey(sk2);
    engine.setStaticValidators({pk1, pk2});

    auto r1 = engine.submit(synapse::core::poe_v1::ContentType::TEXT, "entry_a", "alpha", {}, sk1, true);
    assert(r1.ok && r1.finalized);

    auto r2 = engine.submit(synapse::core::poe_v1::ContentType::TEXT, "entry_b", "beta", {r1.contentId}, sk2, true);
    assert(r2.ok && r2.finalized);

    uint64_t budget = 1000000ULL;
    auto e1 = engine.runEpoch(budget, 20);
    assert(e1.ok);
    auto e2 = engine.runEpoch(budget, 20);
    assert(e2.ok);

    assert(e1.allocations.size() == e2.allocations.size());
    assert(e1.allocationHash == e2.allocationHash);

    uint64_t sum1 = 0;
    uint64_t sum2 = 0;
    for (size_t i = 0; i < e1.allocations.size(); ++i) {
        assert(e1.allocations[i].contentId == e2.allocations[i].contentId);
        assert(e1.allocations[i].amount == e2.allocations[i].amount);
        sum1 += e1.allocations[i].amount;
        sum2 += e2.allocations[i].amount;
    }
    assert(sum1 == budget);
    assert(sum2 == budget);

    engine.close();
    std::filesystem::remove_all(tmpDir, ec);
}

static void testDuplicateContentRejected() {
    auto uniq = std::to_string(static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count()));
    auto tmpDir = std::filesystem::temp_directory_path() / ("synapsenet_poe_dup_" + uniq);
    std::error_code ec;
    std::filesystem::remove_all(tmpDir, ec);
    std::filesystem::create_directories(tmpDir, ec);
    std::string dbPath = (tmpDir / "poe.db").string();

    synapse::core::PoeV1Engine engine;
    assert(engine.open(dbPath));

    synapse::core::PoeV1Config cfg;
    cfg.powBits = 8;
    cfg.limits.minPowBits = cfg.powBits;
    cfg.limits.maxPowBits = 28;
    cfg.validatorsN = 1;
    cfg.validatorsM = 1;
    engine.setConfig(cfg);

    synapse::crypto::PrivateKey sk = makeSk(11);
    synapse::crypto::PublicKey pk = synapse::crypto::derivePublicKey(sk);
    engine.setStaticValidators({pk});

    auto r1 = engine.submit(synapse::core::poe_v1::ContentType::TEXT, "dup", "same body", {}, sk, false);
    assert(r1.ok);

    auto r2 = engine.submit(synapse::core::poe_v1::ContentType::TEXT, "dup", "same body", {}, sk, false);
    assert(!r2.ok);
    assert(r2.error == "duplicate_content");

    engine.close();
    std::filesystem::remove_all(tmpDir, ec);
}

int main() {
    testCanonicalize();
    testCodeCanonicalize();
    testCodeVsTextHashing();
    testSimhashDeterminism();
    testMinhashDeterminism();
    testLeadingZeros();
    testValidatorSelectionDeterminism();
    testKnowledgeEntryV1Roundtrip();
    testValidationVoteV1Roundtrip();
    testAcceptanceRewardDeterminism();
    testEpochDeterminism();
    testDuplicateContentRejected();
    std::cout << "PoE v1 determinism tests passed\n";
    return 0;
}
