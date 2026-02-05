#include "core/transfer.h"
#include "crypto/crypto.h"
#include <cassert>
#include <chrono>
#include <filesystem>
#include <string>
#include <vector>

static std::string addressFromPubKey(const synapse::crypto::PublicKey& pubKey) {
    std::string hex = synapse::crypto::toHex(pubKey);
    if (hex.size() < 52) return {};
    return "ngt1" + hex.substr(0, 52);
}

static synapse::core::Transaction createTxWithMinFee(
    synapse::core::TransferManager& tm,
    const std::string& from,
    const std::string& to,
    uint64_t amount,
    uint64_t feeHint = 0) {
    uint64_t fee = feeHint ? feeHint : tm.estimateFee(0);
    synapse::core::Transaction tx;
    for (int i = 0; i < 5; ++i) {
        tx = tm.createTransaction(from, to, amount, fee);
        uint64_t requiredFee = tm.estimateFee(tx.serialize().size());
        if (requiredFee <= fee) break;
        fee = requiredFee;
    }
    return tx;
}

static void testUtxoOwnershipEnforced() {
    auto uniq = std::to_string(static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count()));
    auto tmpDir = std::filesystem::temp_directory_path() / ("synapsenet_transfer_" + uniq);
    std::error_code ec;
    std::filesystem::remove_all(tmpDir, ec);
    std::filesystem::create_directories(tmpDir, ec);
    std::string dbPath = (tmpDir / "transfer.db").string();

    synapse::core::TransferManager tm;
    assert(tm.open(dbPath));

    auto kpA = synapse::crypto::generateKeyPair();
    auto kpB = synapse::crypto::generateKeyPair();
    std::string addrA = addressFromPubKey(kpA.publicKey);
    std::string addrB = addressFromPubKey(kpB.publicKey);
    assert(!addrA.empty());
    assert(!addrB.empty());

    synapse::crypto::Hash256 rewardId = synapse::crypto::sha256(std::string("rewardA"));
    assert(tm.creditRewardDeterministic(addrA, rewardId, 100000));

    auto tx = createTxWithMinFee(tm, addrA, addrB, 100);
    assert(!tx.inputs.empty());

    assert(tm.signTransaction(tx, kpB.privateKey));
    assert(!tm.submitTransaction(tx));

    assert(tm.signTransaction(tx, kpA.privateKey));
    assert(tm.submitTransaction(tx));
}

static void testRejectsLowFee() {
    auto uniq = std::to_string(static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count()));
    auto tmpDir = std::filesystem::temp_directory_path() / ("synapsenet_transfer_fee_" + uniq);
    std::error_code ec;
    std::filesystem::remove_all(tmpDir, ec);
    std::filesystem::create_directories(tmpDir, ec);
    std::string dbPath = (tmpDir / "transfer.db").string();

    synapse::core::TransferManager tm;
    assert(tm.open(dbPath));

    auto kpA = synapse::crypto::generateKeyPair();
    auto kpB = synapse::crypto::generateKeyPair();
    std::string addrA = addressFromPubKey(kpA.publicKey);
    std::string addrB = addressFromPubKey(kpB.publicKey);
    assert(!addrA.empty());
    assert(!addrB.empty());

    synapse::crypto::Hash256 rewardId = synapse::crypto::sha256(std::string("reward_fee"));
    assert(tm.creditRewardDeterministic(addrA, rewardId, 100000));

    auto lowFeeTx = tm.createTransaction(addrA, addrB, 100, 1);
    assert(tm.signTransaction(lowFeeTx, kpA.privateKey));
    assert(!tm.submitTransaction(lowFeeTx));

    auto okTx = createTxWithMinFee(tm, addrA, addrB, 100);
    assert(tm.signTransaction(okTx, kpA.privateKey));
    assert(tm.submitTransaction(okTx));
}

static void testBlockOrderRejectsDoubleSpend() {
    auto uniq = std::to_string(static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count()));
    auto tmpDir = std::filesystem::temp_directory_path() / ("synapsenet_transfer_block1_" + uniq);
    std::error_code ec;
    std::filesystem::remove_all(tmpDir, ec);
    std::filesystem::create_directories(tmpDir, ec);
    std::string dbPath = (tmpDir / "transfer.db").string();

    synapse::core::TransferManager tm;
    assert(tm.open(dbPath));

    auto kpA = synapse::crypto::generateKeyPair();
    auto kpB = synapse::crypto::generateKeyPair();
    auto kpC = synapse::crypto::generateKeyPair();
    std::string addrA = addressFromPubKey(kpA.publicKey);
    std::string addrB = addressFromPubKey(kpB.publicKey);
    std::string addrC = addressFromPubKey(kpC.publicKey);
    assert(!addrA.empty() && !addrB.empty() && !addrC.empty());

    synapse::crypto::Hash256 rewardId = synapse::crypto::sha256(std::string("reward_block1"));
    assert(tm.creditRewardDeterministic(addrA, rewardId, 100000));

    auto tx1 = createTxWithMinFee(tm, addrA, addrB, 100);
    auto tx2 = createTxWithMinFee(tm, addrA, addrC, 80);
    assert(tm.signTransaction(tx1, kpA.privateKey));
    assert(tm.signTransaction(tx2, kpA.privateKey));

    std::vector<synapse::core::Transaction> txs = {tx1, tx2};
    assert(!tm.verifyTransactionsInBlockOrder(txs));
}

static void testBlockOrderAllowsChainedSpend() {
    auto uniq = std::to_string(static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count()));
    auto tmpDir = std::filesystem::temp_directory_path() / ("synapsenet_transfer_block2_" + uniq);
    std::error_code ec;
    std::filesystem::remove_all(tmpDir, ec);
    std::filesystem::create_directories(tmpDir, ec);
    std::string dbPath = (tmpDir / "transfer.db").string();

    synapse::core::TransferManager tm;
    assert(tm.open(dbPath));

    auto kpA = synapse::crypto::generateKeyPair();
    auto kpB = synapse::crypto::generateKeyPair();
    auto kpC = synapse::crypto::generateKeyPair();
    std::string addrA = addressFromPubKey(kpA.publicKey);
    std::string addrB = addressFromPubKey(kpB.publicKey);
    std::string addrC = addressFromPubKey(kpC.publicKey);
    assert(!addrA.empty() && !addrB.empty() && !addrC.empty());

    synapse::crypto::Hash256 rewardId = synapse::crypto::sha256(std::string("reward_block2"));
    assert(tm.creditRewardDeterministic(addrA, rewardId, 100000));

    auto tx1 = createTxWithMinFee(tm, addrA, addrB, 100);
    assert(tx1.outputs.size() == 2);
    uint64_t changeAmt = tx1.outputs[1].amount;
    assert(tx1.outputs[1].address == addrA);
    assert(tm.signTransaction(tx1, kpA.privateKey));

    synapse::core::Transaction tx2;
    tx2.timestamp = tx1.timestamp + 1;
    tx2.fee = tm.estimateFee(0);
    tx2.status = synapse::core::TxStatus::PENDING;
    synapse::core::TxInput in;
    in.prevTxHash = tx1.txid;
    in.outputIndex = 1;
    tx2.inputs.push_back(in);
    synapse::core::TxOutput out1;
    out1.amount = 50;
    out1.address = addrC;
    tx2.outputs.push_back(out1);
    synapse::core::TxOutput out2;
    out2.amount = 1;
    out2.address = addrA;
    tx2.outputs.push_back(out2);
    tx2.fee = tm.estimateFee(tx2.serialize().size());
    tx2.outputs[1].amount = changeAmt - out1.amount - tx2.fee;
    tx2.txid = tx2.computeHash();
    assert(tm.signTransaction(tx2, kpA.privateKey));

    std::vector<synapse::core::Transaction> txs = {tx1, tx2};
    assert(tm.verifyTransactionsInBlockOrder(txs));
}

static void testApplyBlockDropsConflictingPending() {
    auto uniq = std::to_string(static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count()));
    auto tmpDir = std::filesystem::temp_directory_path() / ("synapsenet_transfer_block3_" + uniq);
    std::error_code ec;
    std::filesystem::remove_all(tmpDir, ec);
    std::filesystem::create_directories(tmpDir, ec);
    std::string dbPath = (tmpDir / "transfer.db").string();

    synapse::core::TransferManager tm;
    assert(tm.open(dbPath));

    auto kpA = synapse::crypto::generateKeyPair();
    auto kpB = synapse::crypto::generateKeyPair();
    auto kpC = synapse::crypto::generateKeyPair();
    std::string addrA = addressFromPubKey(kpA.publicKey);
    std::string addrB = addressFromPubKey(kpB.publicKey);
    std::string addrC = addressFromPubKey(kpC.publicKey);
    assert(!addrA.empty() && !addrB.empty() && !addrC.empty());

    synapse::crypto::Hash256 rewardId = synapse::crypto::sha256(std::string("reward_block3"));
    const uint64_t rewardAmount = 100000;
    assert(tm.creditRewardDeterministic(addrA, rewardId, rewardAmount));

    auto pendingTx = createTxWithMinFee(tm, addrA, addrB, 100);
    assert(tm.signTransaction(pendingTx, kpA.privateKey));
    assert(tm.submitTransaction(pendingTx));

    auto blockTx = createTxWithMinFee(tm, addrA, addrC, 80);
    assert(tm.signTransaction(blockTx, kpA.privateKey));

    std::vector<synapse::core::Transaction> txs = {blockTx};
    synapse::crypto::Hash256 blockHash = synapse::crypto::sha256(std::string("block3"));
    assert(tm.applyBlockTransactionsFromBlock(txs, 1, blockHash));

    assert(tm.getPending().empty());
    assert(tm.getBalance(addrB) == 0);
    assert(tm.getBalance(addrC) == 80);
    assert(tm.getBalance(addrA) == rewardAmount - 80 - blockTx.fee);
}

static void testRollbackBlockRestoresUtxo() {
    auto uniq = std::to_string(static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count()));
    auto tmpDir = std::filesystem::temp_directory_path() / ("synapsenet_transfer_reorg_" + uniq);
    std::error_code ec;
    std::filesystem::remove_all(tmpDir, ec);
    std::filesystem::create_directories(tmpDir, ec);
    std::string dbPath = (tmpDir / "transfer.db").string();

    synapse::core::TransferManager tm;
    assert(tm.open(dbPath));

    auto kpA = synapse::crypto::generateKeyPair();
    auto kpB = synapse::crypto::generateKeyPair();
    std::string addrA = addressFromPubKey(kpA.publicKey);
    std::string addrB = addressFromPubKey(kpB.publicKey);
    assert(!addrA.empty() && !addrB.empty());

    synapse::crypto::Hash256 rewardId = synapse::crypto::sha256(std::string("reward_reorg"));
    const uint64_t rewardAmount = 100000;
    assert(tm.creditRewardDeterministic(addrA, rewardId, rewardAmount));

    auto blockTx = createTxWithMinFee(tm, addrA, addrB, 100);
    assert(tm.signTransaction(blockTx, kpA.privateKey));

    std::vector<synapse::core::Transaction> txs = {blockTx};
    synapse::crypto::Hash256 blockHash = synapse::crypto::sha256(std::string("block_reorg_1"));
    assert(tm.applyBlockTransactionsFromBlock(txs, 1, blockHash));
    assert(tm.getBalance(addrB) == 100);

    assert(tm.rollbackBlockTransactions(1, blockHash));

    assert(tm.getBalance(addrB) == 0);
    assert(tm.getBalance(addrA) == rewardAmount);
}

static void testMempoolEvictsLowestFee() {
    auto uniq = std::to_string(static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count()));
    auto tmpDir = std::filesystem::temp_directory_path() / ("synapsenet_transfer_mempool_" + uniq);
    std::error_code ec;
    std::filesystem::remove_all(tmpDir, ec);
    std::filesystem::create_directories(tmpDir, ec);
    std::string dbPath = (tmpDir / "transfer.db").string();

    synapse::core::TransferManager tm;
    assert(tm.open(dbPath));
    tm.setMaxMempoolSize(1);

    auto kpA = synapse::crypto::generateKeyPair();
    auto kpB = synapse::crypto::generateKeyPair();
    auto kpC = synapse::crypto::generateKeyPair();
    std::string addrA = addressFromPubKey(kpA.publicKey);
    std::string addrB = addressFromPubKey(kpB.publicKey);
    std::string addrC = addressFromPubKey(kpC.publicKey);
    assert(!addrA.empty() && !addrB.empty() && !addrC.empty());

    synapse::crypto::Hash256 rewardA = synapse::crypto::sha256(std::string("reward_mempool_A"));
    synapse::crypto::Hash256 rewardB = synapse::crypto::sha256(std::string("reward_mempool_B"));
    assert(tm.creditRewardDeterministic(addrA, rewardA, 100000));
    assert(tm.creditRewardDeterministic(addrB, rewardB, 100000));

    auto txA = createTxWithMinFee(tm, addrA, addrC, 100);
    assert(tm.signTransaction(txA, kpA.privateKey));
    assert(tm.submitTransaction(txA));

    auto txBsame = createTxWithMinFee(tm, addrB, addrC, 100);
    assert(tm.signTransaction(txBsame, kpB.privateKey));
    assert(!tm.submitTransaction(txBsame));

    auto txB = createTxWithMinFee(tm, addrB, addrC, 100, txA.fee + 1);
    assert(tm.signTransaction(txB, kpB.privateKey));
    assert(tm.submitTransaction(txB));

    auto pending = tm.getPending();
    assert(pending.size() == 1);
    assert(pending[0].txid == txB.txid);

    auto dropped = tm.getTransaction(txA.txid);
    assert(dropped.txid == txA.txid);
    assert(dropped.status == synapse::core::TxStatus::REJECTED);
}

int main() {
    testUtxoOwnershipEnforced();
    testRejectsLowFee();
    testBlockOrderRejectsDoubleSpend();
    testBlockOrderAllowsChainedSpend();
    testApplyBlockDropsConflictingPending();
    testRollbackBlockRestoresUtxo();
    testMempoolEvictsLowestFee();
    return 0;
}
