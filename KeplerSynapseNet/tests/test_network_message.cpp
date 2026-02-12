#include "network/network.h"
#include <cassert>
#include <vector>

static void testMessageRoundTrip() {
    synapse::network::Message msg;
    msg.type = synapse::network::MessageType::PING;
    msg.command = "ping";
    msg.payload = {1, 2, 3, 4, 5};
    msg.timestamp = 1;

    auto bytes = msg.serialize();
    assert(!bytes.empty());

    auto parsed = synapse::network::Message::deserialize(bytes);
    assert(parsed.command == "ping");
    assert(parsed.payload == msg.payload);
}

static void testSerializeRejectsInvalidCommand() {
    synapse::network::Message msg;
    msg.type = synapse::network::MessageType::PING;
    msg.command = "pi\ng";
    msg.payload = {1};
    auto bytes = msg.serialize();
    assert(bytes.empty());
}

static void testSerializeRejectsOversizedPayload() {
    synapse::network::Message msg;
    msg.type = synapse::network::MessageType::PING;
    msg.command = "ping";
    msg.payload.assign(synapse::network::MAX_MESSAGE_SIZE + 1, 0x42);
    auto bytes = msg.serialize();
    assert(bytes.empty());
}

static void testDeserializeRejectsTrailingBytes() {
    synapse::network::Message msg;
    msg.type = synapse::network::MessageType::PING;
    msg.command = "ping";
    msg.payload = {7, 8, 9};
    auto bytes = msg.serialize();
    assert(!bytes.empty());
    bytes.push_back(0x00);

    auto parsed = synapse::network::Message::deserialize(bytes);
    assert(parsed.command.empty());
    assert(parsed.payload.empty());
}

static void testDeserializeRejectsBadCommandAndChecksum() {
    synapse::network::Message msg;
    msg.type = synapse::network::MessageType::PING;
    msg.command = "ping";
    msg.payload = {7, 8, 9};
    auto bytes = msg.serialize();
    assert(!bytes.empty());

    auto badCommand = bytes;
    badCommand[4] = 0x01;
    auto parsedBadCommand = synapse::network::Message::deserialize(badCommand);
    assert(parsedBadCommand.command.empty());
    assert(parsedBadCommand.payload.empty());

    auto badChecksum = bytes;
    badChecksum[24] ^= 0x01;
    auto parsedBadChecksum = synapse::network::Message::deserialize(badChecksum);
    assert(parsedBadChecksum.command.empty());
    assert(parsedBadChecksum.payload.empty());
}

int main() {
    testMessageRoundTrip();
    testSerializeRejectsInvalidCommand();
    testSerializeRejectsOversizedPayload();
    testDeserializeRejectsTrailingBytes();
    testDeserializeRejectsBadCommandAndChecksum();
    return 0;
}
