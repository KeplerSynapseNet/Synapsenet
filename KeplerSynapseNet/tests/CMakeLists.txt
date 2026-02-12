cmake_minimum_required(VERSION 3.16)

add_executable(test_crypto test_crypto.cpp)
target_link_libraries(test_crypto Threads::Threads)
add_test(NAME CryptoTests COMMAND test_crypto)

add_executable(test_network test_network.cpp)
target_link_libraries(test_network Threads::Threads)
add_test(NAME NetworkTests COMMAND test_network)

add_executable(test_ledger test_ledger.cpp)
target_link_libraries(test_ledger Threads::Threads)
add_test(NAME LedgerTests COMMAND test_ledger)

add_executable(test_poe test_poe.cpp)
target_link_libraries(test_poe synapsed_core)
add_test(NAME PoETests COMMAND test_poe)

add_executable(test_privacy test_privacy.cpp)
target_link_libraries(test_privacy Threads::Threads)
add_test(NAME PrivacyTests COMMAND test_privacy)

add_executable(test_quantum test_quantum.cpp)
target_link_libraries(test_quantum Threads::Threads)
add_test(NAME QuantumTests COMMAND test_quantum)

add_executable(test_model test_model.cpp)
target_link_libraries(test_model Threads::Threads)
add_test(NAME ModelTests COMMAND test_model)

add_executable(test_wallet test_wallet.cpp)
target_link_libraries(test_wallet Threads::Threads)
add_test(NAME WalletTests COMMAND test_wallet)

add_executable(test_transfer test_transfer.cpp)
target_link_libraries(test_transfer synapsed_core)
add_test(NAME TransferTests COMMAND test_transfer)

add_executable(test_update_manifest test_update_manifest.cpp)
target_link_libraries(test_update_manifest synapsed_core)
add_test(NAME UpdateManifestTests COMMAND test_update_manifest)

add_executable(test_agent_runtime test_agent_runtime.cpp)
target_link_libraries(test_agent_runtime synapsed_core)
add_test(NAME AgentRuntimeTests COMMAND test_agent_runtime)

add_executable(test_implant_compatibility test_implant_compatibility.cpp)
target_link_libraries(test_implant_compatibility synapsed_core)
add_test(NAME ImplantCompatibilityTests COMMAND test_implant_compatibility)

add_executable(test_consensus test_consensus.cpp)
target_link_libraries(test_consensus synapsed_core)
add_test(NAME ConsensusTests COMMAND test_consensus)

add_executable(test_peer_discovery test_peer_discovery.cpp)
target_link_libraries(test_peer_discovery synapsed_core)
add_test(NAME PeerDiscoveryTests COMMAND test_peer_discovery)

add_executable(test_network_message test_network_message.cpp)
target_link_libraries(test_network_message synapsed_core)
add_test(NAME NetworkMessageTests COMMAND test_network_message)

add_executable(test_remote_model test_remote_model.cpp)
target_link_libraries(test_remote_model synapsed_core)
add_test(NAME RemoteModelTests COMMAND test_remote_model)

add_executable(test_marketplace test_marketplace.cpp)
target_link_libraries(test_marketplace synapsed_core)
add_test(NAME MarketplaceTests COMMAND test_marketplace)

# Task 5: ModelLoader Unit Tests
if(GTEST_FOUND)
    add_executable(test_model_loader test_model_loader.cpp)
    target_include_directories(test_model_loader PRIVATE ${GTEST_INCLUDE_DIRS})
    target_link_libraries(test_model_loader 
        Threads::Threads 
        synapsed_core
        ${GTEST_LIBRARIES}
    )
    add_test(NAME ModelLoaderTests COMMAND test_model_loader)
else()
    message(WARNING "GoogleTest not found - skipping test_model_loader tests")
endif()
