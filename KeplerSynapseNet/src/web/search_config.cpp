#include "web/web.h"
#include <fstream>
#include <sstream>
#include <algorithm>

namespace synapse {
namespace web {

static std::string toLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return std::tolower(c); });
    return value;
}

static std::string trim(const std::string& value) {
    size_t start = value.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = value.find_last_not_of(" \t\r\n");
    return value.substr(start, end - start + 1);
}

static std::vector<std::string> splitList(const std::string& value) {
    std::vector<std::string> items;
    std::stringstream ss(value);
    std::string item;
    while (std::getline(ss, item, ',')) {
        std::string trimmed = trim(item);
        if (!trimmed.empty()) items.push_back(trimmed);
    }
    return items;
}

static bool parseBool(const std::string& value) {
    std::string v = toLower(trim(value));
    return v == "1" || v == "true" || v == "yes" || v == "on";
}

static std::string engineToString(SearchEngine engine) {
    switch (engine) {
        case SearchEngine::GOOGLE: return "google";
        case SearchEngine::BING: return "bing";
        case SearchEngine::DUCKDUCKGO: return "duckduckgo";
        case SearchEngine::BRAVE: return "brave";
        case SearchEngine::AHMIA: return "ahmia";
        case SearchEngine::TORCH: return "torch";
        case SearchEngine::NOTEVIL: return "notevil";
        case SearchEngine::DARKSEARCH: return "darksearch";
        case SearchEngine::DEEPSEARCH: return "deepsearch";
        case SearchEngine::CUSTOM: return "custom";
    }
    return "custom";
}

static bool parseEngine(const std::string& value, SearchEngine& engine) {
    std::string v = toLower(trim(value));
    if (v == "google") { engine = SearchEngine::GOOGLE; return true; }
    if (v == "bing") { engine = SearchEngine::BING; return true; }
    if (v == "duckduckgo") { engine = SearchEngine::DUCKDUCKGO; return true; }
    if (v == "brave") { engine = SearchEngine::BRAVE; return true; }
    if (v == "ahmia") { engine = SearchEngine::AHMIA; return true; }
    if (v == "torch") { engine = SearchEngine::TORCH; return true; }
    if (v == "notevil") { engine = SearchEngine::NOTEVIL; return true; }
    if (v == "darksearch") { engine = SearchEngine::DARKSEARCH; return true; }
    if (v == "deepsearch") { engine = SearchEngine::DEEPSEARCH; return true; }
    if (v == "custom") { engine = SearchEngine::CUSTOM; return true; }
    return false;
}

SearchConfig defaultSearchConfig() {
    SearchConfig cfg;
    cfg.clearnetEngines = {SearchEngine::DUCKDUCKGO, SearchEngine::BRAVE};
    cfg.darknetEngines = {SearchEngine::AHMIA, SearchEngine::TORCH, SearchEngine::DARKSEARCH, SearchEngine::DEEPSEARCH};
    cfg.maxResultsPerEngine = 10;
    cfg.maxPageSize = 1024 * 1024;
    cfg.timeoutSeconds = 10;
    cfg.enableClearnet = true;
    cfg.enableDarknet = true;
    cfg.enableKnowledgeNetwork = false;
    cfg.streamingMode = false;
    cfg.removeAds = true;
    cfg.removeScripts = true;
    cfg.removeStyles = true;
    cfg.routeClearnetThroughTor = false;
    cfg.tor.socksHost = "127.0.0.1";
    cfg.tor.socksPort = 9050;
    cfg.tor.controlHost = "127.0.0.1";
    cfg.tor.controlPort = 9051;
    cfg.tor.controlPassword = "";
    cfg.tor.useNewCircuit = false;
    cfg.tor.circuitTimeout = cfg.timeoutSeconds;
    return cfg;
}

bool loadSearchConfig(const std::string& path, SearchConfig& config) {
    std::ifstream file(path);
    if (!file.is_open()) {
        config = defaultSearchConfig();
        return false;
    }
    
    SearchConfig cfg = defaultSearchConfig();
    std::string line;
    while (std::getline(file, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        auto pos = line.find('=');
        if (pos == std::string::npos) continue;
        std::string key = trim(line.substr(0, pos));
        std::string value = trim(line.substr(pos + 1));
        
        if (key == "clearnet_engines") {
            cfg.clearnetEngines.clear();
            for (const auto& item : splitList(value)) {
                SearchEngine engine;
                if (parseEngine(item, engine)) cfg.clearnetEngines.push_back(engine);
            }
        } else if (key == "darknet_engines") {
            cfg.darknetEngines.clear();
            for (const auto& item : splitList(value)) {
                SearchEngine engine;
                if (parseEngine(item, engine)) cfg.darknetEngines.push_back(engine);
            }
        } else if (key == "custom_clearnet_urls") {
            cfg.customClearnetUrls = splitList(value);
        } else if (key == "custom_darknet_urls") {
            cfg.customDarknetUrls = splitList(value);
        } else if (key == "direct_onion_links") {
            cfg.directOnionLinks = splitList(value);
        } else if (key == "max_results_per_engine") {
            cfg.maxResultsPerEngine = static_cast<size_t>(std::stoul(value));
        } else if (key == "max_page_size") {
            cfg.maxPageSize = static_cast<size_t>(std::stoul(value));
        } else if (key == "timeout_seconds") {
            cfg.timeoutSeconds = static_cast<uint32_t>(std::stoul(value));
        } else if (key == "enable_clearnet") {
            cfg.enableClearnet = parseBool(value);
        } else if (key == "enable_darknet") {
            cfg.enableDarknet = parseBool(value);
        } else if (key == "enable_knowledge_network") {
            cfg.enableKnowledgeNetwork = parseBool(value);
        } else if (key == "streaming_mode") {
            cfg.streamingMode = parseBool(value);
        } else if (key == "remove_ads") {
            cfg.removeAds = parseBool(value);
        } else if (key == "remove_scripts") {
            cfg.removeScripts = parseBool(value);
        } else if (key == "remove_styles") {
            cfg.removeStyles = parseBool(value);
        } else if (key == "route_clearnet_through_tor") {
            cfg.routeClearnetThroughTor = parseBool(value);
        } else if (key == "tor_socks_host") {
            cfg.tor.socksHost = value;
        } else if (key == "tor_socks_port") {
            cfg.tor.socksPort = static_cast<uint16_t>(std::stoul(value));
        } else if (key == "tor_control_host") {
            cfg.tor.controlHost = value;
        } else if (key == "tor_control_port") {
            cfg.tor.controlPort = static_cast<uint16_t>(std::stoul(value));
        } else if (key == "tor_control_password") {
            cfg.tor.controlPassword = value;
        } else if (key == "tor_use_new_circuit") {
            cfg.tor.useNewCircuit = parseBool(value);
        } else if (key == "tor_circuit_timeout") {
            cfg.tor.circuitTimeout = static_cast<uint32_t>(std::stoul(value));
        }
    }
    
    config = cfg;
    return true;
}

bool saveSearchConfig(const SearchConfig& config, const std::string& path) {
    std::ofstream file(path);
    if (!file.is_open()) return false;
    
    auto writeList = [&](const std::vector<std::string>& items) {
        for (size_t i = 0; i < items.size(); i++) {
            if (i > 0) file << ",";
            file << items[i];
        }
    };
    
    auto writeEngines = [&](const std::vector<SearchEngine>& engines) {
        for (size_t i = 0; i < engines.size(); i++) {
            if (i > 0) file << ",";
            file << engineToString(engines[i]);
        }
    };
    
    file << "clearnet_engines=";
    writeEngines(config.clearnetEngines);
    file << "\n";
    
    file << "darknet_engines=";
    writeEngines(config.darknetEngines);
    file << "\n";
    
    file << "custom_clearnet_urls=";
    writeList(config.customClearnetUrls);
    file << "\n";
    
    file << "custom_darknet_urls=";
    writeList(config.customDarknetUrls);
    file << "\n";
    
    file << "direct_onion_links=";
    writeList(config.directOnionLinks);
    file << "\n";
    
    file << "max_results_per_engine=" << config.maxResultsPerEngine << "\n";
    file << "max_page_size=" << config.maxPageSize << "\n";
    file << "timeout_seconds=" << config.timeoutSeconds << "\n";
    file << "enable_clearnet=" << (config.enableClearnet ? "1" : "0") << "\n";
    file << "enable_darknet=" << (config.enableDarknet ? "1" : "0") << "\n";
    file << "enable_knowledge_network=" << (config.enableKnowledgeNetwork ? "1" : "0") << "\n";
    file << "streaming_mode=" << (config.streamingMode ? "1" : "0") << "\n";
    file << "remove_ads=" << (config.removeAds ? "1" : "0") << "\n";
    file << "remove_scripts=" << (config.removeScripts ? "1" : "0") << "\n";
    file << "remove_styles=" << (config.removeStyles ? "1" : "0") << "\n";
    file << "route_clearnet_through_tor=" << (config.routeClearnetThroughTor ? "1" : "0") << "\n";
    file << "tor_socks_host=" << config.tor.socksHost << "\n";
    file << "tor_socks_port=" << config.tor.socksPort << "\n";
    file << "tor_control_host=" << config.tor.controlHost << "\n";
    file << "tor_control_port=" << config.tor.controlPort << "\n";
    file << "tor_control_password=" << config.tor.controlPassword << "\n";
    file << "tor_use_new_circuit=" << (config.tor.useNewCircuit ? "1" : "0") << "\n";
    file << "tor_circuit_timeout=" << config.tor.circuitTimeout << "\n";
    
    return true;
}

}
}
