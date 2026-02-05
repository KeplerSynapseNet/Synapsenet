#include "web/web.h"
#include "web/curl_fetch.h"
#include <mutex>
#include <thread>
#include <chrono>
#include <sstream>
#include <algorithm>
#include <regex>
#include <ctime>
#include <iomanip>

namespace synapse {
namespace web {

struct WebSearch::Impl {
    SearchConfig config;
    mutable std::mutex mtx;
    bool initialized = false;
    WebStats stats{};
    std::function<void(const std::vector<SearchResult>&)> searchCallback;
    std::function<void(const std::string&)> errorCallback;
    
    std::string buildSearchUrl(SearchEngine engine, const std::string& query);
    std::vector<SearchResult> parseResults(const std::string& html, SearchEngine engine);
    std::string httpGet(const std::string& host, const std::string& path, uint16_t port = 80);
    double calculateRelevance(const std::string& query, const SearchResult& result);
};

std::string WebSearch::Impl::buildSearchUrl(SearchEngine engine, const std::string& query) {
    std::string encoded = urlEncode(query);
    switch (engine) {
        case SearchEngine::DUCKDUCKGO:
            return "/html/?q=" + encoded;
        case SearchEngine::BRAVE:
            return "/search?q=" + encoded;
        default:
            return "/search?q=" + encoded;
    }
}

std::string WebSearch::Impl::httpGet(const std::string& host, const std::string& path, uint16_t port) {
    std::ostringstream url;
    url << "http://" << host;
    if (port != 0 && port != 80) url << ":" << port;
    if (!path.empty() && path[0] != '/') url << "/";
    url << (path.empty() ? "/" : path);

    CurlFetchOptions opt;
    opt.timeoutSeconds = config.timeoutSeconds;
    opt.maxBytes = config.maxPageSize;
    if (config.routeClearnetThroughTor && !config.tor.socksHost.empty() && config.tor.socksPort != 0) {
        opt.socksProxyHostPort = config.tor.socksHost + ":" + std::to_string(config.tor.socksPort);
    }
    CurlFetchResult res = curlFetch(url.str(), opt);
    if (res.exitCode != 0 || res.body.empty()) {
        stats.failedFetches++;
        if (errorCallback && !res.error.empty()) {
            errorCallback(res.error);
        }
        return "";
    }

    stats.successfulFetches++;
    stats.bytesDownloaded += res.body.size();
    return res.body;
}

std::vector<SearchResult> WebSearch::Impl::parseResults(const std::string& html, SearchEngine engine) {
    std::vector<SearchResult> results;
    std::regex linkRegex("<a[^>]*href=\"(https?://[^\"]+)\"[^>]*>([^<]*)</a>");
    
    std::smatch match;
    std::string::const_iterator searchStart(html.cbegin());
    
    while (std::regex_search(searchStart, html.cend(), match, linkRegex)) {
        SearchResult result;
        result.url = match[1].str();
        result.title = match[2].str();
        result.domain = extractDomain(result.url);
        result.isOnion = isOnionUrl(result.url);
        result.timestamp = std::time(nullptr);
        result.contentType = ContentType::HTML;
        result.relevanceScore = 0.0;
        
        if (!result.url.empty() && result.url.find("javascript:") == std::string::npos) {
            results.push_back(result);
        }
        
        searchStart = match.suffix().first;
        if (results.size() >= config.maxResultsPerEngine) break;
    }
    
    return results;
}

double WebSearch::Impl::calculateRelevance(const std::string& query, const SearchResult& result) {
    double score = 0.0;
    std::string lowerQuery = query;
    std::string lowerTitle = result.title;
    std::string lowerSnippet = result.snippet;
    
    std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(), ::tolower);
    std::transform(lowerTitle.begin(), lowerTitle.end(), lowerTitle.begin(), ::tolower);
    std::transform(lowerSnippet.begin(), lowerSnippet.end(), lowerSnippet.begin(), ::tolower);
    
    std::istringstream iss(lowerQuery);
    std::string word;
    while (iss >> word) {
        if (lowerTitle.find(word) != std::string::npos) score += 2.0;
        if (lowerSnippet.find(word) != std::string::npos) score += 1.0;
        if (result.domain.find(word) != std::string::npos) score += 1.5;
    }
    
    return score;
}

WebSearch::WebSearch() : impl_(std::make_unique<Impl>()) {
    impl_->config = defaultSearchConfig();
}
WebSearch::~WebSearch() { shutdown(); }

bool WebSearch::init(const SearchConfig& config) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->config = config;
    impl_->initialized = true;
    return true;
}

void WebSearch::shutdown() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->initialized = false;
}

std::vector<SearchResult> WebSearch::search(const std::string& query, QueryType type) {
    std::vector<SearchResult> allResults;
    
    if (type == QueryType::CLEARNET || type == QueryType::BOTH) {
        auto clearnetResults = searchClearnet(query);
        allResults.insert(allResults.end(), clearnetResults.begin(), clearnetResults.end());
    }
    
    if (type == QueryType::DARKNET || type == QueryType::BOTH) {
        auto darknetResults = searchDarknet(query);
        allResults.insert(allResults.end(), darknetResults.begin(), darknetResults.end());
    }
    
    for (auto& result : allResults) {
        result.relevanceScore = impl_->calculateRelevance(query, result);
    }
    
    std::sort(allResults.begin(), allResults.end(),
              [](const SearchResult& a, const SearchResult& b) {
                  return a.relevanceScore > b.relevanceScore;
              });
    
    impl_->stats.totalSearches++;
    
    if (impl_->searchCallback) {
        impl_->searchCallback(allResults);
    }
    
    return allResults;
}

std::vector<SearchResult> WebSearch::searchClearnet(const std::string& query) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    std::vector<SearchResult> results;
    
    if (!impl_->config.enableClearnet) return results;
    
    std::string encoded = urlEncode(query);
    
    auto applyTemplate = [&](const std::string& base) {
        std::string url = base;
        size_t pos = url.find("{query}");
        if (pos != std::string::npos) {
            url.replace(pos, 7, encoded);
            return url;
        }
        pos = url.find("%s");
        if (pos != std::string::npos) {
            url.replace(pos, 2, encoded);
            return url;
        }
        if (url.find('?') == std::string::npos) {
            return url + "?q=" + encoded;
        }
        return url + "&q=" + encoded;
    };
    
    auto fetchUrl = [&](const std::string& url) -> std::string {
        CurlFetchOptions opt;
        opt.timeoutSeconds = impl_->config.timeoutSeconds;
        opt.maxBytes = impl_->config.maxPageSize;
        if (impl_->config.routeClearnetThroughTor && !impl_->config.tor.socksHost.empty() && impl_->config.tor.socksPort != 0) {
            opt.socksProxyHostPort = impl_->config.tor.socksHost + ":" + std::to_string(impl_->config.tor.socksPort);
        }
        CurlFetchResult res = curlFetch(url, opt);
        if (res.exitCode != 0) {
            impl_->stats.failedFetches++;
            if (impl_->errorCallback && !res.error.empty()) {
                impl_->errorCallback(res.error);
            }
            return "";
        }
        impl_->stats.successfulFetches++;
        impl_->stats.bytesDownloaded += res.body.size();
        return res.body;
    };
    
    for (auto engine : impl_->config.clearnetEngines) {
        std::string host;
        std::string path = impl_->buildSearchUrl(engine, query);
        
        switch (engine) {
            case SearchEngine::DUCKDUCKGO:
                host = "html.duckduckgo.com";
                break;
            case SearchEngine::BRAVE:
                host = "search.brave.com";
                break;
            default:
                continue;
        }
        
        std::string html = impl_->httpGet(host, path, 80);
        if (html.empty()) continue;
        
        auto engineResults = impl_->parseResults(html, engine);
        results.insert(results.end(), engineResults.begin(), engineResults.end());
    }
    
    for (const auto& base : impl_->config.customClearnetUrls) {
        std::string url = applyTemplate(base);
        std::string html = fetchUrl(url);
        if (html.empty()) continue;
        auto engineResults = impl_->parseResults(html, SearchEngine::CUSTOM);
        results.insert(results.end(), engineResults.begin(), engineResults.end());
    }
    
    impl_->stats.clearnetSearches++;
    return results;
}

std::vector<SearchResult> WebSearch::searchDarknet(const std::string& query) {
    SearchConfig config;
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        config = impl_->config;
    }
    
    std::vector<SearchResult> results;
    if (!config.enableDarknet) return results;
    
    QueryDetector detector;
    QueryAnalysis analysis = detector.analyze(query);
    
    DarknetEngines engines;
    OnionSearchRouter router;
    auto routes = router.route(query, analysis, config, engines);
    
    TorEngine tor;
    TorConfig torCfg = config.tor;
    if (torCfg.socksHost.empty()) torCfg.socksHost = "127.0.0.1";
    if (torCfg.socksPort == 0) torCfg.socksPort = 9050;
    if (torCfg.controlHost.empty()) torCfg.controlHost = "127.0.0.1";
    if (torCfg.controlPort == 0) torCfg.controlPort = 9051;
    torCfg.circuitTimeout = config.timeoutSeconds;
    tor.init(torCfg);
    
    TorFetch fetcher;
    fetcher.setTorEngine(&tor);
    fetcher.setTimeout(config.timeoutSeconds);
    fetcher.setMaxBytes(config.maxPageSize);
    fetcher.init(torCfg);
    
    DeepSearchWrapper deep;
    auto searchResults = deep.search(query, routes, fetcher, config.maxResultsPerEngine);
    results.insert(results.end(), searchResults.begin(), searchResults.end());
    
    std::string lowerQuery = query;
    std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(), ::tolower);
    bool wantsForum = lowerQuery.find("dread") != std::string::npos ||
                      lowerQuery.find("forum") != std::string::npos ||
                      lowerQuery.find("discussion") != std::string::npos ||
                      lowerQuery.find("thread") != std::string::npos;
    
    if (wantsForum) {
        HtmlExtractor extractor;
        ForumCrawler crawler;
        auto forumResults = crawler.crawl(query, fetcher, extractor, config.maxResultsPerEngine);
        results.insert(results.end(), forumResults.begin(), forumResults.end());
    }
    
    auto fetchStats = fetcher.getStats();
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        impl_->stats.darknetSearches++;
        impl_->stats.successfulFetches += fetchStats.successes;
        impl_->stats.failedFetches += fetchStats.failures;
        impl_->stats.bytesDownloaded += fetchStats.bytes;
    }
    
    return results;
}

void WebSearch::setConfig(const SearchConfig& config) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->config = config;
}

SearchConfig WebSearch::getConfig() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->config;
}

void WebSearch::addClearnetEngine(SearchEngine engine) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->config.clearnetEngines.push_back(engine);
}

void WebSearch::addDarknetEngine(SearchEngine engine) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->config.darknetEngines.push_back(engine);
}

void WebSearch::addCustomEngine(const std::string& url, bool isDarknet) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (isDarknet) {
        impl_->config.customDarknetUrls.push_back(url);
    } else {
        impl_->config.customClearnetUrls.push_back(url);
    }
}

void WebSearch::removeEngine(SearchEngine engine) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    auto& clearnet = impl_->config.clearnetEngines;
    auto& darknet = impl_->config.darknetEngines;
    clearnet.erase(std::remove(clearnet.begin(), clearnet.end(), engine), clearnet.end());
    darknet.erase(std::remove(darknet.begin(), darknet.end(), engine), darknet.end());
}

void WebSearch::setMaxResults(size_t count) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->config.maxResultsPerEngine = count;
}

void WebSearch::setTimeout(uint32_t seconds) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->config.timeoutSeconds = seconds;
}

void WebSearch::onSearchComplete(std::function<void(const std::vector<SearchResult>&)> callback) {
    impl_->searchCallback = callback;
}

void WebSearch::onSearchError(std::function<void(const std::string&)> callback) {
    impl_->errorCallback = callback;
}

WebStats WebSearch::getStats() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->stats;
}

std::string urlEncode(const std::string& str) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    
    for (char c : str) {
        if (isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else if (c == ' ') {
            escaped << '+';
        } else {
            escaped << '%' << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c));
        }
    }
    
    return escaped.str();
}

std::string urlDecode(const std::string& str) {
    std::string result;
    for (size_t i = 0; i < str.size(); i++) {
        if (str[i] == '%' && i + 2 < str.size()) {
            int value;
            std::istringstream iss(str.substr(i + 1, 2));
            if (iss >> std::hex >> value) {
                result += static_cast<char>(value);
                i += 2;
            } else {
                result += str[i];
            }
        } else if (str[i] == '+') {
            result += ' ';
        } else {
            result += str[i];
        }
    }
    return result;
}

bool isOnionUrl(const std::string& url) {
    std::string host = url;
    size_t schemePos = host.find("://");
    if (schemePos != std::string::npos) {
        host = host.substr(schemePos + 3);
    }
    size_t slash = host.find('/');
    if (slash != std::string::npos) {
        host = host.substr(0, slash);
    }
    size_t colon = host.find(':');
    if (colon != std::string::npos) {
        host = host.substr(0, colon);
    }
    if (host.size() <= 6) return false;
    if (host.size() != 62) return host.find(".onion") != std::string::npos;
    if (host.substr(host.size() - 6) != ".onion") return false;
    std::string stem = host.substr(0, host.size() - 6);
    if (stem.size() != 56) return false;
    for (char c : stem) {
        if (!(c >= 'a' && c <= 'z') && !(c >= '2' && c <= '7')) {
            return false;
        }
    }
    return true;
}

bool isValidUrl(const std::string& url) {
    if (url.empty()) return false;
    if (url.substr(0, 7) != "http://" && url.substr(0, 8) != "https://") return false;
    return true;
}

std::string extractDomain(const std::string& url) {
    size_t start = url.find("://");
    if (start == std::string::npos) return "";
    start += 3;
    
    size_t end = url.find('/', start);
    if (end == std::string::npos) end = url.length();
    
    return url.substr(start, end - start);
}

std::string normalizeUrl(const std::string& url) {
    std::string normalized = url;
    
    if (!normalized.empty() && normalized.back() == '/') {
        normalized.pop_back();
    }
    
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::tolower);
    
    return normalized;
}

}
}
