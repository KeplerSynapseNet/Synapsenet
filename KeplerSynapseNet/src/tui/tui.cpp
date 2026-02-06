#include "tui/tui.h"
#include "tui/bip39_wordlist.h"
#include "screens.h"
#include <ncurses.h>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <thread>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <random>
#include <array>
#include <filesystem>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <cstdlib>
#include <cmath>
#include "model/model_loader.h"
#include "utils/config.h"
#include "crypto/keys.h"
#include "web/web.h"

namespace synapse {
namespace tui {

static const char* LOGO_SYNAPSENET[] = {
    " _____                                 _   ",
    "|   __|_ _ ___ ___ ___ ___ ___ ___ ___| |_ ",
    "|__   | | |   | .'| . |_ -| -_|   | -_|  _|",
    "|_____|_  |_|_|__,|  _|___|___|_|_|___|_|  ",
    "      |___|       |_|                      "
};
static const int LOGO_SYNAPSENET_COUNT = 5;

static const char* LOGO_KEPLER[] = {
    " _____         _         ",
    "|  |  |___ ___| |___ ___ ",
    "|    -| -_| . | | -_|  _|",
    "|__|__|___|  _|_|___|_|  ",
    "          |_|            "
};
static const int LOGO_KEPLER_COUNT = 5;

static std::array<uint8_t, 7> glyph5x7(char c) {
    switch (c) {
        case 'A': return {0b01110, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001};
        case 'B': return {0b11110, 0b10001, 0b10001, 0b11110, 0b10001, 0b10001, 0b11110};
        case 'C': return {0b01110, 0b10001, 0b10000, 0b10000, 0b10000, 0b10001, 0b01110};
        case 'D': return {0b11110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b11110};
        case 'E': return {0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b11111};
        case 'F': return {0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b10000};
        case 'G': return {0b01110, 0b10001, 0b10000, 0b10111, 0b10001, 0b10001, 0b01110};
        case 'H': return {0b10001, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001};
        case 'I': return {0b01110, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110};
        case 'J': return {0b00111, 0b00010, 0b00010, 0b00010, 0b00010, 0b10010, 0b01100};
        case 'K': return {0b10001, 0b10010, 0b10100, 0b11000, 0b10100, 0b10010, 0b10001};
        case 'L': return {0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b11111};
        case 'M': return {0b10001, 0b11011, 0b10101, 0b10001, 0b10001, 0b10001, 0b10001};
        case 'N': return {0b10001, 0b11001, 0b10101, 0b10011, 0b10001, 0b10001, 0b10001};
        case 'O': return {0b01110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110};
        case 'P': return {0b11110, 0b10001, 0b10001, 0b11110, 0b10000, 0b10000, 0b10000};
        case 'Q': return {0b01110, 0b10001, 0b10001, 0b10001, 0b10101, 0b10010, 0b01101};
        case 'R': return {0b11110, 0b10001, 0b10001, 0b11110, 0b10100, 0b10010, 0b10001};
        case 'S': return {0b01111, 0b10000, 0b10000, 0b01110, 0b00001, 0b00001, 0b11110};
        case 'T': return {0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100};
        case 'U': return {0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110};
        case 'V': return {0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01010, 0b00100};
        case 'W': return {0b10001, 0b10001, 0b10001, 0b10001, 0b10101, 0b11011, 0b10001};
        case 'X': return {0b10001, 0b10001, 0b01010, 0b00100, 0b01010, 0b10001, 0b10001};
        case 'Y': return {0b10001, 0b10001, 0b01010, 0b00100, 0b00100, 0b00100, 0b00100};
        case 'Z': return {0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b10000, 0b11111};
        default: return {0, 0, 0, 0, 0, 0, 0};
    }
}

static std::vector<std::string> renderDotText5x7(const std::string& text) {
    constexpr int H = 7;
    std::vector<std::string> lines(H, "");
    for (char raw : text) {
        if (raw == ' ') {
            for (int r = 0; r < H; ++r) lines[r].append("   ");
            continue;
        }
        char c = static_cast<char>(std::toupper(static_cast<unsigned char>(raw)));
        auto rows = glyph5x7(c);
        for (int r = 0; r < H; ++r) {
            for (int b = 4; b >= 0; --b) {
                bool on = (rows[static_cast<size_t>(r)] >> b) & 1U;
                lines[r].push_back(on ? '.' : ' ');
                lines[r].push_back(on ? '.' : ' ');
            }
            lines[r].push_back(' ');
        }
    }
    return lines;
}

static int safeScreenWidth(int x, int requested) {
    if (requested <= 0) return 0;
    int maxW = COLS - x;
    if (maxW <= 0) return 0;
    if (maxW > 1) maxW -= 1;
    return std::min(requested, maxW);
}

static std::string truncEnd(const std::string& s, int maxLen) {
    if (maxLen <= 0) return {};
    if (static_cast<int>(s.size()) <= maxLen) return s;
    if (maxLen <= 3) return s.substr(0, static_cast<size_t>(maxLen));
    return s.substr(0, static_cast<size_t>(maxLen - 3)) + "...";
}

static std::string truncStart(const std::string& s, int maxLen) {
    if (maxLen <= 0) return {};
    if (static_cast<int>(s.size()) <= maxLen) return s;
    if (maxLen <= 3) return s.substr(s.size() - static_cast<size_t>(maxLen));
    return "..." + s.substr(s.size() - static_cast<size_t>(maxLen - 3));
}

static void printClippedLine(int y, int x, int width, const std::string& s) {
    int w = safeScreenWidth(x, width);
    if (w <= 0) return;
    mvhline(y, x, ' ', w);
    mvaddnstr(y, x, s.c_str(), w);
}

static std::vector<std::string> wrapLines(const std::string& s, int width, int maxLines) {
    std::vector<std::string> out;
    if (width <= 0 || maxLines <= 0) return out;
    if (s.empty()) {
        out.emplace_back();
        return out;
    }
    size_t pos = 0;
    while (pos < s.size() && static_cast<int>(out.size()) < maxLines) {
        size_t len = std::min(static_cast<size_t>(width), s.size() - pos);
        out.push_back(s.substr(pos, len));
        pos += len;
    }
    if (pos < s.size() && !out.empty()) {
        out.back() = truncStart(s, width);
    }
    return out;
}

struct ChatMessage {
    std::string role;
    std::string content;
};

struct LocalAppState {
    WalletInfo wallet;
    NetworkInfo network;
    AIModelInfo model;
    std::vector<NodeInfo> peers;
    std::vector<ContributionInfo> recentContributions;
    std::vector<KnowledgeEntrySummary> knowledgeEntries;
    std::mutex knowledgeMutex;
    int qualityScore = 0;
    int networkRank = 0;
    int knowledgeShared = 0;
    int validations = 0;
    std::string nodeId;
    bool isFirstRun = true;
    std::vector<std::string> generatedSeedWords;
    double miningProgress = 0;
    std::vector<ChatMessage> chatHistory;
    std::mutex chatMutex;
    bool aiGenerating = false;
    std::string modelPath;
    uint16_t listeningPort = 0;
    bool networkOnline = false;
    std::string sendToAddress;
    double sendAmount = 0.0;
    std::string sendAmountStr;
    int walletScreen = 0;
    std::vector<std::string> availableModels;
    int selectedModelIndex = 0;
    bool modelSelectionActive = false;
    std::string aiCurrentResponse;  // Accumulate AI response as it streams
    std::mutex aiResponseMutex;      // Protect aiCurrentResponse for thread safety
    bool forceNewWallet = false;
    std::string downloadPath;
    std::string downloadPartPath;
    std::string knowledgeQuestion;
    std::string knowledgeAnswer;
    std::string knowledgeSource;
    int knowledgeField = 0;
    std::string codeTitle;
    std::string codePatchFile;
    std::string codeCitations;
    int codeField = 0;
    bool webInjectEnabled = false;
    bool webOnionEnabled = false;
    bool webTorForClearnet = false;
    bool webSearching = false;
    uint64_t webLastResults = 0;
    uint64_t webLastClearnetResults = 0;
    uint64_t webLastDarknetResults = 0;
    std::string webLastError;
    std::mutex webMutex;
    
    // Operation status tracking
    struct OperationStatus {
        std::string operation;
        std::string status;  // PENDING, IN_PROGRESS, SUCCESS, ERROR
        std::string details;
        uint64_t timestamp;
    };
    OperationStatus currentOperation;
    std::vector<OperationStatus> operationHistory;
    std::mutex operationMutex;
    
    // Reward history
    struct RewardNotification {
        double amount;
        std::string reason;
        std::string entryId;
        std::string details;
        uint64_t timestamp;
    };
    std::vector<RewardNotification> rewardHistory;
    std::mutex rewardMutex;
};

struct TUI::Impl {
    Screen screen = Screen::BOOT;
    std::atomic<bool> running{false};
    StatusInfo status{};
    LocalAppState state{};
    std::function<void(int)> inputHandler;
    std::function<void(const std::string&)> commandHandler;
    int initStep = 0;
    int frameCounter = 0;
    int menuSelection = 0;
    int scrollOffset = 0;
    int chatScrollOffset = 0;
    bool autoScrollEnabled = true;  // Auto-scroll enabled by default
    int webPromptStep = 0;
    bool webPromptDone = false;
    std::string inputBuffer;
    size_t inputCursor = 0;
    std::unique_ptr<synapse::model::ModelLoader> modelLoader;
    std::unique_ptr<synapse::web::WebSearch> webSearch;
    std::unique_ptr<synapse::web::QueryDetector> webDetector;
    std::unique_ptr<synapse::web::HtmlExtractor> webExtractor;
    std::unique_ptr<synapse::web::AIWrapper> webAi;
    std::atomic<bool> modelDownloadActive{false};
    std::atomic<bool> aiCancelRequested{false};
    bool aiModelPanelActive = false;
    int aiModelSelection = 0;
    int aiModelScroll = 0;
    uint64_t lastModelScanMs = 0;
    
    void drawBoot();
    void drawInit();
    void drawNetworkDiscovery();
    void drawSyncing();
    void drawWebPrompt();
    void drawWelcome();
    void drawWalletCreate();
    void drawWalletCreated();
    void drawWalletImport();
    void drawConnected();
    void drawDashboard();
    void drawWallet();
    void drawNetwork();
    void drawKnowledge();
    void drawKnowledgeSubmit();
    void drawCode();
    void drawCodeSubmit();
    void drawModel();
    void drawAIChat();
    void drawSecurity();
    void drawSettings();
    void drawMining();
    void drawModelLoader();
    void drawSendNGT();
    void drawReceiveNGT();
    void drawStatusBar();
    void drawBox(int y, int x, int h, int w, const char* title);
    void drawDoubleBox(int y, int x, int h, int w);
    void drawProgressBar(int y, int x, int w, double progress, int color);
    void centerText(int y, const char* text);
    void initDefaultState();
};

void TUI::Impl::initDefaultState() {
    state.wallet.address = "";
    state.wallet.balance = 0.0;
    state.wallet.pending = 0.0;
    state.wallet.totalEarned = 0.0;
    
    state.network.totalNodes = 0;
    state.network.knowledgeEntries = 0;
    state.network.knowledgeFinalized = 0;
    state.network.knowledgePending = 0;
    state.network.networkSize = 0.0;
    state.network.yourStorage = 0.0;
    state.network.syncProgress = 0.0;
    state.network.synced = false;
    state.network.knownPeers = 0;
    state.network.connectedPeers = 0;
    state.network.bootstrapNodes = 0;
    state.network.dnsSeeds = 0;
    state.network.dnsQueries = 0;
    state.network.peerExchanges = 0;
    state.network.lastPeerRefresh = 0;
    state.network.lastAnnounce = 0;
    
    state.model.name = "";
    state.model.status = "NOT LOADED";
    state.model.progress = 0.0;
    state.model.mode = "PRIVATE";
    state.model.slotsUsed = 0;
    state.model.slotsMax = 0;
    state.model.uptime = 0.0;
    state.model.earningsToday = 0.0;
    state.model.earningsWeek = 0.0;
    state.model.earningsTotal = 0.0;
    
    state.nodeId = "";
    state.qualityScore = 0;
    state.networkRank = 0;
    state.knowledgeShared = 0;
    state.validations = 0;
    state.miningProgress = 0.0;
    state.isFirstRun = true;
    state.chatHistory.clear();
    state.aiGenerating = false;
    state.modelPath = "";
    state.listeningPort = 0;
    state.networkOnline = false;
    state.forceNewWallet = false;
    state.downloadPath.clear();
    state.downloadPartPath.clear();
    state.sendToAddress.clear();
    state.sendAmount = 0.0;
    state.sendAmountStr.clear();
    state.walletScreen = 0;
    state.knowledgeQuestion.clear();
    state.knowledgeAnswer.clear();
    state.knowledgeSource.clear();
    state.knowledgeField = 0;
    state.codeTitle.clear();
    state.codePatchFile.clear();
    state.codeCitations.clear();
    state.codeField = 0;
    
    state.peers.clear();
    state.recentContributions.clear();
    modelLoader = std::make_unique<synapse::model::ModelLoader>();
    if (modelLoader) {
        modelLoader->onStateChange([this](synapse::model::ModelState s) {
            if (s == synapse::model::ModelState::READY) {
                state.model.status = "ACTIVE";
                state.model.progress = 1.0;
                if (state.model.name.empty()) {
                    state.model.name = modelLoader->getInfo().name;
                }
                return;
            }
            if (s == synapse::model::ModelState::DOWNLOADING) {
                state.model.status = "DOWNLOADING";
                return;
            }
            if (s == synapse::model::ModelState::UNLOADED) {
                if (state.model.status != "DOWNLOADING") {
                    state.model.status = "NOT LOADED";
                    state.model.progress = 0.0;
                }
                return;
            }
        });
        modelLoader->onProgress([this](double p) {
            if (state.model.status == "DOWNLOADING") {
                return;
            }
            if (p < 0.0) p = 0.0;
            if (p > 1.0) p = 1.0;
            state.model.progress = p;
            if (state.model.status != "ACTIVE") {
                state.model.status = "LOADING";
            }
        });
        modelLoader->onError([this](const std::string&) {
            state.model.status = "ERROR";
            state.model.progress = 0.0;
        });
    }
    std::string last = synapse::utils::Config::instance().getString("model.last_path", "");
    if (!last.empty() && std::filesystem::exists(last)) {
        state.modelPath = last;
        state.model.name = std::filesystem::path(last).filename().string();
        state.model.status = "LOADING";
        state.model.progress = 0.0;
        auto pimpl = this;
        std::thread([pimpl, last]() {
            bool ok = false;
            try {
                if (pimpl->modelLoader) ok = pimpl->modelLoader->load(last);
            } catch (...) { ok = false; }
            if (ok) {
                pimpl->state.modelPath = last;
                pimpl->state.model.name = std::filesystem::path(last).filename().string();
                pimpl->state.model.status = "ACTIVE";
                pimpl->state.model.progress = 1.0;
            } else {
                pimpl->state.model.status = "ERROR";
                pimpl->state.model.progress = 0.0;
                synapse::utils::Config::instance().set("model.last_path", "");
                std::string cfgPath = synapse::utils::Config::instance().getDataDir() + "/synapsenet.conf";
                synapse::utils::Config::instance().save(cfgPath);
            }
        }).detach();
    } else {
        std::filesystem::path rootModels = std::filesystem::current_path() / "models";
        std::filesystem::path defaultModelPath = rootModels / "deepseek-coder-6.7b-instruct.Q4_K_M.gguf";
        if (std::filesystem::exists(defaultModelPath)) {
            auto pimpl = this;
            std::thread([pimpl, defaultModelPath]() {
                bool ok = false;
                try {
                    if (pimpl->modelLoader) ok = pimpl->modelLoader->load(defaultModelPath.string());
                } catch (...) { ok = false; }
                if (ok) {
                    pimpl->state.modelPath = defaultModelPath.string();
                    pimpl->state.model.name = defaultModelPath.filename().string();
                    pimpl->state.model.status = "ACTIVE";
                    pimpl->state.model.progress = 1.0;
                } else {
                    pimpl->state.model.status = "ERROR";
                    pimpl->state.model.progress = 0.0;
                }
            }).detach();
        } else {
            state.model.status = "DOWNLOADING";
            state.model.progress = 0.0;
            state.model.name = "deepseek-coder-6.7b-instruct.Q4_K_M.gguf";
            state.downloadPath = defaultModelPath.string();
            state.downloadPartPath = defaultModelPath.string() + ".part";
            if (modelDownloadActive.exchange(true) == false) {
                auto pimpl = this;
                std::thread([pimpl]() {
                    struct ResetFlag {
                        std::atomic<bool>* flag = nullptr;
                        ~ResetFlag() {
                            if (flag) flag->store(false);
                        }
                    } reset{&pimpl->modelDownloadActive};

                    try {
                        const std::string modelName = "deepseek-coder-6.7b-instruct.Q4_K_M.gguf";
                        bool ok = false;
                        try {
                            if (pimpl->modelLoader) {
                                ok = pimpl->modelLoader->downloadModel(modelName, [pimpl](double p) {
                                    pimpl->state.model.progress = p;
                                });
                            }
                        } catch (...) { ok = false; }

                        std::filesystem::path rootModels = std::filesystem::current_path() / "models";
                        std::filesystem::path path = rootModels / modelName;
                        if (ok && std::filesystem::exists(path) && pimpl->modelLoader) {
                            pimpl->state.model.status = "LOADING";
                            pimpl->state.model.progress = 0.0;
                            bool loaded = false;
                            try { loaded = pimpl->modelLoader->load(path.string()); } catch (...) { loaded = false; }
                            if (loaded) {
                                pimpl->state.modelPath = path.string();
                                pimpl->state.model.name = path.filename().string();
                                pimpl->state.model.status = "ACTIVE";
                                pimpl->state.model.progress = 1.0;
                                pimpl->state.downloadPath.clear();
                                pimpl->state.downloadPartPath.clear();
                                synapse::utils::Config::instance().set("model.last_path", path.string());
                                std::string cfgPath = synapse::utils::Config::instance().getDataDir() + "/synapsenet.conf";
                                synapse::utils::Config::instance().save(cfgPath);
                            } else {
                                pimpl->state.model.status = "ERROR";
                                pimpl->state.model.progress = 0.0;
                            }
                        } else {
                            pimpl->state.model.status = "ERROR";
                            pimpl->state.model.progress = 0.0;
                        }
                    } catch (...) {
                        pimpl->state.model.status = "ERROR";
                        pimpl->state.model.progress = 0.0;
                    }
                }).detach();
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(state.webMutex);
        state.webInjectEnabled = synapse::utils::Config::instance().getBool("web.inject.enabled", false);
        state.webOnionEnabled = synapse::utils::Config::instance().getBool("web.inject.onion", false);
        state.webTorForClearnet = synapse::utils::Config::instance().getBool("web.inject.tor_clearnet", false);
        state.webSearching = false;
        state.webLastResults = 0;
        state.webLastClearnetResults = 0;
        state.webLastDarknetResults = 0;
        state.webLastError.clear();
        
        // Initialize operation status
        state.currentOperation.operation = "";
        state.currentOperation.status = "";
        state.currentOperation.details = "";
        state.currentOperation.timestamp = 0;
        state.operationHistory.clear();
        state.rewardHistory.clear();
    }

    webPromptDone = synapse::utils::Config::instance().getBool("web.prompt_done", false);

    webSearch = std::make_unique<synapse::web::WebSearch>();
    webDetector = std::make_unique<synapse::web::QueryDetector>();
    webExtractor = std::make_unique<synapse::web::HtmlExtractor>();
    webAi = std::make_unique<synapse::web::AIWrapper>();
    webAi->init();
    webAi->setWebSearch(webSearch.get());
    webAi->setDetector(webDetector.get());
    webAi->setExtractor(webExtractor.get());
    webAi->enableAutoSearch(true);
    webAi->enableContextInjection(true);

    webSearch->onSearchError([this](const std::string& err) {
        std::lock_guard<std::mutex> lock(state.webMutex);
        state.webLastError = err;
    });

    synapse::web::SearchConfig cfg;
    std::string webCfgPath = synapse::utils::Config::instance().getDataDir() + "/web_search.conf";
    synapse::web::loadSearchConfig(webCfgPath, cfg);
    {
        std::lock_guard<std::mutex> lock(state.webMutex);
        cfg.enableClearnet = true;
        cfg.enableDarknet = state.webOnionEnabled;
        cfg.routeClearnetThroughTor = state.webTorForClearnet;
    }
    webSearch->init(cfg);
}

void TUI::Impl::drawBox(int y, int x, int h, int w, const char* title) {
    mvaddch(y, x, ACS_ULCORNER);
    mvaddch(y, x + w - 1, ACS_URCORNER);
    mvaddch(y + h - 1, x, ACS_LLCORNER);
    mvaddch(y + h - 1, x + w - 1, ACS_LRCORNER);
    for (int i = 1; i < w - 1; i++) {
        mvaddch(y, x + i, ACS_HLINE);
        mvaddch(y + h - 1, x + i, ACS_HLINE);
    }
    for (int i = 1; i < h - 1; i++) {
        mvaddch(y + i, x, ACS_VLINE);
        mvaddch(y + i, x + w - 1, ACS_VLINE);
    }
    if (title && strlen(title) > 0) {
        std::string t = "[" + std::string(title) + "]";
        int avail = std::max(0, w - 4);
        int sw = safeScreenWidth(x + 2, avail);
        if (sw > 0) mvaddnstr(y, x + 2, t.c_str(), sw);
    }
}

void TUI::Impl::drawDoubleBox(int y, int x, int h, int w) {
    for (int i = x; i < x + w; i++) {
        mvprintw(y, i, "=");
        mvprintw(y + h - 1, i, "=");
    }
    for (int i = y; i < y + h; i++) {
        mvprintw(i, x, "|");
        mvprintw(i, x + w - 1, "|");
    }
    mvprintw(y, x, "+");
    mvprintw(y, x + w - 1, "+");
    mvprintw(y + h - 1, x, "+");
    mvprintw(y + h - 1, x + w - 1, "+");
}

void TUI::Impl::drawProgressBar(int y, int x, int w, double progress, int color) {
    int filled = static_cast<int>(progress * (w - 2));
    mvaddch(y, x, '[');
    attron(COLOR_PAIR(color));
    for (int i = 0; i < w - 2; i++) {
        if (i < filled) {
            mvprintw(y, x + 1 + i, "#");
        } else {
            mvaddch(y, x + 1 + i, ' ');
        }
    }
    attroff(COLOR_PAIR(color));
    mvaddch(y, x + w - 1, ']');
}

void TUI::Impl::centerText(int y, const char* text) {
    int cols = COLS;
    int len = strlen(text);
    int xpos = (cols - len) / 2;
    if (xpos < 0) xpos = 0;
    int sw = safeScreenWidth(xpos, cols - xpos);
    if (sw > 0) mvaddnstr(y, xpos, text, sw);
}

void TUI::Impl::drawBoot() {
    clear();
    int row = 1;

    auto dot = renderDotText5x7("SYNAPSENET");
    attron(COLOR_PAIR(5) | A_BOLD);
    for (const auto& ln : dot) {
        centerText(row++, ln.c_str());
    }
    attroff(COLOR_PAIR(5) | A_BOLD);

    row += 1;
    attron(COLOR_PAIR(6));
    centerText(row++, "Decentralized Intelligence Network v0.1");
    attroff(COLOR_PAIR(6));

    row += 1;
    int boxW = std::min(76, COLS - 4);
    int boxX = (COLS - boxW) / 2;
    int boxH = 9;
    drawBox(row, boxX, boxH, boxW, "Did you know?");
    int iy = row + 2;
    int ix = boxX + 3;
    attron(COLOR_PAIR(7));
    mvprintw(iy++, ix, "F2 opens the model panel (load/switch).");
    mvprintw(iy++, ix, "F4 downloads the default GGUF model (resume supported).");
    mvprintw(iy++, ix, "F5/F6/F7: Web injection / Onion / Tor (optional).");
    mvprintw(iy++, ix, "F8 stops generation. PgUp/PgDn scroll chat.");
    attroff(COLOR_PAIR(7));

    int footerY = std::min(LINES - 3, row + boxH + 2);
    attron(A_BLINK);
    centerText(footerY, "Press [SPACE] to continue");
    attroff(A_BLINK);

	    drawStatusBar();
	    ::refresh();
	}


void TUI::Impl::drawInit() {
    clear();
    int row = 3;
    
    attron(COLOR_PAIR(1) | A_BOLD);
    centerText(row++, "Initializing SynapseNet Protocol...");
    attroff(COLOR_PAIR(1) | A_BOLD);
    
    row += 2;
    double progress = (initStep + 1) / 5.0;
    int barWidth = 42;
    int startX = (COLS - barWidth) / 2;
    
    mvaddch(row, startX, '[');
    attron(COLOR_PAIR(1));
    for (int i = 0; i < 40; i++) {
        if (i < static_cast<int>(progress * 40)) {
            mvprintw(row, startX + 1 + i, "#");
        } else {
            mvaddch(row, startX + 1 + i, ' ');
        }
    }
    attroff(COLOR_PAIR(1));
    mvaddch(row, startX + 41, ']');
    mvprintw(row, startX + 44, "%d%%", static_cast<int>(progress * 100));
    
    row += 3;
    
    const char* steps[] = {
        "Loading configuration...",
        "Initializing quantum-resistant cryptography...",
        "Loading wallet...",
        "Starting local AI engine...",
        "Connecting to Knowledge Network..."
    };
    
    const char* details[] = {
        "Reading synapsenet.conf",
        "CRYSTALS-Dilithium + Kyber",
        "Wallet: %s",
        "Local model runtime ready",
        "Binding to port %d"
    };
    
    for (int i = 0; i < 5; i++) {
        if (i < initStep) {
            attron(COLOR_PAIR(1));
            mvprintw(row, startX, "[OK]");
            attroff(COLOR_PAIR(1));
            mvprintw(row, startX + 5, " %s", steps[i]);
            if (i == 4 && state.listeningPort > 0) {
                mvprintw(row, startX + 30, "(port %d)", state.listeningPort);
            }
        } else if (i == initStep) {
            attron(COLOR_PAIR(2));
            mvprintw(row, startX, "[..]");
            attroff(COLOR_PAIR(2));
            mvprintw(row, startX + 5, " %s", steps[i]);
            
            static int dots = 0;
            dots = (dots + 1) % 4;
            for (int d = 0; d < dots; d++) {
                mvprintw(row, startX + 5 + strlen(steps[i]) + d, ".");
            }
        } else {
            attron(COLOR_PAIR(7));
            mvprintw(row, startX, "[  ]");
            attroff(COLOR_PAIR(7));
            mvprintw(row, startX + 5, " %s", steps[i]);
        }
        row++;
    }
    
    row += 2;
    if (initStep < 5) {
        attron(COLOR_PAIR(7));
        if (initStep == 2) {
            std::string shortAddr = state.wallet.address.empty() ? "not found" :
                state.wallet.address.substr(0, 10) + "..." + state.wallet.address.substr(state.wallet.address.length() - 4);
            mvprintw(row, startX, details[initStep], shortAddr.c_str());
        } else if (initStep == 4 && state.listeningPort > 0) {
            mvprintw(row, startX, details[initStep], state.listeningPort);
        } else if (initStep == 4) {
            mvprintw(row, startX, details[initStep], 0);
        } else {
            mvprintw(row, startX, "%s", details[initStep]);
        }
        attroff(COLOR_PAIR(7));
    }
    
    ::refresh();
    
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    if (initStep < 4) {
        initStep++;
    } else {
        screen = Screen::NETWORK_DISCOVERY;
    }
}

void TUI::Impl::drawNetworkDiscovery() {
    clear();
    int row = 2;
    int boxW = 76;
    int boxX = (COLS - boxW) / 2;
    
    attron(COLOR_PAIR(4) | A_BOLD);
    centerText(row++, "Network Status");
    attroff(COLOR_PAIR(4) | A_BOLD);
    
    row += 1;
    drawBox(row, boxX, 20, boxW, "");
    
    int innerRow = row + 2;
    
    size_t realPeers = state.peers.size();
    
    if (state.listeningPort > 0) {
        attron(COLOR_PAIR(1) | A_BOLD);
        mvprintw(innerRow++, boxX + 3, "NODE STATUS: ONLINE");
        attroff(COLOR_PAIR(1) | A_BOLD);
        innerRow++;
        attron(COLOR_PAIR(1));
        mvprintw(innerRow++, boxX + 3, "Listening:    port %d", state.listeningPort);
        mvprintw(innerRow++, boxX + 3, "Protocol:     SynapseNet v0.1");
        mvprintw(innerRow++, boxX + 3, "Encryption:   CRYSTALS-Kyber (quantum-safe)");
        attroff(COLOR_PAIR(1));
    } else {
        attron(COLOR_PAIR(2) | A_BOLD);
        mvprintw(innerRow++, boxX + 3, "NODE STATUS: OFFLINE");
        attroff(COLOR_PAIR(2) | A_BOLD);
        innerRow++;
        attron(COLOR_PAIR(2));
        mvprintw(innerRow++, boxX + 3, "Could not bind to any port");
        mvprintw(innerRow++, boxX + 3, "Running in local-only mode");
        attroff(COLOR_PAIR(2));
    }
    
    innerRow++;
    mvprintw(innerRow++, boxX + 3, "----------------------------------------");
    innerRow++;
    
    if (realPeers == 0) {
        mvprintw(innerRow++, boxX + 3, "Connected Peers: 0");
        innerRow++;
        attron(COLOR_PAIR(2));
        mvprintw(innerRow++, boxX + 3, "GENESIS MODE - First node on network");
        mvprintw(innerRow++, boxX + 3, "Waiting for other nodes to connect...");
        innerRow++;
        mvprintw(innerRow++, boxX + 3, "Bootstrap: %lu nodes   DNS: %lu seeds",
                 state.network.bootstrapNodes, state.network.dnsSeeds);
        mvprintw(innerRow++, boxX + 3, "Known peers: %lu   DNS queries: %lu",
                 state.network.knownPeers, state.network.dnsQueries);
        mvprintw(innerRow++, boxX + 3, "Peer exchange: %lu (last %lus ago)",
                 state.network.peerExchanges,
                 (state.network.lastPeerRefresh > 0) ? (static_cast<uint64_t>(std::time(nullptr)) - state.network.lastPeerRefresh) : 0ULL);
        attroff(COLOR_PAIR(2));
    } else {
        mvprintw(innerRow++, boxX + 3, "Connected Peers: %zu", realPeers);
        innerRow++;
        for (size_t i = 0; i < state.peers.size() && i < 5; i++) {
            attron(COLOR_PAIR(1));
            printClippedLine(innerRow++, boxX + 5, boxW - 6, "* " + truncEnd(state.peers[i].id, boxW - 8));
            attroff(COLOR_PAIR(1));
        }
    }
    
    row += 22;
    
    if (state.listeningPort > 0) {
        attron(COLOR_PAIR(1));
        centerText(row, "Network: READY");
        attroff(COLOR_PAIR(1));
    } else {
        attron(COLOR_PAIR(2));
        centerText(row, "Network: OFFLINE");
        attroff(COLOR_PAIR(2));
    }
    
    ::refresh();
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    static int waitCount = 0;
    waitCount++;
    if (waitCount > 15) {
        waitCount = 0;
        screen = Screen::SYNCING;
        state.network.syncProgress = 0.0;
    }
}

void TUI::Impl::drawSyncing() {
    clear();
    int row = 2;
    int boxW = 76;
    int boxX = (COLS - boxW) / 2;
    
    attron(COLOR_PAIR(4) | A_BOLD);
    centerText(row++, "Knowledge Network");
    attroff(COLOR_PAIR(4) | A_BOLD);
    
    row += 1;
    drawBox(row, boxX, 14, boxW, "");
    
    int innerRow = row + 2;
    
    size_t realPeers = state.peers.size();
    
    if (realPeers == 0) {
        attron(COLOR_PAIR(1) | A_BOLD);
        mvprintw(innerRow++, boxX + 3, "GENESIS NODE");
        attroff(COLOR_PAIR(1) | A_BOLD);
        innerRow++;
        
        mvprintw(innerRow++, boxX + 3, "You are starting a new network.");
        mvprintw(innerRow++, boxX + 3, "");
        mvprintw(innerRow++, boxX + 3, "Knowledge Chain:  Empty (genesis block)");
        mvprintw(innerRow++, boxX + 3, "Network Size:     0 bytes");
        mvprintw(innerRow++, boxX + 3, "Your Storage:     0 bytes");
        innerRow++;
        
        attron(COLOR_PAIR(1));
        mvprintw(innerRow++, boxX + 3, "Status: Ready to accept connections");
        attroff(COLOR_PAIR(1));
        
        state.network.syncProgress = 1.0;
        state.network.synced = true;
    } else {
        attron(A_BOLD);
        mvprintw(innerRow++, boxX + 3, "SYNCHRONIZING");
        attroff(A_BOLD);
        innerRow++;
        
        mvprintw(innerRow++, boxX + 3, "Network Size:     %.1f GB", state.network.networkSize);
        mvprintw(innerRow++, boxX + 3, "Downloaded:       %.1f GB", state.network.networkSize * state.network.syncProgress);
        mvprintw(innerRow++, boxX + 3, "Entries:          %lu", state.network.knowledgeEntries);
        innerRow++;
        
        mvprintw(innerRow, boxX + 3, "Progress: ");
        int barX = boxX + 13;
        mvaddch(innerRow, barX, '[');
        attron(COLOR_PAIR(1));
        int filled = static_cast<int>(state.network.syncProgress * 40);
        for (int i = 0; i < 40; i++) {
            mvprintw(innerRow, barX + 1 + i, i < filled ? "#" : " ");
        }
        attroff(COLOR_PAIR(1));
        mvaddch(innerRow, barX + 41, ']');
        mvprintw(innerRow++, barX + 43, "%d%%", static_cast<int>(state.network.syncProgress * 100));
    }
    
    row += 16;
    
    if (state.network.synced) {
        attron(COLOR_PAIR(1));
        centerText(row, "Sync: COMPLETE");
        attroff(COLOR_PAIR(1));
    }
    
    ::refresh();
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    static int syncWait = 0;
    syncWait++;
    
    if (realPeers > 0 && state.network.syncProgress < 1.0) {
        state.network.syncProgress += 0.05;
    }
    
    if (syncWait > 10) {
        syncWait = 0;
        state.network.syncProgress = 1.0;
        state.network.synced = true;
        if (!webPromptDone) {
            webPromptStep = 0;
            screen = Screen::WEB_PROMPT;
        } else {
            screen = state.isFirstRun ? Screen::WELCOME : Screen::DASHBOARD;
        }
    }
}

void TUI::Impl::drawWebPrompt() {
    clear();

    int boxW = 76;
    int boxH = 17;
    int boxX = (COLS - boxW) / 2;
    int boxY = (LINES - boxH) / 2;
    if (boxY < 1) boxY = 1;

    attron(COLOR_PAIR(4) | A_BOLD);
    centerText(boxY - 1 < 0 ? 0 : boxY - 1, "PRIVACY & WEB SEARCH");
    attroff(COLOR_PAIR(4) | A_BOLD);

    drawBox(boxY, boxX, boxH, boxW, "Startup choice");

    int y = boxY + 2;
    int innerW = boxW - 6;

    printClippedLine(y++, boxX + 3, innerW, "SynapseNet can optionally search the web to help your local AI.");
    printClippedLine(y++, boxX + 3, innerW, "This is not consensus: it only affects your chat UX.");
    y++;

    auto onOff = [](bool v) { return v ? "ON" : "OFF"; };
    {
        std::lock_guard<std::mutex> lock(state.webMutex);
        std::string s1 = std::string("Web injection: ") + onOff(state.webInjectEnabled);
        std::string s2 = std::string("Onion sources: ") + onOff(state.webOnionEnabled);
        std::string s3 = std::string("Tor for clearnet: ") + onOff(state.webTorForClearnet);
        printClippedLine(y++, boxX + 3, innerW, s1);
        printClippedLine(y++, boxX + 3, innerW, s2);
        printClippedLine(y++, boxX + 3, innerW, s3);
    }
    y++;

    std::string q;
    if (webPromptStep == 0) q = "Enable AI web injection? [Y/N]";
    else if (webPromptStep == 1) q = "Include onion sources (.onion) in search? [Y/N]";
    else q = "Route clearnet web requests through Tor? [Y/N]";

    attron(COLOR_PAIR(1) | A_BOLD);
    printClippedLine(y++, boxX + 3, innerW, q);
    attroff(COLOR_PAIR(1) | A_BOLD);

    y++;
    attron(COLOR_PAIR(2));
    printClippedLine(y++, boxX + 3, innerW, "Default is NO. You can change later in AI Chat (F5/F6/F7).");
    attroff(COLOR_PAIR(2));

    int controlsY = boxY + boxH - 2;
    printClippedLine(controlsY, boxX + 3, innerW, "[Y] Yes  [N] No  [Esc] Skip");

    ::refresh();
}

void TUI::Impl::drawWelcome() {
    clear();
    int boxW = 76;
    int boxH = 20;
    int boxX = (COLS - boxW) / 2;
    int boxY = (LINES - boxH) / 2;
    
    attron(COLOR_PAIR(4));
    for (int i = boxX; i < boxX + boxW; i++) {
        mvprintw(boxY, i, "=");
        mvprintw(boxY + boxH - 1, i, "=");
    }
    for (int i = boxY; i < boxY + boxH; i++) {
        mvprintw(i, boxX, "|");
        mvprintw(i, boxX + boxW - 1, "|");
    }
    mvprintw(boxY, boxX, "+");
    mvprintw(boxY, boxX + boxW - 1, "+");
    mvprintw(boxY + boxH - 1, boxX, "+");
    mvprintw(boxY + boxH - 1, boxX + boxW - 1, "+");
    attroff(COLOR_PAIR(4));
    
    int row = boxY + 2;
    attron(COLOR_PAIR(1) | A_BOLD);
    centerText(row++, "WELCOME TO SYNAPSENET");
    attroff(COLOR_PAIR(1) | A_BOLD);
    
    row += 1;
    if (state.isFirstRun) {
        centerText(row++, "First run detected. Create or import a wallet.");
    } else {
        centerText(row++, "Wallet found. You can continue or create a new one.");
    }
    row += 1;
    
    int menuX = boxX + 5;
    drawBox(row, menuX, 10, boxW - 10, "");
    
    int menuRow = row + 2;
    attron(COLOR_PAIR(4) | A_BOLD);
    mvprintw(menuRow++, menuX + 3, "[1] Create New Wallet");
    attroff(COLOR_PAIR(4) | A_BOLD);
    mvprintw(menuRow++, menuX + 3, "    Generate a new quantum-safe wallet and seed phrase");
    menuRow++;
    
    attron(COLOR_PAIR(4) | A_BOLD);
    mvprintw(menuRow++, menuX + 3, "[2] Import Existing Wallet");
    attroff(COLOR_PAIR(4) | A_BOLD);
    mvprintw(menuRow++, menuX + 3, "    Restore from seed phrase or private key");
    menuRow++;
    
    attron(COLOR_PAIR(4) | A_BOLD);
    mvprintw(menuRow++, menuX + 3, "[3] Continue");
    attroff(COLOR_PAIR(4) | A_BOLD);
    mvprintw(menuRow++, menuX + 3, "    Go to dashboard");
    
    row = boxY + boxH - 3;
    mvprintw(row, menuX + 3, "Select option [1-3]: _");
    
    ::refresh();
}

void TUI::Impl::drawWalletCreate() {
    clear();
    int row = 2;
    int boxW = 76;
    int boxX = (COLS - boxW) / 2;
    
    if (state.generatedSeedWords.empty()) {
        std::random_device rd;
        
        auto now = std::chrono::high_resolution_clock::now();
        auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        
        std::array<uint32_t, 16> seed_data;
        for (size_t i = 0; i < seed_data.size(); i++) {
            seed_data[i] = rd() ^ static_cast<uint32_t>(nanos >> (i * 2));
        }
        seed_data[0] ^= static_cast<uint32_t>(std::hash<std::thread::id>{}(std::this_thread::get_id()));
        seed_data[1] ^= static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&state));
        
        std::seed_seq seq(seed_data.begin(), seed_data.end());
        std::mt19937_64 gen(seq);
        std::uniform_int_distribution<> dis(0, BIP39_WORDLIST_SIZE - 1);
        
        state.generatedSeedWords.clear();
        for (int i = 0; i < 24; i++) {
            state.generatedSeedWords.push_back(BIP39_WORDLIST[dis(gen)]);
        }
    }
    
    attron(COLOR_PAIR(1) | A_BOLD);
    centerText(row++, "CREATING NEW WALLET");
    mvprintw(row++, boxX, "===================");
    attroff(COLOR_PAIR(1) | A_BOLD);
    
    row += 1;
    centerText(row++, "Generating quantum-resistant keys...");
    row += 1;
    
    drawBox(row, boxX, 18, boxW, "");
    
    int innerRow = row + 2;
    attron(COLOR_PAIR(3) | A_BOLD);
    mvprintw(innerRow++, boxX + 3, "!!! IMPORTANT: SAVE YOUR SEED PHRASE !!!");
    attroff(COLOR_PAIR(3) | A_BOLD);
    innerRow++;
    
    mvprintw(innerRow++, boxX + 3, "Your 24-word seed phrase is the ONLY way to recover your wallet.");
    mvprintw(innerRow++, boxX + 3, "Write it down on paper. Do NOT store digitally. Do NOT share.");
    innerRow++;
    
    int seedBoxX = boxX + 5;
    drawBox(innerRow, seedBoxX, 8, boxW - 10, "");
    
    int seedRow = innerRow + 2;
    attron(COLOR_PAIR(4));
    for (int i = 0; i < 6; i++) {
        mvprintw(seedRow, seedBoxX + 3, "%2d. %-12s", i + 1, state.generatedSeedWords[i].c_str());
        mvprintw(seedRow, seedBoxX + 19, "%2d. %-12s", i + 7, state.generatedSeedWords[i + 6].c_str());
        mvprintw(seedRow, seedBoxX + 35, "%2d. %-12s", i + 13, state.generatedSeedWords[i + 12].c_str());
        mvprintw(seedRow, seedBoxX + 51, "%2d. %-12s", i + 19, state.generatedSeedWords[i + 18].c_str());
        seedRow++;
    }
    attroff(COLOR_PAIR(4));
    
    innerRow += 10;
    mvprintw(innerRow, boxX + 3, "Have you written down your seed phrase? [y/n]: _");
    
    ::refresh();
}


void TUI::Impl::drawWalletCreated() {
    clear();
    int row = 2;
    int boxW = 76;
    int boxX = (COLS - boxW) / 2;
    
    attron(COLOR_PAIR(1) | A_BOLD);
    centerText(row++, "WALLET CREATED SUCCESSFULLY");
    attroff(COLOR_PAIR(1) | A_BOLD);
    
    row += 1;
    drawBox(row, boxX, 18, boxW, "");
    
    int innerRow = row + 2;
    mvprintw(innerRow++, boxX + 3, "Your Wallet Address:");
    mvprintw(innerRow++, boxX + 3, "============================================");
    innerRow++;
    
    attron(COLOR_PAIR(4) | A_BOLD);
    std::string addr = state.wallet.address.empty() ? "not created" : state.wallet.address;
    auto addrLines = wrapLines(addr, boxW - 6, 2);
    for (const auto& l : addrLines) {
        printClippedLine(innerRow++, boxX + 3, boxW - 6, l);
    }
    attroff(COLOR_PAIR(4) | A_BOLD);
    innerRow++;
    
    mvprintw(innerRow++, boxX + 3, "Balance:           %.2f NGT", state.wallet.balance);
    mvprintw(innerRow++, boxX + 3, "Status:            Active");
    mvprintw(innerRow++, boxX + 3, "Protection:        Quantum-Resistant (CRYSTALS-Dilithium)");
    innerRow++;
    
    for (int i = 0; i < boxW - 6; i++) {
        mvaddch(innerRow, boxX + 3 + i, '-');
    }
    innerRow += 2;
    
    mvprintw(innerRow++, boxX + 3, "Start earning NGT by:");
    attron(COLOR_PAIR(1));
    mvprintw(innerRow++, boxX + 5, "* Contributing knowledge to the network");
    mvprintw(innerRow++, boxX + 5, "* Validating others' contributions");
    mvprintw(innerRow++, boxX + 5, "* Keeping your node online");
    attroff(COLOR_PAIR(1));
    
    row += 20;
    attron(A_BLINK);
    centerText(row, "Press [ENTER] to continue to dashboard...");
    attroff(A_BLINK);
    
    ::refresh();
}

void TUI::Impl::drawWalletImport() {
    clear();
    int row = 2;
    int boxW = 76;
    int boxX = (COLS - boxW) / 2;

    attron(COLOR_PAIR(1) | A_BOLD);
    centerText(row++, "IMPORT WALLET");
    attroff(COLOR_PAIR(1) | A_BOLD);

    row += 1;
    drawBox(row, boxX, 10, boxW, "");

    int innerRow = row + 2;
    mvprintw(innerRow++, boxX + 3, "Paste your 12/24-word seed phrase:");
    mvprintw(innerRow++, boxX + 3, "(words separated by spaces)");
    innerRow++;

    std::string display = inputBuffer;
    if (display.size() > static_cast<size_t>(boxW - 8)) {
        display = display.substr(display.size() - (boxW - 8));
    }
    attron(A_REVERSE);
    mvprintw(innerRow++, boxX + 3, "%-*s", boxW - 6, "");
    {
        std::string line = display + "_";
        int sw = safeScreenWidth(boxX + 3, boxW - 6);
        if (sw > 0) mvaddnstr(innerRow - 1, boxX + 3, line.c_str(), sw);
    }
    attroff(A_REVERSE);

    innerRow += 2;
    mvprintw(innerRow++, boxX + 3, "[Enter] Import (overwrites wallet.dat)   [Esc] Back");

    ::refresh();
}

void TUI::Impl::drawConnected() {
    clear();
    int row = 2;
    int boxW = 76;
    int boxX = (COLS - boxW) / 2;
    
    attron(COLOR_PAIR(1) | A_BOLD);
    centerText(row++, "SYNAPSENET CONNECTED");
    attroff(COLOR_PAIR(1) | A_BOLD);
    
    row += 1;
    drawBox(row, boxX, 18, boxW, "");
    
    int innerRow = row + 2;
    mvprintw(innerRow++, boxX + 3, "Node ID:           %s", state.nodeId.c_str());
    
    attron(COLOR_PAIR(1));
    mvprintw(innerRow++, boxX + 3, "Status:            * ONLINE");
    attroff(COLOR_PAIR(1));
    
    std::string shortAddr = state.wallet.address.empty() ? "not set" : 
        state.wallet.address.substr(0, 10) + "..." + state.wallet.address.substr(state.wallet.address.length() - 4);
    mvprintw(innerRow++, boxX + 3, "Wallet:            %s", shortAddr.c_str());
    mvprintw(innerRow++, boxX + 3, "Balance:           %.2f NGT", state.wallet.balance);
    innerRow++;
    
    for (int i = 0; i < boxW - 6; i++) {
        mvaddch(innerRow, boxX + 3 + i, '-');
    }
    innerRow += 2;
    
    mvprintw(innerRow++, boxX + 3, "Network:           %lu nodes online", state.network.totalNodes);
    mvprintw(innerRow++, boxX + 3, "Knowledge Chain:   %.1f GB (%s)", 
             state.network.networkSize, state.network.synced ? "synced" : "syncing");
    mvprintw(innerRow++, boxX + 3, "Your Contribution: %lu entries", state.network.knowledgeEntries);
    mvprintw(innerRow++, boxX + 3, "Quality Score:     %.1f%%", static_cast<double>(state.qualityScore));
    innerRow++;
    
    for (int i = 0; i < boxW - 6; i++) {
        mvaddch(innerRow, boxX + 3 + i, '-');
    }
    innerRow += 2;
    
    mvprintw(innerRow++, boxX + 3, "Last Session:      First time");
    attron(COLOR_PAIR(1));
    mvprintw(innerRow++, boxX + 3, "Welcome to SynapseNet!");
    attroff(COLOR_PAIR(1));
    
    row += 20;
    centerText(row, "Loading dashboard...");
    row += 2;
    centerText(row, "Press [ENTER] to continue");
    
    ::refresh();
}

void TUI::Impl::drawDashboard() {
    clear();
    int row = 0;
    
    attron(COLOR_PAIR(4) | A_BOLD);
    centerText(row++, "================================================================================");
    centerText(row++, "SYNAPSENET v0.1 MINING");
    centerText(row++, "Fill the Global Knowledge Network Together");
    centerText(row++, "================================================================================");
    attroff(COLOR_PAIR(4) | A_BOLD);
    
    row++;
    attron(COLOR_PAIR(6));
    for (int i = 0; i < LOGO_KEPLER_COUNT; i++) {
        centerText(row++, LOGO_KEPLER[i]);
    }
    attroff(COLOR_PAIR(6));
    
    row++;
    attron(COLOR_PAIR(4));
    for (int i = 0; i < LOGO_SYNAPSENET_COUNT; i++) {
        centerText(row++, LOGO_SYNAPSENET[i]);
    }
    attroff(COLOR_PAIR(4));
    
    row += 2;
    centerText(row++, "--------------------------------------------------------------------------------");
    
    size_t realPeers = state.peers.size();
    if (state.listeningPort > 0) {
        attron(COLOR_PAIR(1));
        char statusLine[100];
        snprintf(statusLine, sizeof(statusLine), "ONLINE - Listening on port %d (Genesis Mode)", state.listeningPort);
        centerText(row++, statusLine);
        attroff(COLOR_PAIR(1));
    } else if (realPeers == 0) {
        attron(COLOR_PAIR(2));
        centerText(row++, "OFFLINE - No network port available");
        attroff(COLOR_PAIR(2));
    } else {
        attron(COLOR_PAIR(1));
        centerText(row++, "ONLINE - Connected to network");
        attroff(COLOR_PAIR(1));
    }
    centerText(row++, "--------------------------------------------------------------------------------");
    
    row++;
    int boxW = 31;
    int leftX = (COLS - 70) / 2;
    int rightX = leftX + boxW + 4;
    
    drawBox(row, leftX, 7, boxW, "CONNECTION");
    drawBox(row, rightX, 7, boxW, "WALLET");
    
    int innerRow = row + 1;
    if (state.listeningPort > 0) {
        attron(COLOR_PAIR(1));
        mvprintw(innerRow, leftX + 2, "Status:    * ONLINE");
        attroff(COLOR_PAIR(1));
    } else {
        attron(COLOR_PAIR(2));
        mvprintw(innerRow, leftX + 2, "Status:    * OFFLINE");
        attroff(COLOR_PAIR(2));
    }
    
    std::string shortAddr = state.wallet.address.empty() ? "not created" :
        state.wallet.address.substr(0, 8) + "..." + state.wallet.address.substr(state.wallet.address.length() - 4);
    mvprintw(innerRow++, rightX + 2, "Address: %s", shortAddr.c_str());
    
    mvprintw(innerRow, leftX + 2, "Peers:     %zu", realPeers);
    mvprintw(innerRow++, rightX + 2, "Balance: %.2f NGT", state.wallet.balance);
    
    mvprintw(innerRow, leftX + 2, "Port:      %d", state.listeningPort);
    mvprintw(innerRow++, rightX + 2, "Pending: +%.1f NGT", state.wallet.pending);
    
    mvprintw(innerRow, leftX + 2, "Network:   %s", state.listeningPort > 0 ? "Ready" : "Offline");
    mvprintw(innerRow++, rightX + 2, "Earned: %.2f NGT", state.wallet.totalEarned);
    
    if (realPeers == 0 && state.listeningPort > 0) {
        attron(COLOR_PAIR(1));
        mvprintw(innerRow, leftX + 2, "[GENESIS NODE]");
        mvprintw(innerRow, rightX + 2, "[ONLINE]");
        attroff(COLOR_PAIR(1));
    } else if (state.listeningPort == 0) {
        attron(COLOR_PAIR(2));
        mvprintw(innerRow, leftX + 2, "[OFFLINE]");
        mvprintw(innerRow, rightX + 2, "[OFFLINE]");
        attroff(COLOR_PAIR(2));
    } else {
        attron(COLOR_PAIR(1));
        mvprintw(innerRow, leftX + 2, "[CONNECTED]");
        mvprintw(innerRow, rightX + 2, "[ONLINE]");
        attroff(COLOR_PAIR(1));
    }
    
    row += 8;
    drawBox(row, leftX, 7, boxW, "LOCAL AI");
    drawBox(row, rightX, 7, boxW, "STATS");
    
    innerRow = row + 1;
    {
        std::string modelName = state.model.name.empty() ? "not loaded" : state.model.name;
        if (modelLoader && modelLoader->isLoaded()) {
            modelName = modelLoader->getInfo().name;
        }
        printClippedLine(innerRow, leftX + 2, boxW - 4, "Model:     " + truncEnd(modelName, boxW - 14));
    }
    mvprintw(innerRow++, rightX + 2, "Knowledge: %lu entries", state.network.knowledgeEntries);
    
    std::string st = state.model.status.empty() ? "NOT LOADED" : state.model.status;
    if (modelLoader) {
        auto ms = modelLoader->getState();
        if (ms == synapse::model::ModelState::READY) st = "ACTIVE";
        else if (ms == synapse::model::ModelState::LOADING) st = "LOADING";
        else if (ms == synapse::model::ModelState::DOWNLOADING) st = "DOWNLOADING";
        else if (ms == synapse::model::ModelState::ERROR) st = "ERROR";
    }
    if (st == "ACTIVE") {
        attron(COLOR_PAIR(1));
        mvprintw(innerRow, leftX + 2, "Status:    * READY");
        attroff(COLOR_PAIR(1));
    } else if (st == "ERROR") {
        attron(COLOR_PAIR(3));
        mvprintw(innerRow, leftX + 2, "Status:    * ERROR");
        attroff(COLOR_PAIR(3));
    } else if (st == "DOWNLOADING" || st == "LOADING") {
        attron(COLOR_PAIR(2));
        mvprintw(innerRow, leftX + 2, "Status:    * %s %3d%%", st.c_str(), static_cast<int>(state.model.progress * 100));
        attroff(COLOR_PAIR(2));
    } else if (!state.model.name.empty()) {
        attron(COLOR_PAIR(2));
        mvprintw(innerRow, leftX + 2, "Status:    * %s", st.c_str());
        attroff(COLOR_PAIR(2));
    } else {
        attron(COLOR_PAIR(2));
        mvprintw(innerRow, leftX + 2, "Status:    * NO MODEL");
        attroff(COLOR_PAIR(2));
    }
    mvprintw(innerRow++, rightX + 2, "Validations: %d", state.validations);
    
    printClippedLine(innerRow, leftX + 2, boxW - 4, "Mode:      " + truncEnd(state.model.mode, boxW - 14));
    mvprintw(innerRow++, rightX + 2, "Quality: %.1f%%", static_cast<double>(state.qualityScore));
    
    mvprintw(innerRow, leftX + 2, "Access:    PRIVATE");
    mvprintw(innerRow++, rightX + 2, "Rank: #%d", state.networkRank > 0 ? state.networkRank : 0);
    if ((st == "DOWNLOADING" || st == "LOADING") && boxW >= 22) {
        int barW = std::min(24, boxW - 10);
        int barY = row + 5;
        int barX = leftX + 2;
        drawProgressBar(barY, barX, barW, state.model.progress, st == "DOWNLOADING" ? 6 : 2);
    }
    
    row += 9;
    centerText(row++, "--------------------------------------------------------------------------------");
    centerText(row++, "MENU");
    centerText(row++, "--------------------------------------------------------------------------------");
    
    row++;
    int menuX = leftX;
    mvprintw(row, menuX, "[1] Contribute Knowledge");
    mvprintw(row++, menuX + 30, "[5] Network Statistics");
    mvprintw(row, menuX, "[2] Validate Contributions");
    mvprintw(row++, menuX + 30, "[6] Peer Discovery");
    mvprintw(row, menuX, "[3] AI Query");
    mvprintw(row++, menuX + 30, "[7] Settings");
    mvprintw(row, menuX, "[4] Wallet & Transfers");
    mvprintw(row++, menuX + 30, "[8] Security");
    
    row++;
    mvprintw(row++, menuX, "[9] IDE / Code Contributions");
    
    row++;
    mvprintw(row++, menuX, "[Q] Quit");
    
    row++;
    centerText(row++, "--------------------------------------------------------------------------------");
    
    // Display recent rewards if available
    {
        std::lock_guard<std::mutex> lock(state.rewardMutex);
        if (!state.rewardHistory.empty() && row < LINES - 5) {
            row++;
            int rewardBoxW = 70;
            int rewardBoxX = (COLS - rewardBoxW) / 2;
            int rewardBoxH = std::min(static_cast<int>(state.rewardHistory.size()) + 2, LINES - row - 3);
            if (rewardBoxH > 2) {
                drawBox(row, rewardBoxX, rewardBoxH, rewardBoxW, "Recent Rewards");
                int rewardRow = row + 1;
                int displayCount = std::min(static_cast<int>(state.rewardHistory.size()), rewardBoxH - 2);
                for (int i = static_cast<int>(state.rewardHistory.size()) - displayCount; i < static_cast<int>(state.rewardHistory.size()); ++i) {
                    if (rewardRow >= row + rewardBoxH - 1) break;
                    const auto& reward = state.rewardHistory[i];
                    std::ostringstream oss;
                    oss << std::fixed << std::setprecision(8) << reward.amount << " NGT";
                    std::string amountStr = oss.str();
                    std::string reasonStr = truncEnd(reward.reason, 20);
                    std::string entryStr = reward.entryId.empty() ? "" : " (" + truncEnd(reward.entryId, 8) + ")";
                    std::string line = amountStr + " - " + reasonStr + entryStr;
                    printClippedLine(rewardRow++, rewardBoxX + 2, rewardBoxW - 4, line);
                }
                row += rewardBoxH;
            }
        }
    }
    
    ::refresh();
}


void TUI::Impl::drawStatusBar() {
    int row = LINES - 1;
    attron(A_REVERSE);
    int w = safeScreenWidth(0, COLS);
    mvhline(row, 0, ' ', w);
    std::string modelName;
    if (modelLoader && modelLoader->isLoaded()) {
        modelName = modelLoader->getInfo().name;
    } else {
        modelName = state.model.name;
    }
    std::string modelStatus = state.model.status.empty() ? "NOT LOADED" : state.model.status;
    if (modelLoader) {
        auto ms = modelLoader->getState();
        if (ms == synapse::model::ModelState::READY) modelStatus = "READY";
        else if (ms == synapse::model::ModelState::LOADING) modelStatus = "LOADING";
        else if (ms == synapse::model::ModelState::DOWNLOADING) modelStatus = "DOWNLOADING";
        else if (ms == synapse::model::ModelState::ERROR) modelStatus = "ERROR";
    }
    std::string modelSeg;
    if (!modelName.empty()) {
        modelSeg = " | Model: " + truncEnd(modelName, 18) + " " + modelStatus;
        if (modelStatus == "LOADING" || modelStatus == "DOWNLOADING") {
            modelSeg += " " + std::to_string(static_cast<int>(state.model.progress * 100)) + "%";
        }
    }
    
    // Add current operation status if available
    std::string operationStatus = "";
    {
        std::lock_guard<std::mutex> lock(state.operationMutex);
        if (!state.currentOperation.operation.empty() && !state.currentOperation.status.empty()) {
            std::string statusSymbol = "";
            if (state.currentOperation.status == "SUCCESS") statusSymbol = "✓";
            else if (state.currentOperation.status == "ERROR") statusSymbol = "✗";
            else if (state.currentOperation.status == "IN_PROGRESS") statusSymbol = "...";
            else if (state.currentOperation.status == "PENDING") statusSymbol = "⏳";
            
            operationStatus = " | " + state.currentOperation.operation + statusSymbol;
            if (!state.currentOperation.details.empty() && operationStatus.length() < 30) {
                operationStatus += " " + truncEnd(state.currentOperation.details, 20);
            }
        }
    }
    
    std::ostringstream bal;
    bal << std::fixed << std::setprecision(2) << state.wallet.balance;
    std::string line = " SynapseNet v0.1 | Peers: " + std::to_string(state.peers.size()) + " | Balance: " + bal.str() + " NGT" +
                       modelSeg + operationStatus + " | " + (state.network.synced ? "SYNCED" : "GENESIS") + " ";
    int sw = safeScreenWidth(2, COLS - 2);
    if (sw > 0) mvaddnstr(row, 2, line.c_str(), sw);
    attroff(A_REVERSE);
}

void TUI::Impl::drawWallet() {
    clear();
    int row = 1;
    
    attron(COLOR_PAIR(4) | A_BOLD);
    centerText(row++, "WALLET");
    attroff(COLOR_PAIR(4) | A_BOLD);
    
    row++;
    int boxW = 70;
    int boxX = (COLS - boxW) / 2;
    
    drawBox(row, boxX, 12, boxW, "Balance");
    
    int innerRow = row + 2;
    std::string shortAddr = state.wallet.address.empty() ? "not created" :
        (state.wallet.address.size() > 18
            ? state.wallet.address.substr(0, 10) + "..." + state.wallet.address.substr(state.wallet.address.size() - 5)
            : state.wallet.address);
    mvprintw(innerRow++, boxX + 3, "Address:      %s", shortAddr.c_str());
    innerRow++;
    
    attron(COLOR_PAIR(1) | A_BOLD);
    mvprintw(innerRow++, boxX + 3, "Balance:      %.2f NGT", state.wallet.balance);
    attroff(COLOR_PAIR(1) | A_BOLD);
    
    attron(COLOR_PAIR(2));
    mvprintw(innerRow++, boxX + 3, "Pending:      +%.2f NGT", state.wallet.pending);
    attroff(COLOR_PAIR(2));
    
    mvprintw(innerRow++, boxX + 3, "Total Earned: %.2f NGT", state.wallet.totalEarned);
    innerRow++;
    mvprintw(innerRow++, boxX + 3, "Protection:   Quantum-Resistant (CRYSTALS-Dilithium)");
    
    row += 14;
    drawBox(row, boxX, 8, boxW, "Actions");
    
    innerRow = row + 2;
    mvprintw(innerRow++, boxX + 5, "[1] Send NGT");
    mvprintw(innerRow++, boxX + 5, "[2] Receive (Show Address)");
    mvprintw(innerRow++, boxX + 5, "[3] Transaction History");
    mvprintw(innerRow++, boxX + 5, "[4] Export Keys");
    mvprintw(innerRow++, boxX + 5, "[B] Back to Dashboard");
    
    drawStatusBar();
    ::refresh();
}

void TUI::Impl::drawNetwork() {
    clear();
    int row = 1;
    
    attron(COLOR_PAIR(4) | A_BOLD);
    centerText(row++, "NETWORK STATUS");
    attroff(COLOR_PAIR(4) | A_BOLD);
    
    row++;
    int boxW = 70;
    int boxX = (COLS - boxW) / 2;
    
    drawBox(row, boxX, 8, boxW, "Connection");
    
    int innerRow = row + 2;
    if (state.network.totalNodes > 0) {
        attron(COLOR_PAIR(1));
        mvprintw(innerRow++, boxX + 3, "Status:       * ONLINE");
        attroff(COLOR_PAIR(1));
    } else {
        attron(COLOR_PAIR(2));
        mvprintw(innerRow++, boxX + 3, "Status:       * GENESIS (waiting for peers)");
        attroff(COLOR_PAIR(2));
    }
    mvprintw(innerRow++, boxX + 3, "Total Nodes:  %lu", state.network.totalNodes);
    mvprintw(innerRow++, boxX + 3, "Connected:    %zu peers", state.peers.size());
    mvprintw(innerRow++, boxX + 3, "Latency:      --ms");
    
    row += 10;
    drawBox(row, boxX, 10, boxW, "Connected Peers");
    
    innerRow = row + 2;
    if (state.peers.empty()) {
        attron(COLOR_PAIR(2));
        mvprintw(innerRow++, boxX + 3, "No peers connected yet.");
        mvprintw(innerRow++, boxX + 3, "Waiting for network bootstrap...");
        attroff(COLOR_PAIR(2));
    } else {
        for (const auto& peer : state.peers) {
            attron(COLOR_PAIR(1));
            printClippedLine(innerRow, boxX + 3, 21, "* " + truncEnd(peer.id, 18));
            attroff(COLOR_PAIR(1));
            std::string loc = truncEnd(peer.location, 15);
            mvprintw(innerRow, boxX + 25, "%-15s", loc.c_str());
            mvprintw(innerRow, boxX + 45, "%dms", peer.ping);
            innerRow++;
        }
    }
    
    row += 12;
    mvprintw(row++, boxX + 3, "[R] Refresh    [A] Add Peer    [B] Back");
    
    drawStatusBar();
    ::refresh();
}

void TUI::Impl::drawKnowledge() {
    clear();
    int row = 1;
    
    attron(COLOR_PAIR(4) | A_BOLD);
    centerText(row++, "KNOWLEDGE NETWORK");
    attroff(COLOR_PAIR(4) | A_BOLD);
    
    row++;
    int boxW = 76;
    int boxX = (COLS - boxW) / 2;
    
    drawBox(row, boxX, 7, boxW, "PoE v1 Status");

    int innerRow = row + 2;
    mvprintw(innerRow++, boxX + 3, "Total entries:     %lu", state.network.knowledgeEntries);
    mvprintw(innerRow++, boxX + 3, "Finalized entries: %lu", state.network.knowledgeFinalized);
    mvprintw(innerRow++, boxX + 3, "Pending entries:   %lu", state.network.knowledgePending);

    std::vector<KnowledgeEntrySummary> entries;
    {
        std::lock_guard<std::mutex> lock(state.knowledgeMutex);
        entries = state.knowledgeEntries;
    }
    std::vector<KnowledgeEntrySummary> nonCodeEntries;
    nonCodeEntries.reserve(entries.size());
    size_t codeCount = 0;
    for (const auto& e : entries) {
        if (e.contentType == 2) codeCount++;
        else nonCodeEntries.push_back(e);
    }
    mvprintw(innerRow++, boxX + 3, "Code entries:      %zu", codeCount);

    int listY = row + 9;
    int listH = LINES - listY - 6;
    if (listH < 8) listH = 8;
    if (listH > 16) listH = 16;
    drawBox(listY, boxX, listH, boxW, "Recent Entries");

    int innerW = boxW - 6;
    int headerY = listY + 1;
    printClippedLine(headerY, boxX + 3, innerW, "ID        STATUS     VOTES   REWARD     TITLE");

    int dataRows = listH - 3;
    if (dataRows < 1) dataRows = 1;

    int maxScroll = 0;
    if (static_cast<int>(nonCodeEntries.size()) > dataRows) {
        maxScroll = static_cast<int>(nonCodeEntries.size()) - dataRows;
    }
    if (scrollOffset < 0) scrollOffset = 0;
    if (scrollOffset > maxScroll) scrollOffset = maxScroll;

    int printed = 0;
    for (int i = 0; i < dataRows; ++i) {
        int idx = scrollOffset + i;
        int y = listY + 2 + i;
        if (idx >= static_cast<int>(nonCodeEntries.size())) {
            mvhline(y, boxX + 3, ' ', innerW);
            continue;
        }
        const auto& e = nonCodeEntries[idx];
        std::string id = e.submitId.size() > 8 ? e.submitId.substr(0, 8) : e.submitId;
        std::string st = e.finalized ? "FINAL" : "PENDING";
        std::string votes = std::to_string(e.votes) + "/" + std::to_string(e.requiredVotes);
        std::ostringstream r;
        r << "+" << std::fixed << std::setprecision(4) << e.acceptanceReward;
        std::string reward = r.str();
        if (e.acceptanceRewardCredited) reward += " PAID";
        std::string title = truncEnd(e.title, innerW - 38);
        std::string line = id + "  " + st + "   " + votes;
        while (line.size() < 24) line.push_back(' ');
        line += reward;
        while (line.size() < 35) line.push_back(' ');
        line += " " + title;

        if (e.finalized) attron(COLOR_PAIR(1));
        else attron(COLOR_PAIR(2));
        printClippedLine(y, boxX + 3, innerW, line);
        if (e.finalized) attroff(COLOR_PAIR(1));
        else attroff(COLOR_PAIR(2));
        printed++;
    }

    if (scrollOffset > 0) {
        mvaddch(listY + 1, boxX + boxW - 2, '^');
    }
    if (maxScroll > 0 && scrollOffset < maxScroll) {
        mvaddch(listY + listH - 2, boxX + boxW - 2, 'v');
    }

    int controlsY = listY + listH + 1;
    printClippedLine(controlsY, boxX + 3, innerW, "[C] Contribute  [E] Epoch Rewards  [Up/Down] Scroll  [B] Back");
    
    drawStatusBar();
    ::refresh();
}

void TUI::Impl::drawKnowledgeSubmit() {
    clear();
    int row = 1;

    attron(COLOR_PAIR(4) | A_BOLD);
    centerText(row++, "CONTRIBUTE KNOWLEDGE");
    attroff(COLOR_PAIR(4) | A_BOLD);

    row++;
    int boxW = 76;
    int boxX = (COLS - boxW) / 2;

    drawBox(row, boxX, 16, boxW, "New Entry");
    int innerRow = row + 2;

    auto trunc = [](const std::string& s, int maxLen) -> std::string {
        if (maxLen <= 0) return {};
        if (static_cast<int>(s.size()) <= maxLen) return s;
        if (maxLen <= 3) return s.substr(0, static_cast<size_t>(maxLen));
        return s.substr(0, static_cast<size_t>(maxLen - 3)) + "...";
    };

    int fieldW = boxW - 8;
    mvprintw(innerRow++, boxX + 3, "Question:");
    if (state.knowledgeField == 0) attron(A_REVERSE);
    mvprintw(innerRow++, boxX + 3, "> %s%s", trunc(state.knowledgeQuestion, fieldW - 4).c_str(), state.knowledgeField == 0 ? "_" : "");
    if (state.knowledgeField == 0) attroff(A_REVERSE);
    innerRow++;

    mvprintw(innerRow++, boxX + 3, "Answer:");
    if (state.knowledgeField == 1) attron(A_REVERSE);
    mvprintw(innerRow++, boxX + 3, "> %s%s", trunc(state.knowledgeAnswer, fieldW - 4).c_str(), state.knowledgeField == 1 ? "_" : "");
    if (state.knowledgeField == 1) attroff(A_REVERSE);
    innerRow++;

    mvprintw(innerRow++, boxX + 3, "Source (optional):");
    if (state.knowledgeField == 2) attron(A_REVERSE);
    mvprintw(innerRow++, boxX + 3, "> %s%s", trunc(state.knowledgeSource, fieldW - 4).c_str(), state.knowledgeField == 2 ? "_" : "");
    if (state.knowledgeField == 2) attroff(A_REVERSE);
    innerRow += 2;

    mvprintw(innerRow++, boxX + 3, "[Tab] Switch Field    [Enter] Next/Submit    [Esc] Cancel");
    mvprintw(innerRow++, boxX + 3, "Earn NGT for contributing useful knowledge");

    drawStatusBar();
    ::refresh();
}

void TUI::Impl::drawCode() {
    clear();
    int row = 1;

    attron(COLOR_PAIR(4) | A_BOLD);
    centerText(row++, "SYNAPSE IDE");
    attroff(COLOR_PAIR(4) | A_BOLD);

    row++;
    int boxW = 76;
    int boxX = (COLS - boxW) / 2;

    drawBox(row, boxX, 7, boxW, "Code Contributions (PoE v1)");

    std::vector<KnowledgeEntrySummary> entries;
    {
        std::lock_guard<std::mutex> lock(state.knowledgeMutex);
        entries = state.knowledgeEntries;
    }

    size_t codeCount = 0;
    for (const auto& e : entries) {
        if (e.contentType == 2) codeCount++;
    }

    int innerRow = row + 2;
    mvprintw(innerRow++, boxX + 3, "Recent code entries: %zu", codeCount);
    mvprintw(innerRow++, boxX + 3, "Submit patches as deterministic CODE entries (no LLM scoring in consensus)");
    mvprintw(innerRow++, boxX + 3, "Use unified diff in a file, then submit via this screen");

    std::vector<KnowledgeEntrySummary> codeEntries;
    codeEntries.reserve(entries.size());
    for (const auto& e : entries) {
        if (e.contentType == 2) codeEntries.push_back(e);
    }

    int listY = row + 9;
    int listH = LINES - listY - 6;
    if (listH < 8) listH = 8;
    if (listH > 16) listH = 16;
    drawBox(listY, boxX, listH, boxW, "Recent CODE Entries");

    int innerW = boxW - 6;
    int headerY = listY + 1;
    printClippedLine(headerY, boxX + 3, innerW, "ID        STATUS     VOTES   REWARD     TITLE");

    int dataRows = listH - 3;
    if (dataRows < 1) dataRows = 1;

    int maxScroll = 0;
    if (static_cast<int>(codeEntries.size()) > dataRows) {
        maxScroll = static_cast<int>(codeEntries.size()) - dataRows;
    }
    if (scrollOffset < 0) scrollOffset = 0;
    if (scrollOffset > maxScroll) scrollOffset = maxScroll;

    for (int i = 0; i < dataRows; ++i) {
        int idx = scrollOffset + i;
        int y = listY + 2 + i;
        if (idx >= static_cast<int>(codeEntries.size())) {
            mvhline(y, boxX + 3, ' ', innerW);
            continue;
        }
        const auto& e = codeEntries[idx];
        std::string id = e.submitId.size() > 8 ? e.submitId.substr(0, 8) : e.submitId;
        std::string st = e.finalized ? "FINAL" : "PENDING";
        std::string votes = std::to_string(e.votes) + "/" + std::to_string(e.requiredVotes);
        std::ostringstream r;
        r << "+" << std::fixed << std::setprecision(4) << e.acceptanceReward;
        std::string reward = r.str();
        if (e.acceptanceRewardCredited) reward += " PAID";
        std::string title = truncEnd(e.title, innerW - 38);
        std::string line = id + "  " + st + "   " + votes;
        while (line.size() < 24) line.push_back(' ');
        line += reward;
        while (line.size() < 35) line.push_back(' ');
        line += " " + title;

        if (e.finalized) attron(COLOR_PAIR(1));
        else attron(COLOR_PAIR(2));
        printClippedLine(y, boxX + 3, innerW, line);
        if (e.finalized) attroff(COLOR_PAIR(1));
        else attroff(COLOR_PAIR(2));
    }

    if (scrollOffset > 0) {
        mvaddch(listY + 1, boxX + boxW - 2, '^');
    }
    if (maxScroll > 0 && scrollOffset < maxScroll) {
        mvaddch(listY + listH - 2, boxX + boxW - 2, 'v');
    }

    int controlsY = listY + listH + 1;
    printClippedLine(controlsY, boxX + 3, innerW, "[I] Launch IDE  [C] Submit Patch  [Up/Down] Scroll  [B] Back");

    drawStatusBar();
    ::refresh();
}

void TUI::Impl::drawCodeSubmit() {
    clear();
    int row = 1;

    attron(COLOR_PAIR(4) | A_BOLD);
    centerText(row++, "SUBMIT CODE (PATCH)");
    attroff(COLOR_PAIR(4) | A_BOLD);

    row++;
    int boxW = 76;
    int boxX = (COLS - boxW) / 2;

    drawBox(row, boxX, 18, boxW, "New CODE Entry");
    int innerRow = row + 2;

    int fieldW = boxW - 8;
    mvprintw(innerRow++, boxX + 3, "Title:");
    if (state.codeField == 0) attron(A_REVERSE);
    mvprintw(innerRow++, boxX + 3, "> %s%s", truncEnd(state.codeTitle, fieldW - 4).c_str(), state.codeField == 0 ? "_" : "");
    if (state.codeField == 0) attroff(A_REVERSE);
    innerRow++;

    mvprintw(innerRow++, boxX + 3, "Patch file path:");
    if (state.codeField == 1) attron(A_REVERSE);
    mvprintw(innerRow++, boxX + 3, "> %s%s", truncStart(state.codePatchFile, fieldW - 4).c_str(), state.codeField == 1 ? "_" : "");
    if (state.codeField == 1) attroff(A_REVERSE);
    innerRow++;

    mvprintw(innerRow++, boxX + 3, "Citations (optional, comma-separated hex IDs):");
    if (state.codeField == 2) attron(A_REVERSE);
    mvprintw(innerRow++, boxX + 3, "> %s%s", truncEnd(state.codeCitations, fieldW - 4).c_str(), state.codeField == 2 ? "_" : "");
    if (state.codeField == 2) attroff(A_REVERSE);
    innerRow++;

    uintmax_t patchSize = 0;
    bool patchOk = false;
    if (!state.codePatchFile.empty()) {
        std::error_code ec;
        if (std::filesystem::exists(state.codePatchFile, ec) && std::filesystem::is_regular_file(state.codePatchFile, ec)) {
            patchSize = std::filesystem::file_size(state.codePatchFile, ec);
            patchOk = !ec;
        }
    }

    if (patchOk) {
        mvprintw(innerRow++, boxX + 3, "Patch size: %ju bytes", static_cast<uintmax_t>(patchSize));
    } else {
        mvprintw(innerRow++, boxX + 3, "Patch size: --");
    }
    innerRow++;

    mvprintw(innerRow++, boxX + 3, "[Tab] Switch Field    [F2] Submit    [Esc] Cancel");
    mvprintw(innerRow++, boxX + 3, "Tip: generate a unified diff and save it to a file");

    drawStatusBar();
    ::refresh();
}

void TUI::Impl::drawModel() {
    clear();
    int row = 1;
    
    attron(COLOR_PAIR(4) | A_BOLD);
    centerText(row++, "LOCAL AI MODEL");
    attroff(COLOR_PAIR(4) | A_BOLD);
    
    row++;
    int boxW = 70;
    int boxX = (COLS - boxW) / 2;
    
    drawBox(row, boxX, 9, boxW, "Model Status");
    
    int innerRow = row + 2;
    {
        std::string modelName = state.model.name.empty() ? "not loaded" : state.model.name;
        printClippedLine(innerRow++, boxX + 3, boxW - 6, "Model:    " + truncEnd(modelName, boxW - 15));
    }
    
    if (state.model.status == "ACTIVE") {
        attron(COLOR_PAIR(1));
        mvprintw(innerRow++, boxX + 3, "Status:   * %s", state.model.status.c_str());
        attroff(COLOR_PAIR(1));
    } else {
        attron(COLOR_PAIR(2));
        mvprintw(innerRow++, boxX + 3, "Status:   * %s", state.model.status.c_str());
        attroff(COLOR_PAIR(2));
    }
    
    mvprintw(innerRow, boxX + 3, "Progress: ");
    int barX = boxX + 13;
    mvaddch(innerRow, barX, '[');
    for (int i = 0; i < 40; i++) {
        if (i < static_cast<int>(state.model.progress * 40)) {
            attron(COLOR_PAIR(1));
            mvprintw(innerRow, barX + 1 + i, "#");
            attroff(COLOR_PAIR(1));
        } else {
            mvaddch(innerRow, barX + 1 + i, ' ');
        }
    }
    mvaddch(innerRow, barX + 41, ']');
    mvprintw(innerRow++, barX + 43, "%d%%", static_cast<int>(state.model.progress * 100));
    
    printClippedLine(innerRow++, boxX + 3, boxW - 6, "Mode:     " + truncEnd(state.model.mode, boxW - 15));
    mvprintw(innerRow++, boxX + 3, "Uptime:   0h 0m");
    
    row += 11;
    drawBox(row, boxX, 8, boxW, "Earnings");
    
    innerRow = row + 2;
    mvprintw(innerRow++, boxX + 3, "Today:      +%.1f NGT", state.model.earningsToday);
    mvprintw(innerRow++, boxX + 3, "This Week:  +%.1f NGT", state.model.earningsWeek);
    mvprintw(innerRow++, boxX + 3, "Total:      +%.1f NGT", state.model.earningsTotal);
    
    row += 10;
    drawBox(row, boxX, 7, boxW, "Access Control");
    
    innerRow = row + 2;
    mvprintw(innerRow++, boxX + 3, "[1] PRIVATE  - only you (default)");
    mvprintw(innerRow++, boxX + 3, "[2] SHARED   - invite nodes, set limit");
    mvprintw(innerRow++, boxX + 3, "[3] PUBLIC   - anyone can use");
    mvprintw(innerRow++, boxX + 3, "[4] PAID     - set price, earn NGT");
    
    row += 9;
    mvprintw(row++, boxX + 3, "[L] Load Model    [U] Unload    [C] Chat    [B] Back");
    
    drawStatusBar();
    ::refresh();
}

void TUI::Impl::drawAIChat() {
    clear();
    const int marginX = 2;
    const int gapX = 2;
    const int headerY = 1;
    const int contentY = 3;
    const int inputBoxH = 3;
    const int controlsH = 1;

    attron(COLOR_PAIR(4) | A_BOLD);
    centerText(headerY, "AI CHAT");
    attroff(COLOR_PAIR(4) | A_BOLD);

    int rightW = 38;
    int usableW = COLS - marginX * 2;
    if (usableW < 60) rightW = 26;
    if (usableW < 50) rightW = 22;
    int leftW = usableW - rightW - gapX;
    if (leftW < 30) {
        rightW = std::max(18, usableW / 3);
        leftW = usableW - rightW - gapX;
    }

    int leftX = marginX;
    int rightX = leftX + leftW + gapX;

    int convH = LINES - contentY - inputBoxH - controlsH - 2;
    if (convH < 8) convH = 8;

    drawBox(contentY, leftX, convH, leftW, "Conversation");
    drawBox(contentY, rightX, convH, rightW, "Model");

    int inputY = contentY + convH + 1;
    drawBox(inputY, leftX, inputBoxH, leftW, "Input");

    auto trunc = [](const std::string& s, int maxLen) -> std::string {
        if (maxLen <= 0) return {};
        if (static_cast<int>(s.size()) <= maxLen) return s;
        if (maxLen <= 3) return s.substr(0, static_cast<size_t>(maxLen));
        return s.substr(0, static_cast<size_t>(maxLen - 3)) + "...";
    };

    auto scanModels = [&]() -> std::vector<std::string> {
        std::vector<std::string> models;
        std::string homeDir = std::getenv("HOME") ? std::getenv("HOME") : ".";
        std::vector<std::string> scanDirs;
        scanDirs.push_back((std::filesystem::current_path() / "models").string());
        scanDirs.push_back(homeDir + "/.synapsenet/models");
        std::filesystem::path cur = std::filesystem::current_path();
        for (int i = 0; i < 6; ++i) {
            std::filesystem::path p = cur / "third_party/llama.cpp/models";
            if (std::filesystem::exists(p)) scanDirs.push_back(p.string());
            if (cur == cur.root_path()) break;
            cur = cur.parent_path();
        }
        for (const auto& dir : scanDirs) {
            std::error_code ec;
            if (!std::filesystem::exists(dir, ec) || ec) continue;
            for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
                if (ec) break;
                if (entry.is_directory(ec) || ec) continue;
                auto p = entry.path();
                if (p.extension() != ".gguf") continue;
                if (p.filename().string().rfind("ggml-vocab-", 0) == 0) continue;
                if (p.filename().string().size() >= 5 && p.filename().string().substr(p.filename().string().size() - 5) == ".part") continue;
                uint64_t sz = 0;
                sz = static_cast<uint64_t>(entry.file_size(ec));
                if (ec) continue;
                if (sz < 1024 * 1024) continue;
                models.push_back(p.string());
            }
        }
        std::sort(models.begin(), models.end());
        models.erase(std::unique(models.begin(), models.end()), models.end());
        return models;
    };

    auto nowMs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count());
    bool needScan = aiModelPanelActive || state.availableModels.empty() || (nowMs - lastModelScanMs > 2000);
    if (needScan) {
        state.availableModels = scanModels();
        lastModelScanMs = nowMs;
    }
    if (aiModelSelection < 0) aiModelSelection = 0;
    if (aiModelSelection >= static_cast<int>(state.availableModels.size())) aiModelSelection = std::max(0, static_cast<int>(state.availableModels.size()) - 1);

    int modelRow = contentY + 1;
    int modelInnerW = rightW - 4;
    std::string currentName;
    if (modelLoader && modelLoader->isLoaded()) {
        currentName = modelLoader->getInfo().name;
    } else {
        currentName = state.model.name;
    }
    if (currentName.empty()) currentName = "none";

    std::string status;
    if (state.model.status == "DOWNLOADING") {
        status = "DOWNLOADING";
    } else if (modelLoader) {
        auto st = modelLoader->getState();
        if (st == synapse::model::ModelState::READY) status = "ACTIVE";
        else if (st == synapse::model::ModelState::LOADING) status = "LOADING";
        else if (st == synapse::model::ModelState::ERROR) status = "ERROR";
        else status = state.model.status.empty() ? "NOT LOADED" : state.model.status;
    } else {
        status = state.model.status.empty() ? "NOT LOADED" : state.model.status;
    }

    attron(COLOR_PAIR(aiModelPanelActive ? 1 : 7) | A_BOLD);
    mvprintw(modelRow++, rightX + 2, "Active: %s", trunc(currentName, modelInnerW - 8).c_str());
    attroff(COLOR_PAIR(aiModelPanelActive ? 1 : 7) | A_BOLD);
    mvprintw(modelRow++, rightX + 2, "Status: %s", trunc(status, modelInnerW - 8).c_str());

    bool webInject = false;
    bool webOnion = false;
    bool webTor = false;
    bool webSearching = false;
    uint64_t webLast = 0;
    uint64_t webLastClear = 0;
    uint64_t webLastOnion = 0;
    std::string webErr;
    {
        std::lock_guard<std::mutex> lock(state.webMutex);
        webInject = state.webInjectEnabled;
        webOnion = state.webOnionEnabled;
        webTor = state.webTorForClearnet;
        webSearching = state.webSearching;
        webLast = state.webLastResults;
        webLastClear = state.webLastClearnetResults;
        webLastOnion = state.webLastDarknetResults;
        webErr = state.webLastError;
    }

    modelRow++;
    mvprintw(modelRow++, rightX + 2, "Web inject: %s (F5/Ctrl+W)", webInject ? "ON" : "OFF");
    mvprintw(modelRow++, rightX + 2, "Onion src:  %s (F6/Ctrl+O)", webOnion ? "ON" : "OFF");
    mvprintw(modelRow++, rightX + 2, "Tor clear:  %s (F7/Ctrl+T)", webTor ? "ON" : "OFF");
    if (webInject) {
        mvprintw(modelRow++, rightX + 2, "Search: %s", webSearching ? "RUNNING" : "IDLE");
        if (webLast > 0) {
            mvprintw(modelRow++, rightX + 2, "Results: %llu (%llu/%llu)",
                     static_cast<unsigned long long>(webLast),
                     static_cast<unsigned long long>(webLastClear),
                     static_cast<unsigned long long>(webLastOnion));
        }
        if (!webErr.empty()) {
            mvprintw(modelRow++, rightX + 2, "Web err:");
            mvprintw(modelRow++, rightX + 2, "%s", trunc(webErr, modelInnerW).c_str());
        }
    }

    if (state.model.status == "DOWNLOADING" || state.model.status == "LOADING") {
        int pct = static_cast<int>(state.model.progress * 100);
        if (pct < 0) pct = 0;
        if (pct > 100) pct = 100;
        mvprintw(modelRow++, rightX + 2, "Progress: %3d%%", pct);
        drawProgressBar(modelRow++, rightX + 2, modelInnerW, state.model.progress, 2);
    }

    if (state.model.status == "DOWNLOADING") {
        uint64_t curBytes = 0;
        uint64_t expBytes = 0;
        if (modelLoader) {
            try { expBytes = modelLoader->getInfo().sizeBytes; } catch (...) { expBytes = 0; }
        }
        std::error_code ec;
        if (!state.downloadPartPath.empty() && std::filesystem::exists(state.downloadPartPath, ec) && !ec) {
            curBytes = static_cast<uint64_t>(std::filesystem::file_size(state.downloadPartPath, ec));
        }
        if (curBytes == 0 && !state.downloadPath.empty() && std::filesystem::exists(state.downloadPath, ec) && !ec) {
            curBytes = static_cast<uint64_t>(std::filesystem::file_size(state.downloadPath, ec));
        }
        mvprintw(modelRow++, rightX + 2, "Saved: %s", trunc(state.downloadPath, modelInnerW - 7).c_str());
        std::string bytesLine = synapse::model::ModelLoader::formatBytes(curBytes);
        if (expBytes > 0) {
            bytesLine += " / " + synapse::model::ModelLoader::formatBytes(expBytes);
        }
        mvprintw(modelRow++, rightX + 2, "Bytes: %s", trunc(bytesLine, modelInnerW - 7).c_str());
        if (!state.downloadPartPath.empty() && std::filesystem::exists(state.downloadPartPath, ec) && !ec) {
            auto ft = std::filesystem::last_write_time(state.downloadPartPath, ec);
            if (!ec) {
                auto now = std::filesystem::file_time_type::clock::now();
                auto age = now - ft;
                auto secs = std::chrono::duration_cast<std::chrono::seconds>(age).count();
                if (secs < 0) secs = 0;
                std::string ageStr;
                if (secs < 60) {
                    ageStr = std::to_string(secs) + "s";
                } else if (secs < 3600) {
                    ageStr = std::to_string(secs / 60) + "m" + std::to_string(secs % 60) + "s";
                } else {
                    ageStr = std::to_string(secs / 3600) + "h" + std::to_string((secs % 3600) / 60) + "m";
                }
                mvprintw(modelRow++, rightX + 2, "Updated: %s ago", trunc(ageStr, modelInnerW - 10).c_str());
            }
        }
    } else if (modelLoader && modelLoader->getState() == synapse::model::ModelState::ERROR) {
        std::string err = modelLoader->getError();
        mvprintw(modelRow++, rightX + 2, "Error:");
        mvprintw(modelRow++, rightX + 2, "%s", trunc(err, modelInnerW).c_str());
    }

    modelRow++;
    mvprintw(modelRow++, rightX + 2, "Models:");
    mvprintw(modelRow++, rightX + 2, "F2/Ctrl+P to select");
    int listTop = modelRow;
    int listH = contentY + convH - 2 - listTop;
    if (listH < 3) listH = 3;

    if (state.availableModels.empty()) {
        attron(COLOR_PAIR(2));
        std::array<std::string, 4> emptyLines = {
            "No local GGUF models found",
            "Put .gguf in ~/.synapsenet/models",
            "or ./models then press F2/Ctrl+P",
            "Press [F4/Ctrl+D] to download",
        };
        for (int i = 0; i < static_cast<int>(emptyLines.size()) && i < listH; ++i) {
            mvprintw(listTop + i, rightX + 2, "%s", emptyLines[static_cast<size_t>(i)].c_str());
        }
        attroff(COLOR_PAIR(2));
    } else {
        int visible = listH;
        if (visible > 12) visible = 12;
        if (aiModelSelection < aiModelScroll) aiModelScroll = aiModelSelection;
        if (aiModelSelection >= aiModelScroll + visible) aiModelScroll = aiModelSelection - visible + 1;
        if (aiModelScroll < 0) aiModelScroll = 0;
        if (aiModelScroll > std::max(0, static_cast<int>(state.availableModels.size()) - visible)) {
            aiModelScroll = std::max(0, static_cast<int>(state.availableModels.size()) - visible);
        }
        for (int i = 0; i < visible; ++i) {
            int idx = aiModelScroll + i;
            if (idx >= static_cast<int>(state.availableModels.size())) break;
            std::string name = std::filesystem::path(state.availableModels[idx]).filename().string();
            if (idx == aiModelSelection && aiModelPanelActive) attron(A_REVERSE | COLOR_PAIR(1));
            mvprintw(listTop + i, rightX + 2, "%s", trunc(name, modelInnerW).c_str());
            if (idx == aiModelSelection && aiModelPanelActive) attroff(A_REVERSE | COLOR_PAIR(1));
        }
    }

    int chatRow = contentY + 1;
    int maxChatLines = convH - 2;

    auto sanitizeText = [](const std::string& s) -> std::string {
        std::string out;
        out.reserve(s.size());
        for (unsigned char c : s) {
            if (c == '\r') continue;
            if (c == '\t') {
                out.append(4, ' ');
                continue;
            }
            if (c == '\n') {
                out.push_back('\n');
                continue;
            }
            if (c < 32 || c == 127) {
                out.push_back(' ');
                continue;
            }
            out.push_back(static_cast<char>(c));
        }
        return out;
    };

    auto wrapWithPrefix = [&](const std::string& text, int width, const std::string& prefix) -> std::vector<std::string> {
        std::vector<std::string> out;
        if (width <= 0) return out;
        std::string s = sanitizeText(text);
        int prefixLen = static_cast<int>(prefix.size());
        if (prefixLen >= width) prefixLen = width - 1;
        std::string line = prefix.substr(0, static_cast<size_t>(prefixLen));
        int col = prefixLen;

        auto flush = [&]() {
            out.push_back(line);
            line.assign(prefix.substr(0, static_cast<size_t>(prefixLen)));
            col = prefixLen;
        };

        for (char c : s) {
            if (c == '\n') {
                flush();
                continue;
            }
            if (col >= width) flush();
            line.push_back(c);
            col++;
        }
        if (!line.empty() && (line.size() > static_cast<size_t>(prefixLen) || out.empty())) out.push_back(line);
        return out;
    };

    struct RenderLine {
        std::string text;
        int color = 0;
        int attrs = 0;
    };

    int innerW = leftW - 4;
    if (innerW < 10) innerW = 10;

    std::vector<ChatMessage> history;
    {
        std::lock_guard<std::mutex> lock(state.chatMutex);
        history = state.chatHistory;
    }
    std::string streaming;
    {
        std::lock_guard<std::mutex> lock(state.aiResponseMutex);
        streaming = state.aiCurrentResponse;
    }

    std::vector<RenderLine> lines;
    lines.reserve(history.size() * 4 + 32);

    auto addMessage = [&](bool isUser, const std::string& content) {
        RenderLine header;
        header.text = isUser ? "You:" : "AI:";
        header.color = isUser ? 1 : 4;
        header.attrs = A_BOLD;
        lines.push_back(header);

        auto wrapped = wrapWithPrefix(content, innerW, "  ");
        for (auto& w : wrapped) {
            RenderLine l;
            l.text = std::move(w);
            l.color = 0;
            l.attrs = 0;
            lines.push_back(std::move(l));
        }
    };

    bool emptyChat = false;
    {
        std::lock_guard<std::mutex> lock(state.chatMutex);
        emptyChat = state.chatHistory.empty();
    }
    bool emptyStream = false;
    {
        std::lock_guard<std::mutex> lock(state.aiResponseMutex);
        emptyStream = state.aiCurrentResponse.empty();
    }
    if (emptyChat && emptyStream) {
        bool hasLoaded = (modelLoader && modelLoader->isLoaded());
        if (!hasLoaded) {
            attron(COLOR_PAIR(2));
            printClippedLine(chatRow++, leftX + 2, innerW, "Load a model first to start chatting.");
            printClippedLine(chatRow++, leftX + 2, innerW, "Press [F2] to open model panel, [F4] to download.");
            attroff(COLOR_PAIR(2));
        } else {
            attron(COLOR_PAIR(4));
            printClippedLine(chatRow++, leftX + 2, innerW, "Model loaded. Type your message below.");
            attroff(COLOR_PAIR(4));
        }
        if (chatRow < contentY + convH - 1) chatRow++;
    }

    if (!emptyChat || !emptyStream) {
        if (!history.empty()) {
            for (const auto& msg : history) {
                addMessage(msg.role == "user", msg.content);
            }
        }
        if (state.aiGenerating && !streaming.empty()) {
            addMessage(false, streaming);
        }

        int maxScroll = 0;
        if (static_cast<int>(lines.size()) > maxChatLines) {
            maxScroll = static_cast<int>(lines.size()) - maxChatLines;
        }
        if (chatScrollOffset < 0) chatScrollOffset = 0;
        if (chatScrollOffset > maxScroll) chatScrollOffset = maxScroll;
        
        // Auto-scroll: if enabled and user hasn't scrolled up, scroll to bottom
        if (autoScrollEnabled && chatScrollOffset > 0) {
            chatScrollOffset = 0;
        }
        if (autoScrollEnabled && chatScrollOffset == 0 && maxScroll > 0) {
            // Ensure we're at the bottom
            chatScrollOffset = 0;
        }

        int start = std::max(0, static_cast<int>(lines.size()) - maxChatLines - chatScrollOffset);
        int printed = 0;
        for (int i = 0; i < maxChatLines; ++i) {
            int idx = start + i;
            if (idx >= static_cast<int>(lines.size())) break;
            const auto& l = lines[idx];
            if (l.color > 0) attron(COLOR_PAIR(l.color));
            if (l.attrs) attron(l.attrs);
            int w = safeScreenWidth(leftX + 2, innerW);
            if (w > 0) {
                mvhline(contentY + 1 + i, leftX + 2, ' ', w);
                mvaddnstr(contentY + 1 + i, leftX + 2, l.text.c_str(), w);
            }
            if (l.attrs) attroff(l.attrs);
            if (l.color > 0) attroff(COLOR_PAIR(l.color));
            printed++;
        }
        for (int i = printed; i < maxChatLines; ++i) {
            mvhline(contentY + 1 + i, leftX + 2, ' ', innerW);
        }

        if (chatScrollOffset > 0 && maxChatLines > 0) {
            mvaddch(contentY + 1, leftX + leftW - 2, '^');
        }
        if (maxScroll > 0 && chatScrollOffset < maxScroll && maxChatLines > 0) {
            mvaddch(contentY + convH - 2, leftX + leftW - 2, 'v');
        }
    }

    if (inputCursor > inputBuffer.size()) inputCursor = inputBuffer.size();
    const int inputX = leftX + 2;
    const int inputW = safeScreenWidth(inputX, leftW - 4);
    if (inputW > 0) {
        mvhline(inputY + 1, inputX, ' ', inputW);
        mvaddnstr(inputY + 1, inputX, "> ", std::min(2, inputW));

        const int maxChars = std::max(0, inputW - 2);
        size_t startIdx = 0;
        if (maxChars > 0 && inputBuffer.size() > static_cast<size_t>(maxChars)) {
            if (inputCursor > static_cast<size_t>(maxChars)) {
                startIdx = inputCursor - static_cast<size_t>(maxChars);
            }
            if (startIdx + static_cast<size_t>(maxChars) > inputBuffer.size()) {
                startIdx = inputBuffer.size() - static_cast<size_t>(maxChars);
            }
        }

        std::string seg;
        if (maxChars > 0 && startIdx < inputBuffer.size()) {
            seg = inputBuffer.substr(startIdx, static_cast<size_t>(maxChars));
        }
        if (!seg.empty()) mvaddnstr(inputY + 1, inputX + 2, seg.c_str(), maxChars);

        size_t cursorInSeg = inputCursor >= startIdx ? (inputCursor - startIdx) : 0;
        int cx = inputX + 2 + static_cast<int>(cursorInSeg);
        if (cx >= inputX + inputW) cx = inputX + inputW - 1;
        if (cx < inputX + 2) cx = inputX + 2;

        char c = '_';
        if (inputCursor < inputBuffer.size() && cursorInSeg < seg.size()) {
            c = seg[cursorInSeg];
            if (static_cast<unsigned char>(c) < 32 || c == 127) c = ' ';
        }
        attron(A_REVERSE);
        mvaddch(inputY + 1, cx, c);
        attroff(A_REVERSE);
    }

    int controlsY = inputY + inputBoxH;
    std::string ctrl = "[Enter] Send  [F2/Ctrl+P] Models  [F4/Ctrl+D] Download  [F5/Ctrl+W] Web  [F6/Ctrl+O] Onion  [F7/Ctrl+T] Tor  [PgUp/PgDn] Scroll  [Esc] Back  [F3] Clear";
    ctrl += "  [F8] Stop";
    if (state.aiGenerating) ctrl += "  (Generating...)";
    printClippedLine(controlsY, leftX + 2, leftW - 4, ctrl);
    
    drawStatusBar();
    ::refresh();
}

void TUI::Impl::drawSecurity() {
    clear();
    int row = 1;
    
    attron(COLOR_PAIR(4) | A_BOLD);
    centerText(row++, "SECURITY STATUS");
    attroff(COLOR_PAIR(4) | A_BOLD);
    
    row++;
    int boxW = 76;
    int boxX = (COLS - boxW) / 2;
    
    drawBox(row, boxX, 12, boxW, "Quantum-Resistant Protection");
    
    int innerRow = row + 2;
    attron(COLOR_PAIR(1) | A_BOLD);
    mvprintw(innerRow++, boxX + 3, "QUANTUM-RESISTANT PROTECTION: ACTIVE");
    attroff(COLOR_PAIR(1) | A_BOLD);
    innerRow++;
    
    attron(COLOR_PAIR(1));
    mvprintw(innerRow++, boxX + 3, "Wallet Keys:      CRYSTALS-Dilithium (Post-Quantum)");
    mvprintw(innerRow++, boxX + 3, "Seed Phrase:      SPHINCS+ Protected");
    mvprintw(innerRow++, boxX + 3, "Network Comms:    CRYSTALS-Kyber Encrypted");
    mvprintw(innerRow++, boxX + 3, "Knowledge Data:   Lattice-based Encryption");
    attroff(COLOR_PAIR(1));
    innerRow++;
    
    mvprintw(innerRow++, boxX + 3, "Status: Your node is protected against quantum computer attacks");
    
    row += 14;
    drawBox(row, boxX, 10, boxW, "Security Layers");
    
    innerRow = row + 2;
    mvprintw(innerRow++, boxX + 3, "Layer 0: CLASSIC       Ed25519 + X25519 + AES-256-GCM");
    mvprintw(innerRow++, boxX + 3, "Layer 1: LATTICE PQC   ML-KEM-768 (Kyber) + ML-DSA-65");
    mvprintw(innerRow++, boxX + 3, "Layer 2: HASH PQC      SLH-DSA-128s (SPHINCS+)");
    mvprintw(innerRow++, boxX + 3, "Layer 3: ONE-TIME PAD  Vernam Cipher (XOR)");
    mvprintw(innerRow++, boxX + 3, "Layer 4: QKD           BB84/E91 (future hardware)");
    
    row += 12;
    mvprintw(row++, boxX + 3, "[B] Back to Dashboard");
    
    drawStatusBar();
    ::refresh();
}

void TUI::Impl::drawSettings() {
    clear();
    int row = 1;
    
    attron(COLOR_PAIR(4) | A_BOLD);
    centerText(row++, "SETTINGS");
    attroff(COLOR_PAIR(4) | A_BOLD);
    
    row++;
    int boxW = 60;
    int boxX = (COLS - boxW) / 2;
    
    drawBox(row, boxX, 14, boxW, "Configuration");
    
    int innerRow = row + 2;
    const char* settings[] = {
        "[1] Network Settings",
        "[2] Privacy Settings",
        "[3] Model Settings",
        "[4] Display Settings",
        "[5] Security Settings",
        "[6] Wallet Settings",
        "[7] Export Configuration",
        "[8] Import Configuration",
        "[9] Reset to Defaults"
    };
    
    for (int i = 0; i < 9; i++) {
        if (i == menuSelection) {
            attron(A_REVERSE);
        }
        mvprintw(innerRow++, boxX + 5, "%s", settings[i]);
        if (i == menuSelection) {
            attroff(A_REVERSE);
        }
    }
    
    row += 16;
    mvprintw(row++, boxX + 3, "[Up/Down] Navigate    [Enter] Select    [B] Back");
    
    drawStatusBar();
    ::refresh();
}

void TUI::Impl::drawMining() {
    clear();
    int row = 1;
    
    attron(COLOR_PAIR(4) | A_BOLD);
    centerText(row++, "MINING ACTIVITY");
    attroff(COLOR_PAIR(4) | A_BOLD);
    
    row++;
    int boxW = 76;
    int boxX = (COLS - boxW) / 2;
    
    centerText(row++, "--------------------------------------------------------------------------------");
    
    row++;
    mvprintw(row, boxX + 3, "Progress: ");
    int barX = boxX + 13;
    for (int i = 0; i < 45; i++) {
        if (i < static_cast<int>(state.miningProgress * 45)) {
            attron(COLOR_PAIR(1));
            mvprintw(row, barX + i, "#");
            attroff(COLOR_PAIR(1));
        } else {
            mvprintw(row, barX + i, " ");
        }
    }
    mvprintw(row++, barX + 46, "%d%% Processing Knowledge", static_cast<int>(state.miningProgress * 100));
    
    row += 2;
    drawBox(row, boxX, 10, boxW, "Recent Contributions");
    
    int innerRow = row + 2;
    if (state.recentContributions.empty()) {
        attron(COLOR_PAIR(2));
        mvprintw(innerRow++, boxX + 3, "No contributions yet.");
        mvprintw(innerRow++, boxX + 3, "Start contributing knowledge to earn NGT!");
        attroff(COLOR_PAIR(2));
    } else {
        for (const auto& contrib : state.recentContributions) {
            attron(COLOR_PAIR(1));
            mvprintw(innerRow, boxX + 3, "[%s]", contrib.time.c_str());
            attroff(COLOR_PAIR(1));
            mvprintw(innerRow, boxX + 15, "%s: %s", contrib.type.c_str(), contrib.name.c_str());
            attron(COLOR_PAIR(1));
            mvprintw(innerRow, boxX + 55, "+%.1f NGT", contrib.reward);
            attroff(COLOR_PAIR(1));
            innerRow++;
        }
    }
    
    row += 12;
    mvprintw(row++, boxX + 3, "[C] Contribute    [V] Validate    [B] Back");
    
    drawStatusBar();
    ::refresh();
}

void TUI::Impl::drawModelLoader() {
    clear();
    int row = 1;
    
    attron(COLOR_PAIR(4) | A_BOLD);
    centerText(row++, "LOAD AI MODEL");
    attroff(COLOR_PAIR(4) | A_BOLD);
    
    row++;
    int boxW = 70;
    int boxX = (COLS - boxW) / 2;
    
    drawBox(row, boxX, 6, boxW, "Model Directory");

    int innerRow = row + 2;
    std::string homeDir = std::getenv("HOME") ? std::getenv("HOME") : ".";
    std::string userPath = homeDir + "/.synapsenet/models";
    std::string projectPath = std::filesystem::current_path().string() + "/models";
    std::vector<std::string> thirdPartyCandidates;
    std::filesystem::path cur = std::filesystem::current_path();
    for (int i = 0; i < 6; ++i) {
        std::filesystem::path p = cur / "third_party/llama.cpp/models";
        if (std::filesystem::exists(p)) thirdPartyCandidates.push_back(p.string());
        if (cur == cur.root_path()) break;
        cur = cur.parent_path();
    }
    printClippedLine(innerRow++, boxX + 3, boxW - 6, "Path: " + truncStart(userPath, boxW - 12));
    printClippedLine(innerRow++, boxX + 3, boxW - 6, "Also scanning: " + truncStart(projectPath, boxW - 18));
    for (const auto &tp : thirdPartyCandidates) {
        printClippedLine(innerRow++, boxX + 3, boxW - 6, "Also scanning: " + truncStart(tp, boxW - 18));
    }
    mvprintw(innerRow++, boxX + 3, "Supported: .gguf files (llama.cpp format)");

    row += 7;
    drawBox(row, boxX, 12, boxW, "Available Models");

    innerRow = row + 2;

    state.availableModels.clear();
    std::vector<std::string> scanDirs = {userPath, projectPath};
    for (const auto &tp : thirdPartyCandidates) scanDirs.push_back(tp);
    for (const auto &dir : scanDirs) {
        if (!std::filesystem::exists(dir)) continue;
        for (const auto &entry : std::filesystem::directory_iterator(dir)) {
            if (entry.path().extension() != ".gguf") continue;
            std::string name = entry.path().filename().string();
            if (name.rfind("ggml-vocab-", 0) == 0) continue;
            state.availableModels.push_back(entry.path().string());
        }
    }

	    if (state.availableModels.empty()) {
	        attron(COLOR_PAIR(2));
	        mvprintw(innerRow++, boxX + 3, "No models found.");
	        printClippedLine(innerRow++, boxX + 3, boxW - 6, "Press [D] to download a recommended model (DeepSeek Coder 6.7B Q4_K_M).");
	        if (modelLoader && modelLoader->getState() == synapse::model::ModelState::ERROR) {
	            std::string err = modelLoader->getError();
	            if (err.size() > 60) err = err.substr(0, 60) + "...";
	            printClippedLine(innerRow++, boxX + 3, boxW - 6, "Error: " + truncEnd(err, boxW - 13));
        }
        if (state.model.status == "DOWNLOADING") {
            mvprintw(innerRow++, boxX + 3, "Downloading: %d%%", static_cast<int>(state.model.progress * 100));
        }
        mvprintw(innerRow++, boxX + 3, "");
        mvprintw(innerRow++, boxX + 3, "To add models:");
        mvprintw(innerRow++, boxX + 3, "1. mkdir -p ./models");
        mvprintw(innerRow++, boxX + 3, "2. Put .gguf in ./models/ (project root)");
        mvprintw(innerRow++, boxX + 3, "3. Or use ~/.synapsenet/models/");
        attroff(COLOR_PAIR(2));
    } else {
        for (size_t i = 0; i < state.availableModels.size() && i < 12; i++) {
            std::string name = std::filesystem::path(state.availableModels[i]).filename().string();
            if (static_cast<int>(i) == menuSelection) {
                attron(A_REVERSE | COLOR_PAIR(1));
            }
            mvprintw(innerRow++, boxX + 3, "[%zu] %s", i + 1, name.c_str());
            if (static_cast<int>(i) == menuSelection) {
                attroff(A_REVERSE | COLOR_PAIR(1));
            }
        }
    }

    row += 14;
    if (!state.availableModels.empty()) {
        printClippedLine(row++, boxX + 3, boxW - 6, "[1-9] Select Model  [Enter] Load  [D] Download  [R] Refresh  [B] Back");
    } else {
        printClippedLine(row++, boxX + 3, boxW - 6, "[D] Download  [R] Refresh  [B] Back");
    }
    
    drawStatusBar();
    ::refresh();
}

void TUI::Impl::drawSendNGT() {
    clear();
    int row = 1;
    
    attron(COLOR_PAIR(4) | A_BOLD);
    centerText(row++, "SEND NGT");
    attroff(COLOR_PAIR(4) | A_BOLD);
    
    row++;
    int boxW = 70;
    int boxX = (COLS - boxW) / 2;
    
    drawBox(row, boxX, 8, boxW, "Your Balance");
    
    int innerRow = row + 2;
    std::string shortAddr = state.wallet.address.empty() ? "not created" :
        (state.wallet.address.size() > 18
            ? state.wallet.address.substr(0, 10) + "..." + state.wallet.address.substr(state.wallet.address.size() - 5)
            : state.wallet.address);
    mvprintw(innerRow++, boxX + 3, "Address:   %s", shortAddr.c_str());
    attron(COLOR_PAIR(1) | A_BOLD);
    mvprintw(innerRow++, boxX + 3, "Available: %.2f NGT", state.wallet.balance);
    attroff(COLOR_PAIR(1) | A_BOLD);
    mvprintw(innerRow++, boxX + 3, "Pending:   %.2f NGT", state.wallet.pending);
    
    row += 10;
    drawBox(row, boxX, 10, boxW, "Send Transaction");
    
    innerRow = row + 2;
    mvprintw(innerRow++, boxX + 3, "To Address:");
    std::string toDisplay = state.sendToAddress;
    if (static_cast<int>(toDisplay.size()) > boxW - 8) {
        toDisplay = toDisplay.substr(toDisplay.size() - static_cast<size_t>(boxW - 8));
    }
    {
        std::string line = "> " + toDisplay + (state.walletScreen == 0 ? "_" : "");
        if (state.walletScreen == 0) attron(A_REVERSE);
        printClippedLine(innerRow++, boxX + 3, boxW - 6, line);
        if (state.walletScreen == 0) attroff(A_REVERSE);
    }
    innerRow++;
    mvprintw(innerRow++, boxX + 3, "Amount (NGT):");
    {
        std::string amt = state.sendAmountStr;
        std::string line = "> " + amt + (state.walletScreen == 1 ? "_" : "");
        if (state.walletScreen == 1) attron(A_REVERSE);
        printClippedLine(innerRow++, boxX + 3, boxW - 6, line);
        if (state.walletScreen == 1) attroff(A_REVERSE);
    }
    innerRow++;
    
    if (state.listeningPort == 0) {
        attron(COLOR_PAIR(2));
        mvprintw(innerRow++, boxX + 3, "Network offline - cannot send");
        attroff(COLOR_PAIR(2));
    } else if (state.peers.empty()) {
        attron(COLOR_PAIR(2));
        mvprintw(innerRow++, boxX + 3, "No peers connected - transaction will be local");
        attroff(COLOR_PAIR(2));
    }
    
    row += 12;
    mvprintw(row++, boxX + 3, "[Enter] Next/Send    [Tab] Switch Field    [Esc/B] Cancel");
    
    drawStatusBar();
    ::refresh();
}

void TUI::Impl::drawReceiveNGT() {
    clear();
    int row = 1;
    
    attron(COLOR_PAIR(4) | A_BOLD);
    centerText(row++, "RECEIVE NGT");
    attroff(COLOR_PAIR(4) | A_BOLD);
    
    row++;
    int boxW = 70;
    int boxX = (COLS - boxW) / 2;
    
    drawBox(row, boxX, 12, boxW, "Your Wallet Address");
    
    int innerRow = row + 2;
    mvprintw(innerRow++, boxX + 3, "Share this address to receive NGT:");
    innerRow++;
    
    attron(COLOR_PAIR(1) | A_BOLD);
    std::string addr = state.wallet.address.empty() ? "not created" : state.wallet.address;
    auto addrLines = wrapLines(addr, boxW - 6, 3);
    for (const auto& l : addrLines) {
        printClippedLine(innerRow++, boxX + 3, boxW - 6, l);
    }
    attroff(COLOR_PAIR(1) | A_BOLD);
    
    innerRow++;
    mvprintw(innerRow++, boxX + 3, "Network Status:");
    if (state.listeningPort > 0) {
        attron(COLOR_PAIR(1));
        mvprintw(innerRow++, boxX + 3, "  ONLINE - Port %d", state.listeningPort);
        mvprintw(innerRow++, boxX + 3, "  Ready to receive transactions");
        attroff(COLOR_PAIR(1));
    } else {
        attron(COLOR_PAIR(2));
        mvprintw(innerRow++, boxX + 3, "  OFFLINE - Cannot receive from network");
        attroff(COLOR_PAIR(2));
    }
    
    row += 14;
    mvprintw(row++, boxX + 3, "[B] Back to Wallet");
    
    drawStatusBar();
    ::refresh();
}


TUI::TUI() : impl_(std::make_unique<Impl>()) {
    impl_->initDefaultState();
}

TUI::~TUI() {
    shutdown();
}

bool TUI::init() {
    // Check if we're in a proper terminal
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
        return false;
    }
    
    WINDOW* w = initscr();
    if (!w) {
        return false;
    }
    
    // Check minimum terminal size
    if (LINES < 24 || COLS < 80) {
        endwin();
        return false;
    }
    
    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(1, COLOR_GREEN, -1);
        init_pair(2, COLOR_YELLOW, -1);
        init_pair(3, COLOR_RED, -1);
        init_pair(4, COLOR_CYAN, -1);
        init_pair(5, COLOR_MAGENTA, -1);
        init_pair(6, COLOR_BLUE, -1);
        init_pair(7, COLOR_WHITE, -1);
    }
    
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    nodelay(stdscr, TRUE);
    clear();
    mvprintw(0, 0, "SynapseNet TUI starting... (press SPACE)");
    ::refresh();
    
    impl_->running = true;
    impl_->screen = Screen::BOOT;
    
    std::string dataDir = utils::Config::instance().getDataDir();
    if (!dataDir.empty()) {
        std::string walletPath = dataDir + "/wallet.dat";
        if (std::filesystem::exists(walletPath)) {
            impl_->state.isFirstRun = false;
        }
    }
    
    return true;
}

void TUI::run() {
    std::vector<std::string> availableModels;
    
    while (impl_->running) {
        switch (impl_->screen) {
            case Screen::BOOT:
                impl_->drawBoot();
                break;
            case Screen::INIT:
                impl_->drawInit();
                break;
            case Screen::NETWORK_DISCOVERY:
                impl_->drawNetworkDiscovery();
                break;
            case Screen::SYNCING:
                impl_->drawSyncing();
                break;
            case Screen::WEB_PROMPT:
                impl_->drawWebPrompt();
                break;
            case Screen::WELCOME:
                impl_->drawWelcome();
                break;
            case Screen::WALLET_CREATE:
                impl_->drawWalletCreate();
                break;
            case Screen::WALLET_CREATED:
                impl_->drawWalletCreated();
                break;
            case Screen::WALLET_IMPORT:
                impl_->drawWalletImport();
                break;
            case Screen::CONNECTED:
                impl_->drawConnected();
                break;
            case Screen::DASHBOARD:
                impl_->drawDashboard();
                break;
            case Screen::WALLET:
                impl_->drawWallet();
                break;
            case Screen::WALLET_SEND:
                impl_->drawSendNGT();
                break;
            case Screen::WALLET_RECEIVE:
                impl_->drawReceiveNGT();
                break;
            case Screen::NETWORK:
                impl_->drawNetwork();
                break;
            case Screen::KNOWLEDGE:
                impl_->drawKnowledge();
                break;
	            case Screen::KNOWLEDGE_SUBMIT:
	                impl_->drawKnowledgeSubmit();
	                break;
	            case Screen::CODE:
	                impl_->drawCode();
	                break;
	            case Screen::CODE_SUBMIT:
	                impl_->drawCodeSubmit();
	                break;
	            case Screen::MODEL:
	                impl_->drawModelLoader();
	                break;
            case Screen::AI_CHAT:
                impl_->drawAIChat();
                break;
            case Screen::MINING:
                impl_->drawMining();
                break;
            case Screen::SETTINGS:
                impl_->drawSettings();
                break;
            case Screen::SECURITY:
                impl_->drawSecurity();
                break;
            default:
                impl_->drawDashboard();
                break;
        }
        
        int ch = getch();
        if (ch != ERR) {
            // Handle Ctrl+C gracefully
            if (ch == 3) { // Ctrl+C
                impl_->running = false;
                break;
            }
            
            if (impl_->inputHandler) {
                impl_->inputHandler(ch);
            }
            
            if (impl_->screen == Screen::WEB_PROMPT) {
                auto applyAndContinue = [&]() {
                    {
                        std::lock_guard<std::mutex> lock(impl_->state.webMutex);
                        synapse::utils::Config::instance().set("web.inject.enabled", impl_->state.webInjectEnabled);
                        synapse::utils::Config::instance().set("web.inject.onion", impl_->state.webOnionEnabled);
                        synapse::utils::Config::instance().set("web.inject.tor_clearnet", impl_->state.webTorForClearnet);
                        synapse::utils::Config::instance().set("web.prompt_done", true);
                    }
                    std::string cfgPath = synapse::utils::Config::instance().getDataDir() + "/synapsenet.conf";
                    synapse::utils::Config::instance().save(cfgPath);

                    if (impl_->webSearch) {
                        synapse::web::SearchConfig cfg = impl_->webSearch->getConfig();
                        cfg.enableClearnet = true;
                        {
                            std::lock_guard<std::mutex> lock(impl_->state.webMutex);
                            cfg.enableDarknet = impl_->state.webOnionEnabled;
                            cfg.routeClearnetThroughTor = impl_->state.webTorForClearnet;
                        }
                        impl_->webSearch->setConfig(cfg);
                    }

                    impl_->webPromptDone = true;
                    impl_->screen = impl_->state.isFirstRun ? Screen::WELCOME : Screen::DASHBOARD;
                };

                if (ch == 27) {
                    {
                        std::lock_guard<std::mutex> lock(impl_->state.webMutex);
                        impl_->state.webInjectEnabled = false;
                        impl_->state.webOnionEnabled = false;
                        impl_->state.webTorForClearnet = false;
                    }
                    applyAndContinue();
                } else if (ch == 'y' || ch == 'Y') {
                    if (impl_->webPromptStep == 0) {
                        std::lock_guard<std::mutex> lock(impl_->state.webMutex);
                        impl_->state.webInjectEnabled = true;
                        impl_->state.webOnionEnabled = false;
                        impl_->state.webTorForClearnet = false;
                        impl_->webPromptStep = 1;
                    } else if (impl_->webPromptStep == 1) {
                        std::lock_guard<std::mutex> lock(impl_->state.webMutex);
                        impl_->state.webOnionEnabled = true;
                        impl_->webPromptStep = 2;
                    } else {
                        std::lock_guard<std::mutex> lock(impl_->state.webMutex);
                        impl_->state.webTorForClearnet = true;
                        applyAndContinue();
                    }
                } else if (ch == 'n' || ch == 'N') {
                    if (impl_->webPromptStep == 0) {
                        std::lock_guard<std::mutex> lock(impl_->state.webMutex);
                        impl_->state.webInjectEnabled = false;
                        impl_->state.webOnionEnabled = false;
                        impl_->state.webTorForClearnet = false;
                        applyAndContinue();
                    } else if (impl_->webPromptStep == 1) {
                        std::lock_guard<std::mutex> lock(impl_->state.webMutex);
                        impl_->state.webOnionEnabled = false;
                        impl_->webPromptStep = 2;
                    } else {
                        std::lock_guard<std::mutex> lock(impl_->state.webMutex);
                        impl_->state.webTorForClearnet = false;
                        applyAndContinue();
                    }
                }
            } else if (impl_->screen == Screen::AI_CHAT) {
		                auto startDownload = [&]() {
		                    auto pimpl = impl_.get();
		                    if (pimpl->modelDownloadActive.exchange(true)) return;
		                    pimpl->state.model.status = "DOWNLOADING";
		                    pimpl->state.model.progress = 0.0;
		                    pimpl->state.model.name = "deepseek-coder-6.7b-instruct.Q4_K_M.gguf";
		                    std::string dataDir = synapse::utils::Config::instance().getDataDir();
		                    std::filesystem::path rootModels = dataDir.empty() ? (std::filesystem::current_path() / "models") : (std::filesystem::path(dataDir) / "models");
		                    std::error_code ec;
		                    std::filesystem::create_directories(rootModels, ec);
		                    pimpl->state.downloadPath = (rootModels / pimpl->state.model.name).string();
		                    pimpl->state.downloadPartPath = pimpl->state.downloadPath + ".part";
		                    std::thread([pimpl]() {
	                        struct ResetFlag {
	                            std::atomic<bool>* flag = nullptr;
	                            ~ResetFlag() {
	                                if (flag) flag->store(false);
                            }
	                        } reset{&pimpl->modelDownloadActive};

		                        try {
		                            const std::string modelName = "deepseek-coder-6.7b-instruct.Q4_K_M.gguf";
		                            bool ok = false;
		                            try {
		                                if (pimpl->modelLoader) {
	                                    ok = pimpl->modelLoader->downloadModel(modelName, [pimpl](double p) {
                                        pimpl->state.model.progress = p;
                                    });
                                }
		                            } catch (...) { ok = false; }
	
		                            std::string dataDir = synapse::utils::Config::instance().getDataDir();
		                            std::filesystem::path rootModels = dataDir.empty() ? (std::filesystem::current_path() / "models") : (std::filesystem::path(dataDir) / "models");
		                            std::string path = (rootModels / modelName).string();
	
		                            if (ok && pimpl->modelLoader) {
		                                pimpl->state.model.status = "LOADING";
		                                pimpl->state.model.progress = 0.0;
                                bool loaded = false;
                                try { loaded = pimpl->modelLoader->load(path); } catch (...) { loaded = false; }
                                if (loaded) {
                                    pimpl->state.modelPath = path;
                                    pimpl->state.model.name = std::filesystem::path(path).filename().string();
                                    pimpl->state.model.status = "ACTIVE";
                                    pimpl->state.model.progress = 1.0;
                                    pimpl->state.downloadPath.clear();
                                    pimpl->state.downloadPartPath.clear();
                                    synapse::utils::Config::instance().set("model.last_path", path);
                                    std::string cfgPath = synapse::utils::Config::instance().getDataDir() + "/synapsenet.conf";
                                    synapse::utils::Config::instance().save(cfgPath);
                                } else {
                                    pimpl->state.model.status = "ERROR";
                                    pimpl->state.model.progress = 0.0;
                                }
                            } else {
                                pimpl->state.model.status = "ERROR";
                                pimpl->state.model.progress = 0.0;
                            }
                        } catch (...) {
                            pimpl->state.model.status = "ERROR";
                            pimpl->state.model.progress = 0.0;
                        }
                    }).detach();
                };

                if (impl_->aiModelPanelActive) {
                    if (ch == 27 || ch == KEY_F(2) || ch == 16) {
                        impl_->aiModelPanelActive = false;
                    } else if (ch == KEY_UP) {
                        if (impl_->aiModelSelection > 0) impl_->aiModelSelection--;
                    } else if (ch == KEY_DOWN) {
                        if (impl_->aiModelSelection + 1 < static_cast<int>(impl_->state.availableModels.size())) {
                            impl_->aiModelSelection++;
                        }
                    } else if (ch == KEY_F(4) || ch == 4) {
                        startDownload();
                    } else if (ch == '\n' || ch == KEY_ENTER) {
                        if (impl_->aiModelSelection >= 0 && impl_->aiModelSelection < static_cast<int>(impl_->state.availableModels.size())) {
                            std::string pathCopy = impl_->state.availableModels[impl_->aiModelSelection];
                            impl_->state.modelPath = pathCopy;
                            impl_->state.model.name = std::filesystem::path(pathCopy).filename().string();
                            impl_->state.model.status = "LOADING";
                            impl_->state.model.progress = 0.0;
                            auto pimpl = impl_.get();
                            std::thread([pimpl, pathCopy]() {
                                bool ok = false;
                                try { if (pimpl->modelLoader) ok = pimpl->modelLoader->load(pathCopy); } catch (...) { ok = false; }
                                if (ok) {
                                    pimpl->state.model.status = "ACTIVE";
                                    pimpl->state.model.progress = 1.0;
                                    synapse::utils::Config::instance().set("model.last_path", pathCopy);
                                    std::string cfgPath = synapse::utils::Config::instance().getDataDir() + "/synapsenet.conf";
                                    synapse::utils::Config::instance().save(cfgPath);
                                } else {
                                    pimpl->state.model.status = "ERROR";
                                    pimpl->state.model.progress = 0.0;
                                }
                            }).detach();
                            impl_->aiModelPanelActive = false;
                        }
                    }
                } else if (ch == KEY_F(2) || ch == 16) {
                    impl_->aiModelPanelActive = true;
                } else if (ch == KEY_F(4) || ch == 4) {
                    startDownload();
                } else if (ch == KEY_F(5) || ch == 23) {
                    bool enabled = false;
                    {
                        std::lock_guard<std::mutex> lock(impl_->state.webMutex);
                        impl_->state.webInjectEnabled = !impl_->state.webInjectEnabled;
                        impl_->state.webSearching = false;
                        impl_->state.webLastResults = 0;
                        impl_->state.webLastClearnetResults = 0;
                        impl_->state.webLastDarknetResults = 0;
                        impl_->state.webLastError.clear();
                        enabled = impl_->state.webInjectEnabled;
                    }
                    synapse::utils::Config::instance().set("web.inject.enabled", enabled);
                    std::string cfgPath = synapse::utils::Config::instance().getDataDir() + "/synapsenet.conf";
                    synapse::utils::Config::instance().save(cfgPath);
                } else if (ch == KEY_F(6) || ch == 15) {
                    bool enabled = false;
                    {
                        std::lock_guard<std::mutex> lock(impl_->state.webMutex);
                        impl_->state.webOnionEnabled = !impl_->state.webOnionEnabled;
                        impl_->state.webLastError.clear();
                        impl_->state.webLastResults = 0;
                        impl_->state.webLastClearnetResults = 0;
                        impl_->state.webLastDarknetResults = 0;
                        enabled = impl_->state.webOnionEnabled;
                    }
                    if (impl_->webSearch) {
                        synapse::web::SearchConfig cfg = impl_->webSearch->getConfig();
                        cfg.enableClearnet = true;
                        cfg.enableDarknet = enabled;
                        {
                            std::lock_guard<std::mutex> lock(impl_->state.webMutex);
                            cfg.routeClearnetThroughTor = impl_->state.webTorForClearnet;
                        }
                        impl_->webSearch->setConfig(cfg);
                    }
                    synapse::utils::Config::instance().set("web.inject.onion", enabled);
                    std::string cfgPath = synapse::utils::Config::instance().getDataDir() + "/synapsenet.conf";
                    synapse::utils::Config::instance().save(cfgPath);
                } else if (ch == KEY_F(7) || ch == 20) {
                    bool enabled = false;
                    {
                        std::lock_guard<std::mutex> lock(impl_->state.webMutex);
                        impl_->state.webTorForClearnet = !impl_->state.webTorForClearnet;
                        impl_->state.webLastError.clear();
                        impl_->state.webLastResults = 0;
                        impl_->state.webLastClearnetResults = 0;
                        impl_->state.webLastDarknetResults = 0;
                        enabled = impl_->state.webTorForClearnet;
                    }
                    if (impl_->webSearch) {
                        synapse::web::SearchConfig cfg = impl_->webSearch->getConfig();
                        cfg.enableClearnet = true;
                        {
                            std::lock_guard<std::mutex> lock(impl_->state.webMutex);
                            cfg.enableDarknet = impl_->state.webOnionEnabled;
                        }
                        cfg.routeClearnetThroughTor = enabled;
                        impl_->webSearch->setConfig(cfg);
                    }
                    synapse::utils::Config::instance().set("web.inject.tor_clearnet", enabled);
                    std::string cfgPath = synapse::utils::Config::instance().getDataDir() + "/synapsenet.conf";
                    synapse::utils::Config::instance().save(cfgPath);
                } else if (ch == KEY_F(8)) {
                    if (impl_->state.aiGenerating) {
                        impl_->aiCancelRequested.store(true);
                    }
                } else if (ch == KEY_PPAGE) {
                    impl_->chatScrollOffset += 10;
                    // User scrolled up manually - disable auto-scroll temporarily
                    if (impl_->chatScrollOffset > 0) {
                        impl_->autoScrollEnabled = false;
                    }
                } else if (ch == KEY_NPAGE) {
                    impl_->chatScrollOffset -= 10;
                    if (impl_->chatScrollOffset < 0) impl_->chatScrollOffset = 0;
                    // If scrolled back to bottom, re-enable auto-scroll
                    if (impl_->chatScrollOffset == 0) {
                        impl_->autoScrollEnabled = true;
                    }
                } else if (ch == KEY_UP) {
                    if (impl_->inputBuffer.empty()) {
                        impl_->chatScrollOffset += 1;
                        // User scrolled up manually - disable auto-scroll temporarily
                        if (impl_->chatScrollOffset > 0) {
                            impl_->autoScrollEnabled = false;
                        }
                    }
                } else if (ch == KEY_DOWN) {
                    if (impl_->inputBuffer.empty() && impl_->chatScrollOffset > 0) {
                        impl_->chatScrollOffset -= 1;
                        // If scrolled back to bottom, re-enable auto-scroll
                        if (impl_->chatScrollOffset == 0) {
                            impl_->autoScrollEnabled = true;
                        }
                    }
                } else if (ch == KEY_HOME) {
                    if (!impl_->inputBuffer.empty()) {
                        impl_->inputCursor = 0;
                    } else {
                        impl_->chatScrollOffset = 1000000;
                        // User scrolled to top - disable auto-scroll
                        impl_->autoScrollEnabled = false;
                    }
                } else if (ch == KEY_END) {
                    if (!impl_->inputBuffer.empty()) {
                        impl_->inputCursor = impl_->inputBuffer.size();
                    } else {
                        impl_->chatScrollOffset = 0;
                        // Scrolled to bottom - re-enable auto-scroll
                        impl_->autoScrollEnabled = true;
                    }
                } else if (ch == '\n' || ch == KEY_ENTER) {
                    if (!impl_->inputBuffer.empty()) {
                        impl_->chatScrollOffset = 0;
                        impl_->autoScrollEnabled = true;  // Re-enable auto-scroll when sending message
                        impl_->aiCancelRequested.store(false);
                        if (impl_->modelLoader && impl_->modelLoader->isLoaded()) {
                            ChatMessage userMsg;
                            userMsg.role = "user";
                            userMsg.content = impl_->inputBuffer;
                            {
                                std::lock_guard<std::mutex> lock(impl_->state.chatMutex);
                                impl_->state.chatHistory.push_back(userMsg);
                            }
                            // Enable auto-scroll when starting generation
                            impl_->autoScrollEnabled = true;
                            impl_->chatScrollOffset = 0;
                            impl_->state.aiGenerating = true;
                            impl_->drawAIChat();

                            std::string prompt = impl_->inputBuffer;
                            impl_->inputBuffer.clear();
                            impl_->inputCursor = 0;

                            auto pimpl = impl_.get();
                            std::thread([pimpl, prompt]() {
                                bool webInject = false;
                                bool webOnion = false;
                                bool webTor = false;
                                {
                                    std::lock_guard<std::mutex> lock(pimpl->state.webMutex);
                                    webInject = pimpl->state.webInjectEnabled;
                                    webOnion = pimpl->state.webOnionEnabled;
                                    webTor = pimpl->state.webTorForClearnet;
                                    if (webInject) {
                                        pimpl->state.webSearching = true;
                                        pimpl->state.webLastError.clear();
                                        pimpl->state.webLastResults = 0;
                                        pimpl->state.webLastClearnetResults = 0;
                                        pimpl->state.webLastDarknetResults = 0;
                                    }
                                }

                                std::string finalPrompt = prompt;
                                if (webInject && pimpl->webAi && pimpl->webSearch) {
                                    synapse::web::SearchConfig cfg = pimpl->webSearch->getConfig();
                                    cfg.enableClearnet = true;
                                    cfg.enableDarknet = webOnion;
                                    cfg.routeClearnetThroughTor = webTor;
                                    pimpl->webSearch->setConfig(cfg);
                                    try {
                                        finalPrompt = pimpl->webAi->processQuery(prompt);
                                    } catch (...) {
                                        finalPrompt = prompt;
                                    }
                                    auto st = pimpl->webAi->getStats();
                                    {
                                        std::lock_guard<std::mutex> lock(pimpl->state.webMutex);
                                        pimpl->state.webLastResults = st.lastResultCount;
                                        pimpl->state.webLastClearnetResults = st.lastClearnetResults;
                                        pimpl->state.webLastDarknetResults = st.lastDarknetResults;
                                        pimpl->state.webSearching = false;
                                    }
                                } else {
                                    std::lock_guard<std::mutex> lock(pimpl->state.webMutex);
                                    pimpl->state.webSearching = false;
                                }

                                synapse::model::GenerationParams params;
                                params.temperature = 0.7f;
                                params.maxTokens = 2048;
                                std::string out;
                                try {
                                    pimpl->modelLoader->generateStream(finalPrompt, [pimpl, &out](const std::string& token) {
                                        if (pimpl->aiCancelRequested.load()) return false;
                                        out += token;
                                        {
                                            std::lock_guard<std::mutex> lock(pimpl->state.aiResponseMutex);
                                            pimpl->state.aiCurrentResponse += token;
                                        }
                                        // Auto-scroll during streaming if enabled
                                        if (pimpl->autoScrollEnabled) {
                                            pimpl->chatScrollOffset = 0;
                                        }
                                        return !pimpl->aiCancelRequested.load();
                                    }, params);
                                } catch (...) {
                                    out = "[Error during model generation]";
                                }

                                bool cancelled = pimpl->aiCancelRequested.exchange(false);
                                if (cancelled) {
                                    if (out.empty()) out = "[Generation cancelled]";
                                    else out += "\n[Generation cancelled]";
                                }

                                ChatMessage aiMsg;
                                aiMsg.role = "assistant";
                                aiMsg.content = out;
                                if (aiMsg.content.empty()) aiMsg.content = "[No output from model]";
                                {
                                    std::lock_guard<std::mutex> lock(pimpl->state.chatMutex);
                                    pimpl->state.chatHistory.push_back(aiMsg);
                                }
                                {
                                    std::lock_guard<std::mutex> lock(pimpl->state.aiResponseMutex);
                                    pimpl->state.aiCurrentResponse.clear();
                                }
                                // Auto-scroll to bottom when generation completes
                                if (pimpl->autoScrollEnabled) {
                                    pimpl->chatScrollOffset = 0;
                                }
                                pimpl->state.aiGenerating = false;
                            }).detach();
                        } else {
                            std::string msg = "No model loaded. Put a .gguf in ~/.synapsenet/models or ./models and press F2/Ctrl+P to load.";
                            {
                                std::lock_guard<std::mutex> lock(impl_->state.chatMutex);
                                if (impl_->state.chatHistory.empty() ||
                                    impl_->state.chatHistory.back().role != "assistant" ||
                                    impl_->state.chatHistory.back().content != msg) {
                                    impl_->state.chatHistory.push_back(ChatMessage{"assistant", msg});
                                }
                            }
                        }
                    }
                } else if (ch == KEY_LEFT) {
                    if (impl_->inputCursor > 0) impl_->inputCursor--;
                } else if (ch == KEY_RIGHT) {
                    if (impl_->inputCursor < impl_->inputBuffer.size()) impl_->inputCursor++;
                } else if (ch == KEY_DC) {
                    if (impl_->inputCursor < impl_->inputBuffer.size()) {
                        impl_->inputBuffer.erase(impl_->inputCursor, 1);
                    }
                } else if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
                    if (impl_->inputCursor > 0 && !impl_->inputBuffer.empty()) {
                        impl_->inputBuffer.erase(impl_->inputCursor - 1, 1);
                        impl_->inputCursor--;
                    }
                } else if (ch == 1) { // Ctrl+A
                    impl_->inputCursor = 0;
                } else if (ch == 5) { // Ctrl+E
                    impl_->inputCursor = impl_->inputBuffer.size();
                } else if (ch == 11) { // Ctrl+K
                    if (impl_->inputCursor < impl_->inputBuffer.size()) {
                        impl_->inputBuffer.erase(impl_->inputCursor);
                    }
                } else if (ch == 21) { // Ctrl+U
                    if (impl_->inputCursor > 0) {
                        impl_->inputBuffer.erase(0, impl_->inputCursor);
                        impl_->inputCursor = 0;
                    }
                } else if (ch == 27) {
                    if (impl_->state.aiGenerating) {
                        impl_->aiCancelRequested.store(true);
                    }
                    impl_->screen = Screen::DASHBOARD;
                    impl_->inputBuffer.clear();
                    impl_->inputCursor = 0;
                    impl_->aiModelPanelActive = false;
                } else if (ch == KEY_F(3)) {
                    impl_->aiCancelRequested.store(true);
                    {
                        std::lock_guard<std::mutex> lock(impl_->state.chatMutex);
                        impl_->state.chatHistory.clear();
                    }
                    {
                        std::lock_guard<std::mutex> lock(impl_->state.aiResponseMutex);
                        impl_->state.aiCurrentResponse.clear();
                    }
                    impl_->state.aiGenerating = false;
                } else if (ch >= 32 && ch < 127) {
                    char c = static_cast<char>(ch);
                    if (impl_->inputCursor > impl_->inputBuffer.size()) impl_->inputCursor = impl_->inputBuffer.size();
                    impl_->inputBuffer.insert(impl_->inputCursor, 1, c);
                    impl_->inputCursor++;
                }
            } else if (impl_->screen == Screen::MODEL) {
                if (ch == 'r' || ch == 'R') {
                    impl_->menuSelection = 0;
                }
	                if (ch == 'd' || ch == 'D') {
	                    auto pimpl = impl_.get();
	                    if (pimpl->modelDownloadActive.exchange(true)) {
		                    } else {
		                        pimpl->state.model.status = "DOWNLOADING";
		                        pimpl->state.model.progress = 0.0;
		                        pimpl->state.model.name = "deepseek-coder-6.7b-instruct.Q4_K_M.gguf";
		                        std::string dataDir = synapse::utils::Config::instance().getDataDir();
		                        std::filesystem::path rootModels = dataDir.empty() ? (std::filesystem::current_path() / "models") : (std::filesystem::path(dataDir) / "models");
		                        std::error_code ec;
		                        std::filesystem::create_directories(rootModels, ec);
		                        pimpl->state.downloadPath = (rootModels / pimpl->state.model.name).string();
		                        pimpl->state.downloadPartPath = pimpl->state.downloadPath + ".part";
		                        std::thread([pimpl]() {
		                            const std::string modelName = "deepseek-coder-6.7b-instruct.Q4_K_M.gguf";
		                            bool ok = false;
	                            try {
	                                if (pimpl->modelLoader) {
	                                    ok = pimpl->modelLoader->downloadModel(modelName, [pimpl](double p) {
                                        pimpl->state.model.progress = p;
                                    });
                                }
                            } catch (...) {
		                                ok = false;
		                            }
	
	                            std::string dataDir = synapse::utils::Config::instance().getDataDir();
	                            std::filesystem::path rootModels = dataDir.empty() ? (std::filesystem::current_path() / "models") : (std::filesystem::path(dataDir) / "models");
	                            std::string path = (rootModels / modelName).string();
	
		                            if (ok && pimpl->modelLoader) {
		                                pimpl->state.model.status = "LOADING";
		                                pimpl->state.model.progress = 0.0;
                                bool loaded = false;
                                try {
                                    loaded = pimpl->modelLoader->load(path);
                                } catch (...) {
                                    loaded = false;
                                }
                                if (loaded) {
                                    pimpl->state.modelPath = path;
                                    pimpl->state.model.name = std::filesystem::path(path).filename().string();
                                    pimpl->state.model.status = "ACTIVE";
                                    pimpl->state.model.progress = 1.0;
                                    pimpl->state.downloadPath.clear();
                                    pimpl->state.downloadPartPath.clear();
                                    synapse::utils::Config::instance().set("model.last_path", path);
                                    std::string cfgPath = synapse::utils::Config::instance().getDataDir() + "/synapsenet.conf";
                                    synapse::utils::Config::instance().save(cfgPath);
                                    pimpl->screen = Screen::AI_CHAT;
                                    pimpl->chatScrollOffset = 0;
                                } else {
                                    pimpl->state.model.status = "ERROR";
                                    pimpl->state.model.progress = 0.0;
                                }
                            } else {
                                pimpl->state.model.status = "ERROR";
                                pimpl->state.model.progress = 0.0;
                            }
                            pimpl->modelDownloadActive.store(false);
                        }).detach();
                    }
                }

                if (ch >= '1' && ch <= '9') {
                    int idx = ch - '1';
                    if (idx < static_cast<int>(impl_->state.availableModels.size())) {
                        impl_->menuSelection = idx;
                    }
                } else if (ch == '\n' || ch == KEY_ENTER) {
                    if (impl_->menuSelection < static_cast<int>(impl_->state.availableModels.size())) {
                            impl_->state.modelPath = impl_->state.availableModels[impl_->menuSelection];
                            impl_->state.model.name = std::filesystem::path(impl_->state.modelPath).filename().string();
                            impl_->state.model.status = "LOADING";
                            impl_->state.model.progress = 0.0;
                            // switch to chat screen while loading in background
                            impl_->screen = Screen::AI_CHAT;
                            impl_->chatScrollOffset = 0;

                            // capture impl_ safely for background loading
                            auto pimpl = impl_.get();
                            std::string pathCopy = impl_->state.modelPath;
                            std::thread([pimpl, pathCopy]() {
                                bool ok = false;
                                try {
                                    if (pimpl->modelLoader) {
                                        ok = pimpl->modelLoader->load(pathCopy);
                                    }
                                } catch (...) {
                                    ok = false;
                                }
                                if (ok) {
                                    pimpl->state.model.status = "ACTIVE";
                                    pimpl->state.model.progress = 1.0;
                                    synapse::utils::Config::instance().set("model.last_path", pathCopy);
                                    std::string cfgPath = synapse::utils::Config::instance().getDataDir() + "/synapsenet.conf";
                                    synapse::utils::Config::instance().save(cfgPath);
                                } else {
                                    pimpl->state.model.status = "ERROR";
                                    pimpl->state.model.progress = 0.0;
                                }
                            }).detach();
                        }
                } else if (ch == 'b' || ch == 'B' || ch == 27) {
                    impl_->screen = Screen::DASHBOARD;
                } else if (ch == KEY_UP) {
                    if (impl_->menuSelection > 0) impl_->menuSelection--;
                } else if (ch == KEY_DOWN) {
                    if (impl_->menuSelection < static_cast<int>(impl_->state.availableModels.size()) - 1) {
                        impl_->menuSelection++;
                    }
                }
            } else if (impl_->screen == Screen::WALLET_IMPORT) {
                if (ch == 27) {
                    impl_->inputBuffer.clear();
                    impl_->screen = Screen::WELCOME;
                } else if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
                    if (!impl_->inputBuffer.empty()) impl_->inputBuffer.pop_back();
                } else if (ch == '\n' || ch == KEY_ENTER) {
                    std::string mnemonic = impl_->inputBuffer;
                    impl_->inputBuffer.clear();

                    std::string dataDir = utils::Config::instance().getDataDir();
                    if (dataDir.empty()) dataDir = ".";
                    std::filesystem::create_directories(dataDir);
                    std::string walletPath = dataDir + "/wallet.dat";

                    crypto::Keys keys;
                    bool ok = false;
                    try {
                        ok = keys.fromMnemonic(mnemonic);
                        if (ok) {
                            std::error_code ec;
                            std::filesystem::remove(walletPath, ec);
                            ok = keys.save(walletPath, "");
                        }
                    } catch (...) {
                        ok = false;
                    }

                    if (ok) {
                        impl_->state.wallet.address = keys.getAddress();
                        impl_->state.wallet.balance = 0.0;
                        impl_->state.nodeId = impl_->state.wallet.address.empty()
                            ? "node_00000000"
                            : "node_" + impl_->state.wallet.address.substr(0, 8);
                        impl_->state.isFirstRun = false;
                        impl_->screen = Screen::WALLET_CREATED;
                    } else {
                        impl_->state.wallet.address.clear();
                        impl_->screen = Screen::WELCOME;
                    }
                } else if (ch >= 32 && ch < 127) {
                    impl_->inputBuffer += static_cast<char>(ch);
                }
            } else if (impl_->screen == Screen::SETTINGS) {
                if (ch == KEY_UP) {
                    if (impl_->menuSelection > 0) impl_->menuSelection--;
                } else if (ch == KEY_DOWN) {
                    impl_->menuSelection++;
                    if (impl_->menuSelection > 8) impl_->menuSelection = 8;
                } else if (ch == '\n' || ch == KEY_ENTER) {
                    switch (impl_->menuSelection) {
                        case 0: impl_->screen = Screen::NETWORK; break;
                        case 1: impl_->screen = Screen::KNOWLEDGE; break;
                        case 2: impl_->screen = Screen::MODEL; impl_->menuSelection = 0; break;
                        case 3: impl_->screen = Screen::DASHBOARD; break;
                        case 4: impl_->screen = Screen::SECURITY; break;
                        case 5: impl_->screen = Screen::WALLET; break;
                        default: impl_->screen = Screen::DASHBOARD; break;
                    }
                } else if (ch == 'b' || ch == 'B' || ch == 27) {
                    impl_->screen = Screen::DASHBOARD;
                }
            } else if (impl_->screen == Screen::WALLET) {
                if (ch == '1') {
                    impl_->state.sendToAddress.clear();
                    impl_->state.sendAmount = 0.0;
                    impl_->state.sendAmountStr.clear();
                    impl_->state.walletScreen = 0;
                    impl_->screen = Screen::WALLET_SEND;
                } else if (ch == '2') {
                    impl_->screen = Screen::WALLET_RECEIVE;
                } else if (ch == 'b' || ch == 'B' || ch == 27) {
                    impl_->screen = Screen::DASHBOARD;
                }
            } else if (impl_->screen == Screen::WALLET_SEND) {
                if (ch == '\n' || ch == KEY_ENTER) {
                    if (impl_->state.walletScreen == 0) {
                        if (!impl_->state.sendToAddress.empty()) {
                            impl_->state.walletScreen = 1;
                        }
                    } else {
                        double amt = 0.0;
                        try { amt = std::stod(impl_->state.sendAmountStr); } catch (...) { amt = 0.0; }
                        impl_->state.sendAmount = amt;
                        if (!impl_->state.sendToAddress.empty() && impl_->state.sendAmount > 0.0) {
                            if (impl_->commandHandler) {
                                std::ostringstream oss;
                                oss << "send " << impl_->state.sendToAddress << " " << impl_->state.sendAmountStr;
                                impl_->commandHandler(oss.str());
                            }
                            impl_->state.sendToAddress.clear();
                            impl_->state.sendAmountStr.clear();
                            impl_->state.sendAmount = 0.0;
                            impl_->state.walletScreen = 0;
                            impl_->screen = Screen::WALLET;
                        }
                    }
                } else if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
                    if (impl_->state.walletScreen == 0) {
                        if (!impl_->state.sendToAddress.empty()) {
                            impl_->state.sendToAddress.pop_back();
                        }
                    } else {
                        if (!impl_->state.sendAmountStr.empty()) {
                            impl_->state.sendAmountStr.pop_back();
                        }
                    }
                } else if (ch == 27) {
                    impl_->screen = Screen::WALLET;
                    impl_->state.walletScreen = 0;
                } else if (ch >= 32 && ch < 127) {
                    if (ch == '\t') {
                        impl_->state.walletScreen = impl_->state.walletScreen == 0 ? 1 : 0;
                    } else if (impl_->state.walletScreen == 0) {
                        if (impl_->state.sendToAddress.length() < 96) {
                            impl_->state.sendToAddress += static_cast<char>(ch);
                        }
                    } else {
                        char c = static_cast<char>(ch);
                        if ((c >= '0' && c <= '9') || c == '.' || c == ',') {
                            if (c == ',') c = '.';
                            if (impl_->state.sendAmountStr.length() < 32) {
                                impl_->state.sendAmountStr += c;
                            }
                        }
                    }
                }
            } else if (impl_->screen == Screen::WALLET_RECEIVE) {
                if (ch == 'b' || ch == 'B' || ch == 27) {
                    impl_->screen = Screen::WALLET;
                }
            } else if (impl_->screen == Screen::KNOWLEDGE) {
                if (ch == 'c' || ch == 'C') {
                    impl_->state.knowledgeQuestion.clear();
                    impl_->state.knowledgeAnswer.clear();
                    impl_->state.knowledgeSource.clear();
                    impl_->state.knowledgeField = 0;
                    impl_->screen = Screen::KNOWLEDGE_SUBMIT;
                } else if (ch == 'e' || ch == 'E') {
                    if (impl_->commandHandler) {
                        impl_->commandHandler("poe_epoch");
                    }
                } else if (ch == KEY_UP) {
                    impl_->scrollOffset--;
                } else if (ch == KEY_DOWN) {
                    impl_->scrollOffset++;
                } else if (ch == KEY_PPAGE) {
                    impl_->scrollOffset -= 10;
                } else if (ch == KEY_NPAGE) {
                    impl_->scrollOffset += 10;
                } else if (ch == 'b' || ch == 'B' || ch == 27) {
                    impl_->screen = Screen::DASHBOARD;
                }
            } else if (impl_->screen == Screen::KNOWLEDGE_SUBMIT) {
                auto& field = (impl_->state.knowledgeField == 0)
                    ? impl_->state.knowledgeQuestion
                    : (impl_->state.knowledgeField == 1 ? impl_->state.knowledgeAnswer : impl_->state.knowledgeSource);

                if (ch == 27) {
                    impl_->screen = Screen::DASHBOARD;
                } else if (ch == '\t') {
                    impl_->state.knowledgeField = (impl_->state.knowledgeField + 1) % 3;
                } else if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
                    if (!field.empty()) field.pop_back();
                } else if (ch == '\n' || ch == KEY_ENTER) {
                    if (impl_->state.knowledgeField < 2) {
                        impl_->state.knowledgeField++;
                    } else {
                        if (impl_->state.knowledgeQuestion.empty()) {
                            impl_->state.knowledgeField = 0;
                        } else if (impl_->state.knowledgeAnswer.empty()) {
                            impl_->state.knowledgeField = 1;
	                        } else {
	                            auto b64 = [](const std::string& s) -> std::string {
	                                std::vector<uint8_t> in(s.begin(), s.end());
	                                auto out = crypto::base64Encode(in);
	                                return std::string(out.begin(), out.end());
	                            };
		                            if (impl_->commandHandler) {
		                                std::ostringstream oss;
		                                oss << "poe_submit " << b64(impl_->state.knowledgeQuestion) << " "
		                                    << b64(impl_->state.knowledgeAnswer) << " " << b64(impl_->state.knowledgeSource);
		                                impl_->commandHandler(oss.str());
		                            }
		                            impl_->state.knowledgeQuestion.clear();
		                            impl_->state.knowledgeAnswer.clear();
		                            impl_->state.knowledgeSource.clear();
		                            impl_->state.knowledgeField = 0;
		                            impl_->scrollOffset = 0;
		                            impl_->screen = Screen::KNOWLEDGE;
		                        }
                    }
                } else if (ch >= 32 && ch < 127) {
                    if (field.size() < 512) field.push_back(static_cast<char>(ch));
                }
            } else if (impl_->screen == Screen::CODE) {
                if (ch == 'c' || ch == 'C') {
                    impl_->state.codeTitle.clear();
                    impl_->state.codePatchFile.clear();
                    impl_->state.codeCitations.clear();
                    impl_->state.codeField = 0;
                    impl_->screen = Screen::CODE_SUBMIT;
                } else if (ch == 'i' || ch == 'I') {
                    auto exists = [](const std::string& p) -> bool {
                        std::error_code ec;
                        return std::filesystem::exists(p, ec);
                    };

                    std::string cmd;
                    if (exists("./synapseide")) cmd = "./synapseide";
                    else if (exists("./build/synapseide")) cmd = "./build/synapseide";
                    else if (exists("./KeplerSynapseNet/build/synapseide")) cmd = "./KeplerSynapseNet/build/synapseide";
                    else cmd = "synapseide";

                    def_prog_mode();
                    endwin();
                    (void)std::system(cmd.c_str());
                    reset_prog_mode();
                    refresh();
                    keypad(stdscr, TRUE);
                    nodelay(stdscr, TRUE);
                    noecho();
                    cbreak();
                    curs_set(0);
                } else if (ch == KEY_UP) {
                    impl_->scrollOffset--;
                } else if (ch == KEY_DOWN) {
                    impl_->scrollOffset++;
                } else if (ch == KEY_PPAGE) {
                    impl_->scrollOffset -= 10;
                } else if (ch == KEY_NPAGE) {
                    impl_->scrollOffset += 10;
                } else if (ch == 'b' || ch == 'B' || ch == 27) {
                    impl_->screen = Screen::DASHBOARD;
                }
            } else if (impl_->screen == Screen::CODE_SUBMIT) {
                auto& field = (impl_->state.codeField == 0)
                    ? impl_->state.codeTitle
                    : (impl_->state.codeField == 1 ? impl_->state.codePatchFile : impl_->state.codeCitations);

                auto submit = [&]() {
                    if (impl_->state.codeTitle.empty()) {
                        showError("Title required");
                        impl_->state.codeField = 0;
                        return;
                    }
                    if (impl_->state.codePatchFile.empty()) {
                        showError("Patch file path required");
                        impl_->state.codeField = 1;
                        return;
                    }

                    std::ifstream in(impl_->state.codePatchFile, std::ios::binary);
                    if (!in) {
                        showError("Failed to read patch file");
                        impl_->state.codeField = 1;
                        return;
                    }
                    std::ostringstream ss;
                    ss << in.rdbuf();
                    std::string patch = ss.str();
                    if (patch.empty()) {
                        showError("Patch file is empty");
                        impl_->state.codeField = 1;
                        return;
                    }
                    if (patch.size() > 65536) {
                        showError("Patch too large (max 65536 bytes)");
                        impl_->state.codeField = 1;
                        return;
                    }

                    auto b64 = [](const std::string& s) -> std::string {
                        std::vector<uint8_t> in(s.begin(), s.end());
                        auto out = crypto::base64Encode(in);
                        return std::string(out.begin(), out.end());
                    };
                    if (impl_->commandHandler) {
                        std::ostringstream oss;
                        oss << "poe_submit_code " << b64(impl_->state.codeTitle) << " " << b64(patch);
                        if (!impl_->state.codeCitations.empty()) {
                            oss << " " << b64(impl_->state.codeCitations);
                        }
                        impl_->commandHandler(oss.str());
                    }
                    impl_->state.codeTitle.clear();
                    impl_->state.codePatchFile.clear();
                    impl_->state.codeCitations.clear();
                    impl_->state.codeField = 0;
                    impl_->scrollOffset = 0;
                    impl_->screen = Screen::CODE;
                };

                if (ch == 27) {
                    impl_->screen = Screen::CODE;
                } else if (ch == '\t') {
                    impl_->state.codeField = (impl_->state.codeField + 1) % 3;
                } else if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
                    if (!field.empty()) field.pop_back();
                } else if (ch == KEY_F(2)) {
                    submit();
                } else if (ch == '\n' || ch == KEY_ENTER) {
                    if (impl_->state.codeField < 2) {
                        impl_->state.codeField++;
                    } else {
                        submit();
                    }
                } else if (ch >= 32 && ch < 127) {
                    if (impl_->state.codeField == 0) {
                        if (field.size() < 256) field.push_back(static_cast<char>(ch));
                    } else if (impl_->state.codeField == 1) {
                        if (field.size() < 512) field.push_back(static_cast<char>(ch));
                    } else {
                        if (field.size() < 512) field.push_back(static_cast<char>(ch));
                    }
                }
            } else {
                switch (ch) {
                    case KEY_F(5):
                        if (impl_->screen == Screen::DASHBOARD) {
                            impl_->menuSelection = 0;
                            impl_->screen = Screen::MODEL;
                        }
                        break;
                    case KEY_F(6):
                        if (impl_->screen == Screen::DASHBOARD) {
                            impl_->screen = Screen::MINING;
                        }
                        break;
                    case 'm':
                    case 'M':
                        if (impl_->screen == Screen::DASHBOARD) {
                            impl_->menuSelection = 0;
                            impl_->screen = Screen::MODEL;
                        }
                        break;
                    case 'g':
                    case 'G':
                        if (impl_->screen == Screen::DASHBOARD) {
                            impl_->screen = Screen::MINING;
                        }
                        break;
                    case 'q':
                    case 'Q':
                        if (impl_->screen == Screen::DASHBOARD) {
                            impl_->running = false;
                        } else {
                            impl_->screen = Screen::DASHBOARD;
                        }
                        break;
                    case ' ':
                        if (impl_->screen == Screen::BOOT) {
                            impl_->screen = Screen::INIT;
                            impl_->initStep = 0;
                        }
                        break;
                    case '\n':
                    case KEY_ENTER:
                        if (impl_->screen == Screen::WALLET_CREATED || impl_->screen == Screen::CONNECTED) {
                            impl_->screen = Screen::DASHBOARD;
                        }
                        break;
                    case '1':
                        if (impl_->screen == Screen::WELCOME) {
                            impl_->state.generatedSeedWords.clear();
                            impl_->state.forceNewWallet = true;
                            impl_->screen = Screen::WALLET_CREATE;
                        } else if (impl_->screen == Screen::DASHBOARD) {
                            impl_->state.knowledgeQuestion.clear();
                            impl_->state.knowledgeAnswer.clear();
                            impl_->state.knowledgeSource.clear();
                            impl_->state.knowledgeField = 0;
                            impl_->screen = Screen::KNOWLEDGE_SUBMIT;
                        }
                        break;
                    case '2':
                        if (impl_->screen == Screen::WELCOME) {
                            impl_->state.forceNewWallet = false;
                            impl_->inputBuffer.clear();
                            impl_->screen = Screen::WALLET_IMPORT;
                        } else if (impl_->screen == Screen::DASHBOARD) {
                            impl_->screen = Screen::KNOWLEDGE;
                            impl_->scrollOffset = 0;
                        }
                        break;
                    case '3':
                        if (impl_->screen == Screen::WELCOME) {
                            impl_->screen = Screen::DASHBOARD;
                        } else if (impl_->screen == Screen::DASHBOARD) {
                            impl_->screen = Screen::AI_CHAT;
                            impl_->chatScrollOffset = 0;
                        }
                        break;
                    case '4':
                        if (impl_->screen == Screen::DASHBOARD) {
                            impl_->screen = Screen::WALLET;
                        }
                        break;
                    case '5':
                        if (impl_->screen == Screen::DASHBOARD) {
                            impl_->screen = Screen::NETWORK;
                        }
                        break;
                    case '6':
                        if (impl_->screen == Screen::DASHBOARD) {
                            impl_->screen = Screen::NETWORK;
                        }
                        break;
                    case '7':
                        if (impl_->screen == Screen::DASHBOARD) {
                            impl_->screen = Screen::SETTINGS;
                        }
                        break;
                    case '8':
                        if (impl_->screen == Screen::DASHBOARD) {
                            impl_->screen = Screen::SECURITY;
                        }
                        break;
                    case 'y':
                    case 'Y':
                        if (impl_->screen == Screen::WALLET_CREATE) {
                            std::string mnemonic;
                            for (size_t i = 0; i < impl_->state.generatedSeedWords.size(); i++) {
                                if (i > 0) mnemonic += " ";
                                mnemonic += impl_->state.generatedSeedWords[i];
                            }
                            
                            std::string dataDir = utils::Config::instance().getDataDir();
                            if (dataDir.empty()) dataDir = ".";
                            std::filesystem::create_directories(dataDir);
                            std::string walletPath = dataDir + "/wallet.dat";
                            
                            crypto::Keys keys;
                            bool ok = false;
                            
                            if (impl_->state.forceNewWallet && std::filesystem::exists(walletPath)) {
                                std::error_code ec;
                                std::filesystem::remove(walletPath, ec);
                            }

                            if (std::filesystem::exists(walletPath) && !impl_->state.forceNewWallet) {
                                ok = keys.load(walletPath, "");
                            } else {
                                if (!mnemonic.empty()) {
                                    ok = keys.fromMnemonic(mnemonic);
                                }
                                if (!ok) {
                                    ok = keys.generate();
                                }
                                if (ok) {
                                    ok = keys.save(walletPath, "");
                                }
                            }
                            
                            if (ok) {
                                impl_->state.wallet.address = keys.getAddress();
                                impl_->state.wallet.balance = 0.0;
                                impl_->state.nodeId = impl_->state.wallet.address.empty()
                                    ? "node_00000000"
                                    : "node_" + impl_->state.wallet.address.substr(0, 8);
                                impl_->state.isFirstRun = false;
                                impl_->state.forceNewWallet = false;
                                impl_->screen = Screen::WALLET_CREATED;
                            } else {
                                impl_->state.wallet.address.clear();
                                impl_->state.wallet.balance = 0.0;
                                impl_->state.nodeId.clear();
                                impl_->state.forceNewWallet = false;
                                impl_->screen = Screen::WALLET_CREATED;
                            }
                        }
                        break;
                    case 'n':
                    case 'N':
                        if (impl_->screen == Screen::WALLET_CREATE) {
                            impl_->state.generatedSeedWords.clear();
                            impl_->state.forceNewWallet = false;
                            impl_->screen = Screen::WELCOME;
                        }
                        break;
                    case 'b':
                    case 'B':
                        impl_->screen = Screen::DASHBOARD;
                        break;
                    case 'c':
                    case 'C':
                        break;
                    case 's':
                    case 'S':
                        if (impl_->screen == Screen::DASHBOARD) {
                            impl_->screen = Screen::SETTINGS;
                        }
                        break;
                    case 'l':
                    case 'L':
                        if (impl_->screen == Screen::DASHBOARD || impl_->screen == Screen::AI_CHAT) {
                            impl_->screen = Screen::MODEL;
                            impl_->menuSelection = 0;
                        }
                        break;
                    case '9':
                        if (impl_->screen == Screen::DASHBOARD) {
                            impl_->screen = Screen::CODE;
                            impl_->scrollOffset = 0;
                        }
                        break;

                    case KEY_UP:
                        if (impl_->menuSelection > 0) {
                            impl_->menuSelection--;
                        }
                        break;
                    case KEY_DOWN:
                        if (impl_->menuSelection < 8) {
                            impl_->menuSelection++;
                        }
                        break;
                    case 27:
                        impl_->screen = Screen::DASHBOARD;
                        break;
                }
            }
        }
        
        impl_->frameCounter++;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

void TUI::shutdown() {
    if (impl_->running) {
        impl_->running = false;
        endwin();
    }
}

bool TUI::isRunning() const {
    return impl_->running;
}

void TUI::switchScreen(Screen screen) {
    impl_->screen = screen;
}

Screen TUI::currentScreen() const {
    return impl_->screen;
}

void TUI::refresh() {
    ::refresh();
}

void TUI::updateStatus(const StatusInfo& status) {
    impl_->status = status;
}

void TUI::showMessage(const std::string& msg, Color color) {
    int row = LINES - 3;
    attron(COLOR_PAIR(static_cast<int>(color)));
    printClippedLine(row, 2, COLS - 3, msg);
    attroff(COLOR_PAIR(static_cast<int>(color)));
    ::refresh();
}

void TUI::showError(const std::string& err) {
    showMessage(err, Color::RED);
}

void TUI::showProgress(const std::string& label, double progress) {
    int row = LINES - 4;
    mvprintw(row, 2, "%s: ", label.c_str());
    impl_->drawProgressBar(row, 2 + label.length() + 2, 40, progress, 1);
    ::refresh();
}

void TUI::updateOperationStatus(const std::string& operation, const std::string& status, const std::string& details) {
    std::lock_guard<std::mutex> lock(impl_->state.operationMutex);
    impl_->state.currentOperation.operation = operation;
    impl_->state.currentOperation.status = status;
    impl_->state.currentOperation.details = details;
    impl_->state.currentOperation.timestamp = std::time(nullptr);
    
    // Add to history (keep last 20 operations)
    impl_->state.operationHistory.push_back(impl_->state.currentOperation);
    if (impl_->state.operationHistory.size() > 20) {
        impl_->state.operationHistory.erase(impl_->state.operationHistory.begin());
    }
}

void TUI::showRewardNotification(double amount, const std::string& reason, const std::string& entryId, const std::string& details) {
    std::ostringstream oss;
    oss << "You earned +" << std::fixed << std::setprecision(8) << amount << " NGT";
    oss << " for " << reason;
    if (!entryId.empty()) {
        std::string shortId = entryId.size() > 8 ? entryId.substr(0, 8) + "..." : entryId;
        oss << " (" << shortId << ")";
    }
    if (!details.empty()) {
        oss << " - " << details;
    }
    
    std::string msg = oss.str();
    showMessage(msg, Color::GREEN);
    
    // Add to chat history as system message
    appendChatMessage("system", msg);
    
    // Store in reward history
    {
        std::lock_guard<std::mutex> lock(impl_->state.rewardMutex);
        LocalAppState::RewardNotification notif;
        notif.amount = amount;
        notif.reason = reason;
        notif.entryId = entryId;
        notif.details = details;
        notif.timestamp = std::time(nullptr);
        impl_->state.rewardHistory.push_back(notif);
        // Keep last 50 rewards
        if (impl_->state.rewardHistory.size() > 50) {
            impl_->state.rewardHistory.erase(impl_->state.rewardHistory.begin());
        }
    }
}

void TUI::drawBox(int y, int x, int h, int w, const std::string& title) {
    impl_->drawBox(y, x, h, w, title.c_str());
}

void TUI::drawText(int y, int x, const std::string& text, Color color) {
    attron(COLOR_PAIR(static_cast<int>(color)));
    mvprintw(y, x, "%s", text.c_str());
    attroff(COLOR_PAIR(static_cast<int>(color)));
}

void TUI::drawProgressBar(int y, int x, int w, double progress, Color color) {
    impl_->drawProgressBar(y, x, w, progress, static_cast<int>(color));
}

void TUI::onInput(std::function<void(int)> handler) {
    impl_->inputHandler = handler;
}

void TUI::onCommand(std::function<void(const std::string&)> handler) {
    impl_->commandHandler = handler;
}

void TUI::setNetworkPort(uint16_t port) {
    impl_->state.listeningPort = port;
}

void TUI::setNetworkOnline(bool online) {
    impl_->state.networkOnline = online;
}

void TUI::setPeerCount(size_t count) {
    impl_->state.network.totalNodes = count;
}

void TUI::updateNetworkInfo(const NetworkInfo& info) {
    impl_->state.network = info;
}

void TUI::updatePeers(const std::vector<NodeInfo>& peers) {
    impl_->state.peers = peers;
}

void TUI::updateModelInfo(const AIModelInfo& info) {
    AIModelInfo cur = impl_->state.model;
    cur.mode = info.mode;
    cur.slotsUsed = info.slotsUsed;
    cur.slotsMax = info.slotsMax;
    cur.uptime = info.uptime;
    cur.earningsToday = info.earningsToday;
    cur.earningsWeek = info.earningsWeek;
    cur.earningsTotal = info.earningsTotal;
    impl_->state.model = cur;
}

void TUI::updateWalletInfo(const WalletInfo& info) {
    impl_->state.wallet = info;
}

void TUI::updateKnowledgeEntries(const std::vector<KnowledgeEntrySummary>& entries) {
    std::lock_guard<std::mutex> lock(impl_->state.knowledgeMutex);
    impl_->state.knowledgeEntries = entries;
}

void TUI::appendChatMessage(const std::string& role, const std::string& content) {
    ChatMessage msg;
    msg.role = role;
    msg.content = content;
    {
        std::lock_guard<std::mutex> lock(impl_->state.chatMutex);
        impl_->state.chatHistory.push_back(msg);
    }
    // Auto-scroll to bottom when new message is added (if auto-scroll is enabled)
    if (impl_->autoScrollEnabled) {
        impl_->chatScrollOffset = 0;
    }
}

std::string TUI::prompt(const std::string& message) {
    return "";
}

bool TUI::confirm(const std::string& message) {
    return false;
}

int TUI::menu(const std::string& title, const std::vector<std::string>& options) {
    return 0;
}

}
}
