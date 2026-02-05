#pragma once

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <cstdint>

struct _win_st;
typedef struct _win_st WINDOW;

namespace synapse {
namespace tui {

enum class Screen {
    BOOT,
    INIT,
    NETWORK_DISCOVERY,
    SYNCING,
    WEB_PROMPT,
    WELCOME,
    WALLET_CREATE,
    WALLET_CREATED,
    WALLET_IMPORT,
    CONNECTED,
    DASHBOARD,
    WALLET,
    WALLET_SEND,
    WALLET_RECEIVE,
    NETWORK,
    KNOWLEDGE,
    KNOWLEDGE_SUBMIT,
    CODE,
    CODE_SUBMIT,
    AI_CHAT,
    MODEL,
    MINING,
    SETTINGS,
    SECURITY,
    HELP
};

enum class Color {
    DEFAULT = 0,
    GREEN = 1,
    YELLOW = 2,
    RED = 3,
    CYAN = 4,
    MAGENTA = 5,
    BLUE = 6,
    WHITE = 7
};

enum class StartupState {
    LOGO,
    INIT_PROGRESS,
    WALLET_CHOICE,
    SEED_DISPLAY,
    SEED_CONFIRM,
    SEED_IMPORT,
    PASSWORD_ENTRY,
    SYNCING,
    ERROR,
    COMPLETE
};

struct WalletInfo {
    std::string address;
    double balance;
    double pending;
    double staked;
    double totalEarned;
};

struct NetworkInfo {
    uint64_t totalNodes;
    uint64_t knowledgeEntries;
    double networkSize;
    double yourStorage;
    double syncProgress;
    bool synced;
    uint64_t knowledgeFinalized;
    uint64_t knowledgePending;
    // Discovery diagnostics (best-effort; 0 if unavailable)
    uint64_t knownPeers = 0;
    uint64_t connectedPeers = 0;
    uint64_t bootstrapNodes = 0;
    uint64_t dnsSeeds = 0;
    uint64_t dnsQueries = 0;
    uint64_t peerExchanges = 0;
    uint64_t lastPeerRefresh = 0;
    uint64_t lastAnnounce = 0;
};

struct AIModelInfo {
    std::string name;
    std::string status;
    double progress;
    std::string mode;
    int slotsUsed;
    int slotsMax;
    double uptime;
    double earningsToday;
    double earningsWeek;
    double earningsTotal;
};

struct NodeInfo {
    std::string nodeId;
    std::string id;
    std::string address;
    std::string location;
    uint16_t port;
    uint64_t latency;
    int ping;
    std::string version;
    bool isInbound;
};

struct ContributionInfo {
    std::string type;
    std::string name;
    std::string description;
    std::string time;
    double reward;
    uint64_t timestamp;
};

struct KnowledgeEntrySummary {
    std::string submitId;
    std::string title;
    uint8_t contentType = 0;
    bool finalized;
    uint32_t votes;
    uint32_t requiredVotes;
    double acceptanceReward;
    bool acceptanceRewardCredited;
};

struct StatusInfo {
    uint64_t blockHeight;
    uint64_t peerCount;
    uint64_t knowledgeCount;
    uint64_t balance;
    std::string walletAddress;
    std::string modelName;
    std::string modelStatus;
    double syncProgress;
};

class StartupScreen {
public:
    StartupScreen();
    ~StartupScreen();
    
    void init(WINDOW* win, int width, int height);
    void draw();
    bool handleInput(int ch);
    
    void setState(StartupState state);
    StartupState getState() const;
    
    void setProgress(int percent, const std::string& message);
    void generateSeedWords();
    void setSeedWords(const std::vector<std::string>& words);
    std::vector<std::string> getSeedWords() const;
    void setWalletExists(bool exists);
    void setSyncStatus(int peers, int blocks, int totalBlocks);
    void setError(const std::string& error);
    
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class DashboardScreen {
public:
    DashboardScreen();
    ~DashboardScreen();
    
    void init(WINDOW* win, int width, int height);
    void draw();
    bool handleInput(int ch);
    
    void setWalletInfo(const WalletInfo& info);
    void setNetworkInfo(const NetworkInfo& info);
    void setModelInfo(const AIModelInfo& info);
    void setPeers(const std::vector<NodeInfo>& peers);
    void setContributions(const std::vector<ContributionInfo>& contributions);
    
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class TUI {
public:
    TUI();
    ~TUI();
    
    bool init();
    void run();
    void shutdown();
    bool isRunning() const;
    
    void switchScreen(Screen screen);
    Screen currentScreen() const;
    void refresh();
    
    void updateStatus(const StatusInfo& status);
    void showMessage(const std::string& msg, Color color = Color::GREEN);
    void showError(const std::string& err);
    void showProgress(const std::string& label, double progress);
    void updateOperationStatus(const std::string& operation, const std::string& status, const std::string& details = "");
    void showRewardNotification(double amount, const std::string& reason, const std::string& entryId, const std::string& details = "");
    
    void drawBox(int y, int x, int h, int w, const std::string& title = "");
    void drawText(int y, int x, const std::string& text, Color color = Color::DEFAULT);
    void drawProgressBar(int y, int x, int w, double progress, Color color = Color::GREEN);
    
    void onInput(std::function<void(int)> handler);
    void onCommand(std::function<void(const std::string&)> handler);
    
    void setNetworkPort(uint16_t port);
    void setNetworkOnline(bool online);
    void setPeerCount(size_t count);
    void updateNetworkInfo(const NetworkInfo& info);
    void updatePeers(const std::vector<NodeInfo>& peers);
    void updateModelInfo(const AIModelInfo& info);
    void updateWalletInfo(const WalletInfo& info);
    void updateKnowledgeEntries(const std::vector<KnowledgeEntrySummary>& entries);
    void appendChatMessage(const std::string& role, const std::string& content);
    
    std::string prompt(const std::string& message);
    bool confirm(const std::string& message);
    int menu(const std::string& title, const std::vector<std::string>& options);
    
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}
}
