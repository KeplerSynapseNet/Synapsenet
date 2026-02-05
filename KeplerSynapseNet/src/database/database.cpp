#include "database/database.h"
#include <sqlite3.h>
#include <mutex>
#include <stdexcept>

namespace synapse {
namespace database {

struct WriteBatch::Impl {
    std::vector<std::pair<std::string, std::vector<uint8_t>>> puts;
    std::vector<std::string> dels;
};

WriteBatch::WriteBatch() : impl_(std::make_unique<Impl>()) {}
WriteBatch::~WriteBatch() = default;

void WriteBatch::put(const std::string& key, const std::vector<uint8_t>& value) {
    impl_->puts.emplace_back(key, value);
}

void WriteBatch::del(const std::string& key) {
    impl_->dels.push_back(key);
}

void WriteBatch::clear() {
    impl_->puts.clear();
    impl_->dels.clear();
}

struct Iterator::Impl {
    sqlite3_stmt* stmt = nullptr;
    bool valid_ = false;
    std::string currentKey;
    std::vector<uint8_t> currentValue;
};

Iterator::Iterator() : impl_(std::make_unique<Impl>()) {}
Iterator::~Iterator() {
    if (impl_->stmt) sqlite3_finalize(impl_->stmt);
}

void Iterator::seekToFirst() {
    if (impl_->stmt) {
        sqlite3_reset(impl_->stmt);
        next();
    }
}

void Iterator::seekToLast() { impl_->valid_ = false; }

void Iterator::seek(const std::string& key) {
    impl_->valid_ = false;
}

bool Iterator::valid() const { return impl_->valid_; }

void Iterator::next() {
    if (!impl_->stmt) { impl_->valid_ = false; return; }
    int rc = sqlite3_step(impl_->stmt);
    if (rc == SQLITE_ROW) {
        impl_->currentKey = reinterpret_cast<const char*>(sqlite3_column_text(impl_->stmt, 0));
        const void* blob = sqlite3_column_blob(impl_->stmt, 1);
        int blobSize = sqlite3_column_bytes(impl_->stmt, 1);
        impl_->currentValue.assign(static_cast<const uint8_t*>(blob), 
                                   static_cast<const uint8_t*>(blob) + blobSize);
        impl_->valid_ = true;
    } else {
        impl_->valid_ = false;
    }
}

void Iterator::prev() { impl_->valid_ = false; }
std::string Iterator::key() const { return impl_->currentKey; }
std::vector<uint8_t> Iterator::value() const { return impl_->currentValue; }

struct Database::Impl {
    sqlite3* db = nullptr;
    std::string path;
    mutable std::mutex mtx;
    bool isOpen = false;
};

Database::Database() : impl_(std::make_unique<Impl>()) {}

Database::~Database() { close(); }

bool Database::open(const std::string& path) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (impl_->isOpen) return false;
    
    int rc = sqlite3_open(path.c_str(), &impl_->db);
    if (rc != SQLITE_OK) return false;
    
    const char* createTable = 
        "CREATE TABLE IF NOT EXISTS kv ("
        "key TEXT PRIMARY KEY,"
        "value BLOB"
        ");";
    
    char* errMsg = nullptr;
    rc = sqlite3_exec(impl_->db, createTable, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(errMsg);
        sqlite3_close(impl_->db);
        impl_->db = nullptr;
        return false;
    }
    
    sqlite3_exec(impl_->db, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(impl_->db, "PRAGMA synchronous=NORMAL;", nullptr, nullptr, nullptr);
    
    impl_->path = path;
    impl_->isOpen = true;
    return true;
}

void Database::close() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (impl_->db) {
        sqlite3_close(impl_->db);
        impl_->db = nullptr;
    }
    impl_->isOpen = false;
}

bool Database::isOpen() const {
    return impl_->isOpen;
}

bool Database::put(const std::string& key, const std::vector<uint8_t>& value) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (!impl_->db) return false;
    
    sqlite3_stmt* stmt;
    const char* sql = "INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?);";
    
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    
    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, value.data(), value.size(), SQLITE_STATIC);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return rc == SQLITE_DONE;
}

bool Database::put(const std::string& key, const std::string& value) {
    return put(key, std::vector<uint8_t>(value.begin(), value.end()));
}

std::vector<uint8_t> Database::get(const std::string& key) const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (!impl_->db) return {};
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT value FROM kv WHERE key = ?;";
    
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr) != SQLITE_OK) return {};
    
    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);
    
    std::vector<uint8_t> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const void* blob = sqlite3_column_blob(stmt, 0);
        int blobSize = sqlite3_column_bytes(stmt, 0);
        result.assign(static_cast<const uint8_t*>(blob), 
                      static_cast<const uint8_t*>(blob) + blobSize);
    }
    
    sqlite3_finalize(stmt);
    return result;
}

std::string Database::getString(const std::string& key) const {
    auto data = get(key);
    return std::string(data.begin(), data.end());
}

bool Database::del(const std::string& key) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (!impl_->db) return false;
    
    sqlite3_stmt* stmt;
    const char* sql = "DELETE FROM kv WHERE key = ?;";
    
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    
    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return rc == SQLITE_DONE;
}

bool Database::exists(const std::string& key) const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (!impl_->db) return false;
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT 1 FROM kv WHERE key = ? LIMIT 1;";
    
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    
    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);
    
    bool found = sqlite3_step(stmt) == SQLITE_ROW;
    sqlite3_finalize(stmt);
    
    return found;
}

bool Database::write(WriteBatch& batch) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (!impl_->db) return false;
    
    sqlite3_exec(impl_->db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);
    
    for (const auto& [key, value] : batch.impl_->puts) {
        sqlite3_stmt* stmt;
        const char* sql = "INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?);";
        if (sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_blob(stmt, 2, value.data(), value.size(), SQLITE_STATIC);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
    
    for (const auto& key : batch.impl_->dels) {
        sqlite3_stmt* stmt;
        const char* sql = "DELETE FROM kv WHERE key = ?;";
        if (sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
    
    sqlite3_exec(impl_->db, "COMMIT;", nullptr, nullptr, nullptr);
    batch.clear();
    return true;
}

std::unique_ptr<Iterator> Database::newIterator() const {
    auto iter = std::make_unique<Iterator>();
    
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (impl_->db) {
        const char* sql = "SELECT key, value FROM kv ORDER BY key;";
        sqlite3_prepare_v2(impl_->db, sql, -1, &iter->impl_->stmt, nullptr);
    }
    
    return iter;
}

void Database::forEach(const std::string& prefix, 
                       std::function<bool(const std::string&, const std::vector<uint8_t>&)> fn) const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (!impl_->db) return;
    
    sqlite3_stmt* stmt;
    std::string sql = "SELECT key, value FROM kv";
    if (!prefix.empty()) {
        sql += " WHERE key LIKE ? || '%'";
    }
    sql += " ORDER BY key;";
    
    if (sqlite3_prepare_v2(impl_->db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return;
    
    if (!prefix.empty()) {
        sqlite3_bind_text(stmt, 1, prefix.c_str(), -1, SQLITE_STATIC);
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string key = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        const void* blob = sqlite3_column_blob(stmt, 1);
        int blobSize = sqlite3_column_bytes(stmt, 1);
        std::vector<uint8_t> value(static_cast<const uint8_t*>(blob),
                                   static_cast<const uint8_t*>(blob) + blobSize);
        if (!fn(key, value)) break;
    }
    
    sqlite3_finalize(stmt);
}

std::vector<std::string> Database::keys(const std::string& prefix) const {
    std::vector<std::string> result;
    forEach(prefix, [&result](const std::string& key, const std::vector<uint8_t>&) {
        result.push_back(key);
        return true;
    });
    return result;
}

size_t Database::count(const std::string& prefix) const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (!impl_->db) return 0;
    
    sqlite3_stmt* stmt;
    std::string sql = "SELECT COUNT(*) FROM kv";
    if (!prefix.empty()) {
        sql += " WHERE key LIKE ? || '%'";
    }
    sql += ";";
    
    if (sqlite3_prepare_v2(impl_->db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return 0;
    
    if (!prefix.empty()) {
        sqlite3_bind_text(stmt, 1, prefix.c_str(), -1, SQLITE_STATIC);
    }
    
    size_t cnt = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        cnt = sqlite3_column_int64(stmt, 0);
    }
    
    sqlite3_finalize(stmt);
    return cnt;
}

bool Database::compact() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (!impl_->db) return false;
    return sqlite3_exec(impl_->db, "VACUUM;", nullptr, nullptr, nullptr) == SQLITE_OK;
}

std::string Database::getPath() const {
    return impl_->path;
}

uint64_t Database::size() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (!impl_->db) return 0;
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(impl_->db, "SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size();", 
                           -1, &stmt, nullptr) != SQLITE_OK) {
        return 0;
    }
    
    uint64_t sz = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        sz = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return sz;
}

bool Database::backup(const std::string& destPath) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (!impl_->db) return false;
    
    sqlite3* destDb;
    if (sqlite3_open(destPath.c_str(), &destDb) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_backup* bkp = sqlite3_backup_init(destDb, "main", impl_->db, "main");
    if (!bkp) {
        sqlite3_close(destDb);
        return false;
    }
    
    sqlite3_backup_step(bkp, -1);
    sqlite3_backup_finish(bkp);
    
    int rc = sqlite3_errcode(destDb);
    sqlite3_close(destDb);
    
    return rc == SQLITE_OK;
}

bool Database::restore(const std::string& srcPath) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (!impl_->db) return false;
    
    sqlite3* srcDb;
    if (sqlite3_open(srcPath.c_str(), &srcDb) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_backup* bkp = sqlite3_backup_init(impl_->db, "main", srcDb, "main");
    if (!bkp) {
        sqlite3_close(srcDb);
        return false;
    }
    
    sqlite3_backup_step(bkp, -1);
    sqlite3_backup_finish(bkp);
    
    int rc = sqlite3_errcode(impl_->db);
    sqlite3_close(srcDb);
    
    return rc == SQLITE_OK;
}

bool Database::beginTransaction() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (!impl_->db) return false;
    return sqlite3_exec(impl_->db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr) == SQLITE_OK;
}

bool Database::commitTransaction() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (!impl_->db) return false;
    return sqlite3_exec(impl_->db, "COMMIT;", nullptr, nullptr, nullptr) == SQLITE_OK;
}

bool Database::rollbackTransaction() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (!impl_->db) return false;
    return sqlite3_exec(impl_->db, "ROLLBACK;", nullptr, nullptr, nullptr) == SQLITE_OK;
}

std::vector<std::pair<std::string, std::vector<uint8_t>>> Database::getRange(
    const std::string& startKey, const std::string& endKey, size_t limit) const {
    
    std::vector<std::pair<std::string, std::vector<uint8_t>>> results;
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (!impl_->db) return results;
    
    sqlite3_stmt* stmt;
    std::string sql = "SELECT key, value FROM kv WHERE key >= ? AND key < ? ORDER BY key";
    if (limit > 0) {
        sql += " LIMIT " + std::to_string(limit);
    }
    sql += ";";
    
    if (sqlite3_prepare_v2(impl_->db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        return results;
    }
    
    sqlite3_bind_text(stmt, 1, startKey.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, endKey.c_str(), -1, SQLITE_STATIC);
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string key = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        const void* blob = sqlite3_column_blob(stmt, 1);
        int blobSize = sqlite3_column_bytes(stmt, 1);
        std::vector<uint8_t> value(static_cast<const uint8_t*>(blob),
                                    static_cast<const uint8_t*>(blob) + blobSize);
        results.emplace_back(key, value);
    }
    
    sqlite3_finalize(stmt);
    return results;
}

bool Database::clear() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (!impl_->db) return false;
    return sqlite3_exec(impl_->db, "DELETE FROM kv;", nullptr, nullptr, nullptr) == SQLITE_OK;
}

}
}
