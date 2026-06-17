// src/core/note_file_path.cpp
// Plaintext ledger – Java-style path traversal (no encryption)

#include "note_file_path.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <openssl/rand.h>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>

namespace fs = std::filesystem;

// ══════════════════════════════════════════════════════════════════════════
// NoteFilePath
// ══════════════════════════════════════════════════════════════════════════

NoteFilePath::NoteFilePath(
    const std::string& ledger_path,
    const std::vector<NoteBytes::Value>& target_path,
    const std::string& data_dir,
    bool recursive)
    : ledger_path_(ledger_path)
    , target_path_(target_path)
    , data_dir_(data_dir)
    , recursive_(recursive)
{}

const NoteBytes::Value& NoteFilePath::current_path_key() const {
    static NoteBytes::Value empty;
    if (current_level_ < (int)target_path_.size())
        return target_path_[current_level_];
    return empty;
}

std::string NoteFilePath::generate_data_file_path() const {
    std::vector<uint8_t> uuid(16);
    RAND_bytes(uuid.data(), 16);
    std::stringstream ss;
    ss << data_dir_ << "/";
    for (int i = 0; i < 16; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)uuid[i];
        if (i == 3 || i == 5 || i == 7 || i == 9) ss << "-";
    }
    ss << ".dat";
    return ss.str();
}

NoteBytes::Pair NoteFilePath::create_file_path_pair(
    int path_index,
    const std::string& result_path) const
{
    if (path_index >= depth()) {
        return NoteBytes::Pair(
            NoteFileConstants::FILE_PATH,
            NoteBytes::Value(result_path));
    }
    auto inner = create_file_path_pair(path_index + 1, result_path);
    NoteBytes::Object inner_obj;
    inner_obj.add(inner);
    return NoteBytes::Pair(target_path_[path_index], inner_obj.as_value());
}

// ══════════════════════════════════════════════════════════════════════════
// Ledger file I/O (plaintext)
// ══════════════════════════════════════════════════════════════════════════

NoteBytes::Object NoteFileLedger::read_ledger(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return NoteBytes::Object();
    in.seekg(0, std::ios::end);
    std::streamsize sz = in.tellg();
    in.seekg(0, std::ios::beg);
    if (sz == 0) return NoteBytes::Object();
    std::vector<uint8_t> buf(sz);
    in.read((char*)buf.data(), sz);
    try {
        return NoteBytes::Object::deserialize(buf.data(), buf.size());
    } catch (const std::exception& e) {
        syslog(LOG_WARNING, "[NoteFileLedger] parse error: %s", e.what());
        return NoteBytes::Object();
    }
}

bool NoteFileLedger::write_ledger(const std::string& path,
                                   const NoteBytes::Object& obj) {
    auto ser = obj.serialize();
    // Write to temp file first, then atomic rename
    std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary);
        if (!out) return false;
        out.write((const char*)ser.data(), ser.size());
        if (!out.good()) { unlink(tmp.c_str()); return false; }
    }
    if (rename(tmp.c_str(), path.c_str()) != 0) {
        unlink(tmp.c_str());
        return false;
    }
    return true;
}

// ══════════════════════════════════════════════════════════════════════════
// find_or_create_path – mirrors Java NotePathGet
// ══════════════════════════════════════════════════════════════════════════

std::string NoteFileLedger::find_or_create_path(NoteFilePath& path) {
    // Ensure data dir exists
    try { fs::create_directories(path.data_dir()); } catch (...) {}

    struct stat st;
    if (stat(path.ledger_path().c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
        // No ledger yet – create initial structure
        std::string new_fp = path.generate_data_file_path();
        path.set_resolved_file_path(new_fp);
        NoteBytes::Pair root_pair = path.create_file_path_pair(0, new_fp);
        NoteBytes::Object ledger;
        ledger.add(root_pair);
        write_ledger(path.ledger_path(), ledger);
        syslog(LOG_INFO, "[NoteFileLedger] Created ledger: %s -> %s",
               path.ledger_path().c_str(), new_fp.c_str());
        return new_fp;
    }

    // Ledger exists – parse and search
    auto ledger = read_ledger(path.ledger_path());

    // Recursive search returning (found, path_string)
    std::function<std::pair<bool,std::string>(const NoteBytes::Object&,int)> search;
    search = [&](const NoteBytes::Object& obj, int level)
        -> std::pair<bool,std::string> {
        if (level >= path.depth()) {
            auto* fp = obj.get(NoteFileConstants::FILE_PATH);
            if (fp && fp->type() == NoteBytes::Type::STRING)
                return {true, fp->as_string()};
            return {false, ""};
        }
        const auto& seg = path.target_path()[level];
        auto* val = obj.get(seg);
        if (!val) return {false, ""};
        if (level == path.depth() - 1 && val->type() == NoteBytes::Type::STRING)
            return {true, val->as_string()};
        if (val->type() == NoteBytes::Type::OBJECT) {
            auto nested = NoteBytes::as_object(*val);
            return search(nested, level + 1);
        }
        return {false, ""};
    };

    auto [found, found_path] = search(ledger, 0);
    if (found) {
        path.set_resolved_file_path(found_path);
        return found_path;
    }

    // Not found — insert into ledger
    syslog(LOG_INFO, "[NoteFileLedger] Inserting path into ledger");
    std::string new_fp = path.generate_data_file_path();
    path.set_resolved_file_path(new_fp);
    NoteBytes::Pair insert_pair = path.create_file_path_pair(0, new_fp);

    // Recursive insert
    std::function<NoteBytes::Object(const NoteBytes::Object&,int)> insert;
    insert = [&](const NoteBytes::Object& obj, int level) -> NoteBytes::Object {
        NoteBytes::Object result;
        bool inserted = false;
        if (level < path.depth()) {
            const auto& seg = path.target_path()[level];
            for (const auto& p : obj.pairs()) {
                if (p.key() == seg) {
                    if (p.value().type() == NoteBytes::Type::OBJECT) {
                        auto nested = NoteBytes::as_object(p.value());
                        auto merged = insert(nested, level + 1);
                        result.add(seg, merged.as_value());
                        inserted = true;
                    } else {
                        result.add(p);
                        inserted = true;
                    }
                } else {
                    result.add(p);
                }
            }
        }
        if (!inserted && level < path.depth()) {
            auto deep = path.create_file_path_pair(level, new_fp);
            result.add(deep);
        }
        return result;
    };

    auto updated = insert(ledger, 0);
    write_ledger(path.ledger_path(), updated);
    syslog(LOG_INFO, "[NoteFileLedger] Inserted: %s", new_fp.c_str());
    return new_fp;
}

// ══════════════════════════════════════════════════════════════════════════
// delete_from_path – mirrors Java NotePathDelete
// ══════════════════════════════════════════════════════════════════════════

bool NoteFileLedger::delete_from_path(NoteFilePath& path) {
    struct stat st;
    if (stat(path.ledger_path().c_str(), &st) != 0 || !S_ISREG(st.st_mode))
        return false;

    auto ledger = read_ledger(path.ledger_path());
    std::vector<std::string> files_to_delete;

    std::function<NoteBytes::Object(const NoteBytes::Object&,int)> remove;
    remove = [&](const NoteBytes::Object& obj, int level) -> NoteBytes::Object {
        NoteBytes::Object result;
        for (const auto& p : obj.pairs()) {
            if (level < path.depth() && p.key() == path.target_path()[level]) {
                if (level == path.depth() - 1) {
                    // Found target – collect file to delete
                    if (p.value().type() == NoteBytes::Type::STRING)
                        files_to_delete.push_back(p.value().as_string());
                    else if (p.value().type() == NoteBytes::Type::OBJECT) {
                        auto nested = NoteBytes::as_object(p.value());
                        for (auto& np : nested.pairs()) {
                            if (np.key() == NoteFileConstants::FILE_PATH &&
                                np.value().type() == NoteBytes::Type::STRING)
                                files_to_delete.push_back(np.value().as_string());
                        }
                    }
                    // Skip (don't add to result)
                } else if (p.value().type() == NoteBytes::Type::OBJECT) {
                    auto nested = NoteBytes::as_object(p.value());
                    auto cleaned = remove(nested, level + 1);
                    if (cleaned.size() > 0)
                        result.add(p.key(), cleaned.as_value());
                }
            } else {
                result.add(p);
            }
        }
        return result;
    };

    auto updated = remove(ledger, 0);
    write_ledger(path.ledger_path(), updated);

    for (const auto& fp : files_to_delete) {
        if (unlink(fp.c_str()) == 0)
            syslog(LOG_INFO, "[NoteFileLedger] Deleted: %s", fp.c_str());
        else
            syslog(LOG_WARNING, "[NoteFileLedger] unlink fail: %s", fp.c_str());
    }

    return true;
}
