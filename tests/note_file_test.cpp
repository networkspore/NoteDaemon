// tests/note_file_test.cpp
// NoteFile service – API key auth + per-client zone ledger

#include <gtest/gtest.h>
#include <filesystem>
#include <cstdio>
#include <string>

#include "note_file_service.h"
#include "note_file_handle.h"

namespace fs = std::filesystem;

class NoteFileTest : public ::testing::Test {
protected:
    std::string temp_dir;
    std::shared_ptr<NoteFileService> service;

    void SetUp() override {
        temp_dir = std::string("/tmp/notefile_test_") + std::to_string(getpid());
        NoteFileConfig cfg;
        cfg.data_directory = temp_dir + "/data";
        cfg.server_key_path = temp_dir + "/server.key";
        cfg.admin_key_path = temp_dir + "/admin.key";
        cfg.clients_registry = temp_dir + "/clients.dat";
        service = std::make_shared<NoteFileService>(cfg);
        ASSERT_TRUE(service->init());
    }

    void TearDown() override {
        service.reset();
        if (!temp_dir.empty()) fs::remove_all(temp_dir);
    }
};

TEST_F(NoteFileTest, AdminApiKey) {
    EXPECT_FALSE(service->has_admin_api_key());
    EXPECT_TRUE(service->set_admin_api_key("admin-secret-123"));
    EXPECT_TRUE(service->has_admin_api_key());
    EXPECT_TRUE(service->verify_admin_api_key("admin-secret-123"));
    EXPECT_FALSE(service->verify_admin_api_key("wrong-key"));
    // Can't set twice
    EXPECT_FALSE(service->set_admin_api_key("other-key"));
}

TEST_F(NoteFileTest, AdminAuthenticate) {
    ASSERT_TRUE(service->set_admin_api_key("admin-key"));
    auto t = service->authenticate_admin("admin-key", 100);
    ASSERT_NE(t, nullptr);
    EXPECT_EQ(t->client_pid, 100);
    EXPECT_FALSE(t->session_id.empty());
    EXPECT_EQ(service->authenticate_admin("wrong", 100), nullptr);
}

TEST_F(NoteFileTest, AddRemoveListClients) {
    ASSERT_TRUE(service->set_admin_api_key("admin-key"));

    EXPECT_TRUE(service->add_client("alice", "alice-api-key"));
    EXPECT_TRUE(service->add_client("bob", "bob-api-key"));
    EXPECT_FALSE(service->add_client("alice", "dup"));  // duplicate

    auto clients = service->list_clients();
    EXPECT_EQ(clients.size(), 2);

    EXPECT_TRUE(service->remove_client("alice"));
    EXPECT_EQ(service->list_clients().size(), 1);
}

TEST_F(NoteFileTest, ClientAuthenticate) {
    ASSERT_TRUE(service->set_admin_api_key("admin-key"));
    ASSERT_TRUE(service->add_client("alice", "alice-key"));

    auto t = service->authenticate_client("alice", "alice-key", 200);
    ASSERT_NE(t, nullptr);
    EXPECT_EQ(t->client_id, "alice");
    EXPECT_EQ(t->client_pid, 200);

    // Wrong key
    EXPECT_EQ(service->authenticate_client("alice", "wrong", 200), nullptr);
    // Unknown client
    EXPECT_EQ(service->authenticate_client("nobody", "x", 200), nullptr);
}

TEST_F(NoteFileTest, CreateAndReadFile) {
    ASSERT_TRUE(service->set_admin_api_key("admin-key"));
    ASSERT_TRUE(service->add_client("alice", "alice-key"));

    auto handle = service->get_file("alice", std::vector<std::string>{"test", "config"});
    ASSERT_NE(handle, nullptr);

    NoteBytes::Object obj;
    obj.add(NoteBytes::Value("name"), NoteBytes::Value("test_config"));
    obj.add(NoteBytes::Value("version"), NoteBytes::Value(1));
    EXPECT_TRUE(handle->write_object(obj));

    auto read_obj = handle->read_object();
    EXPECT_EQ(read_obj.get_string(std::string_view("name")), "test_config");
    EXPECT_EQ(read_obj.get_int(std::string_view("version")), 1);
}

TEST_F(NoteFileTest, PersistAcrossReopen) {
    ASSERT_TRUE(service->set_admin_api_key("admin-key"));
    ASSERT_TRUE(service->add_client("alice", "alice-key"));

    auto h1 = service->get_file("alice", std::vector<std::string>{"settings"});
    ASSERT_NE(h1, nullptr);
    NoteBytes::Object obj;
    obj.add(NoteBytes::Value("val"), NoteBytes::Value("persist-me"));
    EXPECT_TRUE(h1->write_object(obj));
    h1->close();

    auto h2 = service->get_file("alice", std::vector<std::string>{"settings"});
    ASSERT_NE(h2, nullptr);
    EXPECT_EQ(h2->read_object().get_string(std::string_view("val")), "persist-me");
}

TEST_F(NoteFileTest, ClientIsolation) {
    ASSERT_TRUE(service->set_admin_api_key("admin-key"));
    ASSERT_TRUE(service->add_client("alice", "a-key"));
    ASSERT_TRUE(service->add_client("bob", "b-key"));

    auto ha = service->get_file("alice", std::vector<std::string>{"data"});
    auto hb = service->get_file("bob", std::vector<std::string>{"data"});
    ASSERT_NE(ha, nullptr);
    ASSERT_NE(hb, nullptr);

    NoteBytes::Object oa;
    oa.add(NoteBytes::Value("owner"), NoteBytes::Value("alice"));
    EXPECT_TRUE(ha->write_object(oa));
    NoteBytes::Object ob;
    ob.add(NoteBytes::Value("owner"), NoteBytes::Value("bob"));
    EXPECT_TRUE(hb->write_object(ob));

    EXPECT_EQ(ha->read_object().get_string(std::string_view("owner")), "alice");
    EXPECT_EQ(hb->read_object().get_string(std::string_view("owner")), "bob");
}

// The ledger creates hierarchical filenames for nested paths
TEST_F(NoteFileTest, LedgerNestedPaths) {
    ASSERT_TRUE(service->set_admin_api_key("admin-key"));
    ASSERT_TRUE(service->add_client("alice", "a-key"));

    auto h1 = service->get_file("alice", std::vector<std::string>{"a", "b", "c"});
    ASSERT_NE(h1, nullptr);
    NoteBytes::Object obj;
    obj.add(NoteBytes::Value("depth"), NoteBytes::Value(3));
    EXPECT_TRUE(h1->write_object(obj));

    auto h2 = service->get_file("alice", std::vector<std::string>{"a", "b", "c"});
    ASSERT_NE(h2, nullptr);
    EXPECT_EQ(h2->read_object().get_int(std::string_view("depth")), 3);
}

TEST_F(NoteFileTest, BinaryData) {
    ASSERT_TRUE(service->set_admin_api_key("admin-key"));
    ASSERT_TRUE(service->add_client("alice", "a-key"));

    auto h = service->get_file("alice", std::vector<std::string>{"bin"});
    ASSERT_NE(h, nullptr);
    std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
    EXPECT_TRUE(h->write_bytes(data));
    EXPECT_EQ(h->read_bytes(), data);
}

TEST_F(NoteFileTest, LargeFile) {
    ASSERT_TRUE(service->set_admin_api_key("admin-key"));
    ASSERT_TRUE(service->add_client("alice", "a-key"));

    auto h = service->get_file("alice", std::vector<std::string>{"large"});
    ASSERT_NE(h, nullptr);
    std::vector<uint8_t> buf(50 * 1024);
    for (size_t i = 0; i < buf.size(); i++) buf[i] = (uint8_t)(i & 0xFF);
    EXPECT_TRUE(h->write_bytes(buf));
    EXPECT_EQ(h->read_bytes(), buf);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
