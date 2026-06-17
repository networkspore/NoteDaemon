// tests/note_file_test.cpp
// Integration test for NoteFile service - three-layer auth model

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
        fs::create_directories(temp_dir + "/files");

        NoteFileConfig cfg;
        cfg.data_directory = temp_dir + "/files";
        cfg.ledger_path = temp_dir + "/ledger.dat";
        cfg.key_locker_path = temp_dir + "/key_locker.dat";
        cfg.server_key_path = temp_dir + "/server.key";
        cfg.admin_api_key_path = temp_dir + "/admin_api_key";

        service = std::make_shared<NoteFileService>(cfg);
        ASSERT_TRUE(service->init());
    }

    void TearDown() override {
        service.reset();
        if (!temp_dir.empty()) fs::remove_all(temp_dir);
    }
};

TEST_F(NoteFileTest, ServerKeyGenerated) {
    auto& key = service->server_key();
    EXPECT_EQ(key.private_key.size(), 32);
    EXPECT_EQ(key.public_key.size(), 32);
    EXPECT_TRUE(fs::exists(temp_dir + "/server.key"));
}

TEST_F(NoteFileTest, SetAndVerifyAdminApiKey) {
    EXPECT_FALSE(service->has_admin_api_key());
    EXPECT_TRUE(service->set_admin_api_key("my-api-key-12345"));
    EXPECT_TRUE(service->has_admin_api_key());
    EXPECT_TRUE(service->verify_admin_api_key("my-api-key-12345"));
    EXPECT_FALSE(service->verify_admin_api_key("wrong-key"));
}

TEST_F(NoteFileTest, AdminAuthenticate) {
    ASSERT_TRUE(service->set_admin_api_key("admin-key"));
    auto token = service->authenticate_admin("admin-key", 100);
    ASSERT_NE(token, nullptr);
    EXPECT_EQ(token->client_pid, 100);
    EXPECT_FALSE(token->session_id.empty());

    // Wrong key fails
    EXPECT_EQ(service->authenticate_admin("wrong", 100), nullptr);
}

TEST_F(NoteFileTest, SetLockerPassword) {
    EXPECT_FALSE(service->has_locker_password());
    EXPECT_TRUE(service->set_locker_password("locker-pw-123"));
    EXPECT_TRUE(service->has_locker_password());
}

TEST_F(NoteFileTest, ChangeLockerPassword) {
    ASSERT_TRUE(service->set_locker_password("old-pw"));
    EXPECT_TRUE(service->change_locker_password("old-pw", "new-pw"));
    EXPECT_FALSE(service->change_locker_password("old-pw", "other")); // wrong old
}

TEST_F(NoteFileTest, AddAndRemoveClient) {
    ASSERT_TRUE(service->set_locker_password("locker-pw"));
    EXPECT_TRUE(service->add_client("client-1"));
    EXPECT_TRUE(service->add_client("client-2", "encryption-pw"));

    auto clients = service->list_clients();
    EXPECT_EQ(clients.size(), 2);

    EXPECT_TRUE(service->remove_client("client-1"));
    EXPECT_EQ(service->list_clients().size(), 1);
}

TEST_F(NoteFileTest, ClientEncryptionKey) {
    ASSERT_TRUE(service->set_locker_password("locker-pw"));
    service->add_client("alice", "alice-pw");
    EXPECT_TRUE(service->client_has_encryption("alice"));

    auto key = service->get_client_key("alice");
    EXPECT_EQ(key.size(), 32); // 256-bit AES key

    // Client without encryption — gets a deterministic derived key
    service->add_client("bob");
    EXPECT_FALSE(service->client_has_encryption("bob"));
    auto derived = service->get_client_key("bob");
    EXPECT_EQ(derived.size(), 32);  // derived from server key + client_id
}

TEST_F(NoteFileTest, CreateAndReadFile) {
    ASSERT_TRUE(service->set_locker_password("locker-pw"));
    ASSERT_TRUE(service->add_client("alice", "alice-pw"));

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

TEST_F(NoteFileTest, FilePersistenceAcrossReopen) {
    ASSERT_TRUE(service->set_locker_password("locker-pw"));
    ASSERT_TRUE(service->add_client("alice", "alice-pw"));

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
    ASSERT_TRUE(service->set_locker_password("locker-pw"));
    ASSERT_TRUE(service->add_client("alice", "alice-pw"));
    ASSERT_TRUE(service->add_client("bob", "bob-pw"));

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

    // Each client reads their own data
    EXPECT_EQ(ha->read_object().get_string(std::string_view("owner")), "alice");
    EXPECT_EQ(hb->read_object().get_string(std::string_view("owner")), "bob");
}

TEST_F(NoteFileTest, BinaryDataRoundtrip) {
    ASSERT_TRUE(service->set_locker_password("locker-pw"));
    ASSERT_TRUE(service->add_client("alice", "alice-pw"));
    auto h = service->get_file("alice", std::vector<std::string>{"binary"});
    ASSERT_NE(h, nullptr);

    std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF};
    EXPECT_TRUE(h->write_bytes(data));
    EXPECT_EQ(h->read_bytes(), data);
}

TEST_F(NoteFileTest, LargeData) {
    ASSERT_TRUE(service->set_locker_password("locker-pw"));
    ASSERT_TRUE(service->add_client("alice", "alice-pw"));
    auto h = service->get_file("alice", std::vector<std::string>{"large"});
    ASSERT_NE(h, nullptr);

    std::vector<uint8_t> buf(100 * 1024);
    for (size_t i = 0; i < buf.size(); i++) buf[i] = static_cast<uint8_t>(i & 0xFF);
    EXPECT_TRUE(h->write_bytes(buf));
    EXPECT_EQ(h->read_bytes(), buf);
}

TEST_F(NoteFileTest, NoEncryptionFallback) {
    ASSERT_TRUE(service->set_locker_password("locker-pw"));
    // Client without encryption
    ASSERT_TRUE(service->add_client("alice"));  // no password
    auto h = service->get_file("alice", std::vector<std::string>{"note"});
    ASSERT_NE(h, nullptr);

    NoteBytes::Object obj;
    obj.add(NoteBytes::Value("text"), NoteBytes::Value("hello"));
    EXPECT_TRUE(h->write_object(obj));
    EXPECT_EQ(h->read_object().get_string(std::string_view("text")), "hello");
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
