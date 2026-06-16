#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <cstdio>
#include <string>

#include "note_file_service.h"
#include "note_file_handle.h"

namespace fs = std::filesystem;

class NoteFileTest : public ::testing::Test {
protected:
    std::string temp_dir;
    std::string data_dir;
    std::string ledger_path;
    std::string settings_path;
    std::shared_ptr<NoteFileService> service;

    void SetUp() override {
        temp_dir = std::string("/tmp/notefile_test_") + std::to_string(getpid());
        data_dir = temp_dir + "/files";
        ledger_path = temp_dir + "/ledger.dat";
        settings_path = temp_dir + "/settings.dat";

        NoteFileConfig cfg;
        cfg.data_directory = data_dir;
        cfg.ledger_path = ledger_path;
        cfg.settings_path = settings_path;

        service = std::make_shared<NoteFileService>(cfg);
        ASSERT_TRUE(service->init());
    }

    void TearDown() override {
        service.reset();
        if (!temp_dir.empty()) {
            fs::remove_all(temp_dir);
        }
    }
};

TEST_F(NoteFileTest, SetInitialPassword) {
    EXPECT_FALSE(service->has_password());
    EXPECT_TRUE(service->set_initial_password("test123"));
    EXPECT_TRUE(service->has_password());
}

TEST_F(NoteFileTest, AuthenticateSuccess) {
    ASSERT_TRUE(service->set_initial_password("test123"));
    auto token = service->authenticate("test123", 100);
    ASSERT_NE(token, nullptr);
    EXPECT_TRUE(token->valid);
    EXPECT_EQ(token->client_pid, 100);
    EXPECT_FALSE(token->session_id.empty());
}

TEST_F(NoteFileTest, AuthenticateFailure) {
    ASSERT_TRUE(service->set_initial_password("test123"));
    auto token = service->authenticate("wrong_password", 100);
    EXPECT_EQ(token, nullptr);
}

TEST_F(NoteFileTest, ChangePassword) {
    ASSERT_TRUE(service->set_initial_password("old_pass"));
    ASSERT_TRUE(service->has_password());
    EXPECT_TRUE(service->change_password("old_pass", "new_pass"));
    EXPECT_EQ(service->authenticate("old_pass", 100), nullptr);
    ASSERT_NE(service->authenticate("new_pass", 100), nullptr);
}

TEST_F(NoteFileTest, CreateAndReadFile) {
    ASSERT_TRUE(service->set_initial_password("test123"));
    auto handle = service->get_file(std::vector<std::string>{"test", "config"});
    ASSERT_NE(handle, nullptr);

    NoteBytes::Object obj;
    obj.add(NoteBytes::Value("name"), NoteBytes::Value("test_config"));
    obj.add(NoteBytes::Value("version"), NoteBytes::Value(1));
    EXPECT_TRUE(handle->write_object(obj));

    auto read_obj = handle->read_object();
    EXPECT_EQ(read_obj.get_string(std::string_view("name")), "test_config");
    EXPECT_EQ(read_obj.get_int(std::string_view("version")), 1);
}

TEST_F(NoteFileTest, OverwriteFile) {
    ASSERT_TRUE(service->set_initial_password("test123"));
    auto handle = service->get_file(std::vector<std::string>{"data"});
    ASSERT_NE(handle, nullptr);

    NoteBytes::Object obj1;
    obj1.add(NoteBytes::Value("value"), NoteBytes::Value("first"));
    EXPECT_TRUE(handle->write_object(obj1));

    NoteBytes::Object obj2;
    obj2.add(NoteBytes::Value("value"), NoteBytes::Value("second"));
    obj2.add(NoteBytes::Value("count"), NoteBytes::Value(42));
    EXPECT_TRUE(handle->write_object(obj2));

    auto read_obj = handle->read_object();
    EXPECT_EQ(read_obj.get_string(std::string_view("value")), "second");
    EXPECT_EQ(read_obj.get_int(std::string_view("count")), 42);
}

TEST_F(NoteFileTest, FileExists) {
    ASSERT_TRUE(service->set_initial_password("test123"));
    auto handle = service->get_file(std::vector<std::string>{"exists_test"});
    ASSERT_NE(handle, nullptr);
    EXPECT_FALSE(handle->exists());

    NoteBytes::Object obj;
    obj.add(NoteBytes::Value("data"), NoteBytes::Value("hello"));
    EXPECT_TRUE(handle->write_object(obj));
    EXPECT_TRUE(handle->exists());
    EXPECT_GT(handle->size(), 0);
}

TEST_F(NoteFileTest, MultiplePaths) {
    ASSERT_TRUE(service->set_initial_password("test123"));
    auto h1 = service->get_file(std::vector<std::string>{"app1", "config"});
    auto h2 = service->get_file(std::vector<std::string>{"app2", "config"});
    ASSERT_NE(h1, nullptr);
    ASSERT_NE(h2, nullptr);

    NoteBytes::Object obj1;
    obj1.add(NoteBytes::Value("app"), NoteBytes::Value("app1"));
    EXPECT_TRUE(h1->write_object(obj1));

    NoteBytes::Object obj2;
    obj2.add(NoteBytes::Value("app"), NoteBytes::Value("app2"));
    EXPECT_TRUE(h2->write_object(obj2));

    EXPECT_EQ(h1->read_object().get_string(std::string_view("app")), "app1");
    EXPECT_EQ(h2->read_object().get_string(std::string_view("app")), "app2");
}

TEST_F(NoteFileTest, DeeplyNestedPath) {
    ASSERT_TRUE(service->set_initial_password("test123"));
    auto handle = service->get_file(std::vector<std::string>{"a", "b", "c", "d", "e"});
    ASSERT_NE(handle, nullptr);

    NoteBytes::Object obj;
    obj.add(NoteBytes::Value("depth"), NoteBytes::Value(5));
    EXPECT_TRUE(handle->write_object(obj));

    EXPECT_EQ(handle->read_object().get_int(std::string_view("depth")), 5);
}

TEST_F(NoteFileTest, RawBytes) {
    ASSERT_TRUE(service->set_initial_password("test123"));
    auto handle = service->get_file(std::vector<std::string>{"binary"});
    ASSERT_NE(handle, nullptr);

    std::vector<uint8_t> data = {0x00, 0x01, 0x02, 0xFF, 0xFE};
    EXPECT_TRUE(handle->write_bytes(data));
    EXPECT_EQ(handle->read_bytes(), data);
}

TEST_F(NoteFileTest, ReopenFileSamePath) {
    ASSERT_TRUE(service->set_initial_password("test123"));
    auto handle = service->get_file(std::vector<std::string>{"reopen"});
    ASSERT_NE(handle, nullptr);

    NoteBytes::Object obj;
    obj.add(NoteBytes::Value("val"), NoteBytes::Value("persist"));
    EXPECT_TRUE(handle->write_object(obj));
    handle->close();

    auto handle2 = service->get_file(std::vector<std::string>{"reopen"});
    ASSERT_NE(handle2, nullptr);
    EXPECT_EQ(handle2->read_object().get_string(std::string_view("val")), "persist");
}

TEST_F(NoteFileTest, LargeFile) {
    ASSERT_TRUE(service->set_initial_password("test123"));
    auto handle = service->get_file(std::vector<std::string>{"large"});
    ASSERT_NE(handle, nullptr);

    std::vector<uint8_t> large_data(100 * 1024);
    for (size_t i = 0; i < large_data.size(); i++)
        large_data[i] = static_cast<uint8_t>(i & 0xFF);

    EXPECT_TRUE(handle->write_bytes(large_data));
    EXPECT_EQ(handle->read_bytes(), large_data);
}

TEST_F(NoteFileTest, HandleClose) {
    ASSERT_TRUE(service->set_initial_password("test123"));
    auto handle = service->get_file(std::vector<std::string>{"close_test"});
    ASSERT_NE(handle, nullptr);
    EXPECT_TRUE(handle->is_open());
    handle->close();
    EXPECT_FALSE(handle->is_open());
}

TEST_F(NoteFileTest, AuthKeyDerivation) {
    ASSERT_TRUE(service->set_initial_password("mypassword"));
    auto t1 = service->authenticate("mypassword", 200);
    ASSERT_NE(t1, nullptr);
    EXPECT_EQ(t1->derived_key.size(), 32);

    auto t2 = service->authenticate("mypassword", 201);
    ASSERT_NE(t2, nullptr);
    EXPECT_EQ(t1->derived_key, t2->derived_key);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
