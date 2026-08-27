// file_transfer.cpp
#include "file_transfer.h"
#include <cstdint>
#include <hiredis/read.h>
#include <netinet/in.h>
#include <endian.h>
#include <openssl/err.h>
#include <string>
#include <cstring>
#include <map>
#include <algorithm>
#include <hiredis/hiredis.h>
#include <leveldb/db.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <iostream>
#include <ctime>
#include <vector>
#include <cstdlib>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <filesystem>
#include "server.h"
#include "chat.pb.h"
#include "chat_utils.h"

using namespace std;
namespace fs = filesystem;

map<std::string, std::string> filename_to_file_id;
redisContext* g_redis;
const char* path = "./files/";
map<int, FILETRANSFER> file_contexts;
std::recursive_mutex file_mutex;

string get_filename_meta(const string& file_id, redisContext* redis)
{
    string key = "file:meta:" + file_id;
    redisReply* reply = (redisReply*)redis_command(redis, "HGET %s filename", key.c_str());
    if (!reply || reply->type != REDIS_REPLY_STRING) {
        if (reply) freeReplyObject(reply);
        return "unknown";
    }
    string name = string(reply->str);
    freeReplyObject(reply);
    return name;
}

long long get_file_size(const string& file_id, redisContext* redis)
{
    string key = "file:meta:" + file_id;
    redisReply* reply = (redisReply*)redis_command(redis, "HGET %s filesize", key.c_str());
    if (reply == nullptr || reply->type != REDIS_REPLY_STRING) {
        if (reply) freeReplyObject(reply);
        return -1;
    }
    long long Size = stoull(reply->str);
    freeReplyObject(reply);
    return Size;
}

bool is_target(int fd, redisContext* redis, const string& file_id, const string& name) {
    string key = "file:meta:" + file_id;
    redisReply* group_reply = (redisReply*)redis_command(redis, "HGET %s is_group", key.c_str());
    if (!group_reply || group_reply->type != REDIS_REPLY_STRING) {
        if (group_reply) freeReplyObject(group_reply);
        send_message(fd, "系统错误：无法获取文件类型\n");
        return false;
    }
    bool is_group = (string(group_reply->str) == "1");
    freeReplyObject(group_reply);

    redisReply* target_reply = (redisReply*)redis_command(redis, "HGET %s target", key.c_str());
    if (!target_reply || target_reply->type != REDIS_REPLY_STRING) {
        if (target_reply) freeReplyObject(target_reply);
        send_message(fd, "系统错误：无法获取目标\n");
        return false;
    }
    string target = target_reply->str;
    freeReplyObject(target_reply);

    if (!is_group) {
        if (target != name) {
            send_message(fd, "你不是文件的接收者，无法下载该文件\n");
            return false;
        }
        return true;
    }

    string members_key = "group:" + target + ":members:";
    redisReply* member_reply = (redisReply*)redis_command(redis, "SISMEMBER %s %s", members_key.c_str(), name.c_str());
    if (!member_reply || member_reply->type != REDIS_REPLY_INTEGER) {
        if (member_reply) freeReplyObject(member_reply);
        send_message(fd, "系统错误：无法验证群成员\n");
        return false;
    }
    bool is_member = (member_reply->integer == 1);
    freeReplyObject(member_reply);

    if (!is_member) {
        send_message(fd, "你不是群成员，无法下载该文件\n");
        return false;
    }
    return true;
}

void cleanup_temp_files(redisContext* redis) {
    const int EXPIRY_HOURS = 24;
    auto now = chrono::system_clock::now();

    try {
        for (auto& entry : fs::directory_iterator(path)) {
            if (!entry.is_regular_file()) continue;
            string filename = entry.path().filename().string();
            if (filename.find(".tmp") == string::npos) continue;

            auto last_write = fs::last_write_time(entry.path());
            auto age = chrono::duration_cast<chrono::hours>(
                now.time_since_epoch() - last_write.time_since_epoch()
            );

            if (age.count() < EXPIRY_HOURS) continue;

            string file_id = filename.substr(0, filename.find(".tmp"));

            try {
                fs::remove(entry.path());
            } catch (const fs::filesystem_error& e) {
                cerr << "删除临时文件失败: " << e.what() << endl;
                continue;
            }

            string progress_key = "file:progress:" + file_id;
            redisReply* reply_progress = (redisReply*)redis_command(redis, "DEL %s", progress_key.c_str());
            if (reply_progress) freeReplyObject(reply_progress);

            string meta_key = "file:meta:" + file_id;
            redisReply* reply_meta = (redisReply*)redis_command(redis, "DEL %s", meta_key.c_str());
            if (reply_meta) freeReplyObject(reply_meta);
        }
    } catch (const fs::filesystem_error& e) {
        cerr << "清理临时文件发生错误: " << e.what() << endl;
    }
}

void notify_reciver(redisContext* redis, const string& file_id) {
    cerr << "notify_reciver" << endl;
    string meta_key = "file:meta:" + file_id;

    redisReply* reply1 = (redisReply*)redis_command(redis, "HGET %s sender", meta_key.c_str());
    if (!reply1 || reply1->type != REDIS_REPLY_STRING) { if (reply1) freeReplyObject(reply1); return; }
    string sender = reply1->str;
    freeReplyObject(reply1);

    redisReply* reply2 = (redisReply*)redis_command(redis, "HGET %s target", meta_key.c_str());
    if (!reply2 || reply2->type != REDIS_REPLY_STRING) { if (reply2) freeReplyObject(reply2); return; }
    string target = reply2->str;
    freeReplyObject(reply2);

    redisReply* reply3 = (redisReply*)redis_command(redis, "HGET %s filename", meta_key.c_str());
    if (!reply3 || reply3->type != REDIS_REPLY_STRING) { if (reply3) freeReplyObject(reply3); return; }
    string filename = reply3->str;
    freeReplyObject(reply3);

    redisReply* reply4 = (redisReply*)redis_command(redis, "HGET %s is_group", meta_key.c_str());
    bool is_group = (reply4 && reply4->type == REDIS_REPLY_STRING && string(reply4->str) == "1");
    if (reply4) freeReplyObject(reply4);

    string notify_msg = "FILE_NOTIFY " + sender + " " + filename + " " + file_id + " " + (is_group ? "group" : "private") + "\n";
    string key = "sendfiles:" + filename;
    redis_command(redis_conn, "HSET %s sender %s target %s file_id %s", key.c_str(), sender.c_str(), target.c_str(), file_id.c_str());

    if (!is_group) {
        redis_command(redis, "RPUSH %s %s", ("files:" + target).c_str(), notify_msg.c_str());
        int target_fd = find_client_fd_by_name(target);
        if (target_fd != -1) {
            auto it = chat1.find(target);
            auto it2 = chat_group.find(target);
            if (it == chat1.end() && it2 == chat_group.end())
                send_message(target_fd, notify_msg);
            else {
                string key = "unreadname:" + target;
                redis_command(redis_conn, "RPUSH %s %s", key.c_str(), sender.c_str());
            }
        } else {
            cerr << "对方离线，已存储\n";
            redis_command(redis, "INCR %s", ("offlinefiles:" + target).c_str());
        }
        string place = (sender < target) ? sender + ":" + target : target + ":" + sender;
        store_history(sender, place, notify_msg);
    } else {
        string members_key = "group:" + target + ":members:";
        redisReply* members_reply = (redisReply*)redis_command(redis, "SMEMBERS %s", members_key.c_str());
        if (members_reply && members_reply->type == REDIS_REPLY_ARRAY) {
            for (size_t i = 0; i < members_reply->elements; ++i) {
                string member = members_reply->element[i]->str;
                redis_command(redis, "RPUSH %s %s", ("files:" + member).c_str(), notify_msg.c_str());
                int member_fd = find_client_fd_by_name(member);
                if (member_fd != -1) {
                    auto it = chat1.find(member);
                    auto it2 = chat_group.find(member);
                    if (it == chat1.end() && it2 == chat_group.end())
                        send_message(member_fd, notify_msg);
                    else {
                        string key = "unreadname:" + member;
                        redis_command(redis_conn, "RPUSH %s %s", key.c_str(), sender.c_str());
                    }
                } else {
                    cerr << "对方离线，已存储\n";
                    redis_command(redis, "INCR %s", ("offlinefiles:" + member).c_str());
                }
                store_history(sender, member, notify_msg);
            }
        }
        if (members_reply) freeReplyObject(members_reply);
    }
}

void init_file_transfer(redisContext* redis) {
    if (mkdir(path, 0755) != 0) {
        if (errno != EEXIST) {
            exit(1);
        }
    }
    cleanup_temp_files(redis);
    return;
}

void handle_file_command(redisContext* redis, int fd, const string& sender, const string& target, const string& filename, size_t Size) {
    string is_group = "0";
    string key1 = "friends:" + sender;
    redisReply* reply1 = (redisReply*)redis_command(redis, "SISMEMBER %s %s", key1.c_str(), target.c_str());
    if (!reply1 || reply1->type != REDIS_REPLY_INTEGER || reply1->integer == 0) {
        send_message(fd, "不是好友，不能发送文件\n");
    }
    if (reply1) freeReplyObject(reply1);

    string file_id;
    string filepath;
    string filename1;
    bool is_old = false;

    string key4 = "filename_to_id:" + sender;
    redisReply* reply4 = (redisReply*)redis_command(redis, "HGET %s %s", key4.c_str(), filename.c_str());
    if (reply4 && reply4->type == REDIS_REPLY_STRING) {
        file_id = reply4->str;
        string key6 = "file:meta:" + file_id;
        redisReply* reply6 = (redisReply*)redis_command(redis_conn, "HGET %s filename", key6.c_str());
        if (reply6 && reply6->type == REDIS_REPLY_STRING) {
            filename1 = reply6->str;
            is_old = true;
        }
        if (reply6) freeReplyObject(reply6);
    }
    if (reply4) freeReplyObject(reply4);

    if (!is_old) {
        file_id = to_string(time(nullptr)) + "_" + to_string(rand() % 100000);
        filepath = path + file_id + ".tmp";
    } else {
        string finalpath = path + file_id + "_" + filename1;
        filepath = path + file_id + ".tmp";
        string key8 = "file:meta:" + file_id;
        redis_command(redis_conn, "HSET %s status uploading", key8.c_str());
        lock_guard<recursive_mutex> lock(file_mutex);
        for (auto it = file_contexts.begin(); it != file_contexts.end(); ++it) {
            if (it->second.file_id == file_id && it->second.download_file_fd != -1) {
                close(it->second.download_file_fd);
                it->second.download_file_fd = -1;
                it->second.download_state = DOWNLOAD_IDLE;
                it->second.download_chunk.clear();
            }
        }
    }

    cout << "handle_file_command: sender=" << sender
         << ", target=" << target
         << ", filename=" << filename
         << ", filesize=" << Size << endl;

    string key = "file:meta:" + file_id;
    redisReply* reply = (redisReply*)redis_command(redis,
        "HSET %s sender %s target %s filename %s is_group %s filesize %llu status uploading",
        key.c_str(), sender.c_str(), target.c_str(), filename.c_str(), is_group.c_str(), (unsigned long long)Size);
    if (!reply || reply->type != REDIS_REPLY_INTEGER) {
        if (reply) {
            cerr << "HSET failed, type=" << reply->type
                 << ", str=" << (reply->str ? reply->str : "null") << endl;
            freeReplyObject(reply);
        }
        send_message(fd, "redis存储哈希失败\n");
        return;
    }
    freeReplyObject(reply);

    redisReply* reply2 = (redisReply*)redis_command(redis, "SET file:progress:%s 0", file_id.c_str());
    if (!reply2 || reply2->type != REDIS_REPLY_STATUS || string(reply2->str) != "OK") {
        send_message(fd, "redis存储SET失败\n");
        if (reply2) freeReplyObject(reply2);
        return;
    }
    freeReplyObject(reply2);

    string key2 = "filename_to_id:" + sender;
    redisReply* reply3 = (redisReply*)redis_command(redis, "HSET %s %s %s", key2.c_str(), filename.c_str(), file_id.c_str());
    if (!reply3 || reply3->type != REDIS_REPLY_INTEGER) {
        if (reply3) freeReplyObject(reply3);
        send_message(fd, "redis存储哈希失败\n");
        return;
    }
    freeReplyObject(reply3);

    string msg = "UPLOAD_READY:" + file_id + "\n";
    send_message(fd, msg);
    return;
}

void handle_group_file_command(redisContext* redis, int fd, const string& sender, const string& target, const string& filename, size_t Size) {
    string is_group = "0";

    string key1 = "group:" + target + ":members:";
    redisReply* reply1 = (redisReply*)redis_command(redis, "SISMEMBER %s %s", key1.c_str(), sender.c_str());
    if (!reply1 || reply1->type != REDIS_REPLY_INTEGER || reply1->integer == 0) {
        send_message(fd, "不是群成员，不能发送文件\n");
        if (reply1) freeReplyObject(reply1);
        return;
    }
    freeReplyObject(reply1);
    is_group = "1";

    string file_id;
    string filepath;
    string filename1;
    bool is_old = false;

    string key4 = "filename_to_id:" + sender;
    redisReply* reply4 = (redisReply*)redis_command(redis, "HGET %s %s", key4.c_str(), filename.c_str());
    if (reply4 && reply4->type == REDIS_REPLY_STRING) {
        file_id = reply4->str;
        string key6 = "file:meta:" + file_id;
        redisReply* reply6 = (redisReply*)redis_command(redis_conn, "HGET %s filename", key6.c_str());
        if (reply6 && reply6->type == REDIS_REPLY_STRING) {
            filename1 = reply6->str;
            is_old = true;
        }
        if (reply6) freeReplyObject(reply6);
    }
    if (reply4) freeReplyObject(reply4);

    if (!is_old) {
        file_id = to_string(time(nullptr)) + "_" + to_string(rand() % 100000);
        filepath = path + file_id + ".tmp";
    } else {
        string finalpath = path + file_id + "_" + filename1;
        filepath = path + file_id + ".tmp";
        string key8 = "file:meta:" + file_id;
        redis_command(redis_conn, "HSET %s status uploading", key8.c_str());
        lock_guard<recursive_mutex> lock(file_mutex);
        for (auto it = file_contexts.begin(); it != file_contexts.end(); ++it) {
            if (it->second.file_id == file_id && it->second.download_file_fd != -1) {
                close(it->second.download_file_fd);
                it->second.download_file_fd = -1;
                it->second.download_state = DOWNLOAD_IDLE;
                it->second.download_chunk.clear();
            }
        }
    }

    cout << "handle_group_file_command: sender=" << sender
         << ", target=" << target
         << ", filename=" << filename
         << ", filesize=" << Size << endl;

    string key = "file:meta:" + file_id;
    redisReply* reply = (redisReply*)redis_command(redis,
        "HSET %s sender %s target %s filename %s is_group %s filesize %llu status uploading",
        key.c_str(), sender.c_str(), target.c_str(), filename.c_str(), is_group.c_str(), (unsigned long long)Size);
    if (!reply || reply->type != REDIS_REPLY_INTEGER) {
        if (reply) {
            cerr << "HSET failed, type=" << reply->type
                 << ", str=" << (reply->str ? reply->str : "null") << endl;
            freeReplyObject(reply);
        }
        send_message(fd, "redis存储哈希失败\n");
        return;
    }
    freeReplyObject(reply);

    redisReply* reply2 = (redisReply*)redis_command(redis, "SET file:progress:%s 0", file_id.c_str());
    if (!reply2 || reply2->type != REDIS_REPLY_STATUS || string(reply2->str) != "OK") {
        send_message(fd, "redis存储SET失败\n");
        if (reply2) freeReplyObject(reply2);
        return;
    }
    freeReplyObject(reply2);

    string key2 = "filename_to_id:" + sender;
    redisReply* reply3 = (redisReply*)redis_command(redis, "HSET %s %s %s", key2.c_str(), filename.c_str(), file_id.c_str());
    if (!reply3 || reply3->type != REDIS_REPLY_INTEGER) {
        if (reply3) freeReplyObject(reply3);
        send_message(fd, "redis存储哈希失败\n");
        return;
    }
    freeReplyObject(reply3);

    string msg = "UPLOAD_READY:" + file_id + "\n";
    send_message(fd, msg);
    return;
}

// ============================================================
// 发送文件数据块（使用 Protobuf）
// ============================================================
void send_next_chunk(int fd) {
    auto fit = file_contexts.find(fd);
    if (fit == file_contexts.end()) {
        cerr << "[DOWNLOAD] file context not found, fd=" << fd << endl;
        return;
    }

    FILETRANSFER& ctx = fit->second;
    auto client = get_client(fd);
    if (!client || client->ssl == nullptr) {
        cerr << "[DOWNLOAD] invalid TLS client, fd=" << fd << endl;
        return;
    }

    // 1. 先发送 download_chunk 中尚未发送的数据
    if (!ctx.download_chunk.empty() && ctx.chunk_sent < ctx.download_chunk.size()) {
        while (ctx.chunk_sent < ctx.download_chunk.size()) {
            size_t remaining = ctx.download_chunk.size() - ctx.chunk_sent;
            int write_size = static_cast<int>(min(remaining, static_cast<size_t>(INT_MAX)));

            int n = SSL_write(client->ssl, ctx.download_chunk.data() + ctx.chunk_sent, write_size);
            if (n > 0) {
                ctx.chunk_sent += static_cast<size_t>(n);
                ctx.total_sent += static_cast<size_t>(n);
                continue;
            }

            int ssl_error = SSL_get_error(client->ssl, n);
            if (ssl_error == SSL_ERROR_WANT_WRITE || ssl_error == SSL_ERROR_WANT_READ) {
                epoll_event ev{};
                ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
                ev.data.fd = fd;
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
                return;
            }
            if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                cerr << "[DOWNLOAD] TLS connection closed, fd=" << fd << endl;
                close_connection(fd);
                return;
            }
            cerr << "[DOWNLOAD] SSL_write failed, fd=" << fd << ", error=" << ssl_error << endl;
            ERR_print_errors_fp(stderr);
            close_connection(fd);
            return;
        }
        ctx.download_chunk.clear();
        ctx.chunk_sent = 0;
    }

    // 2. 文件读取完成，发送结束包
    if (ctx.file_read_done) {
        if (ctx.download_state == DOWNLOAD_FINISHED) {
            epoll_event ev{};
            ev.events = EPOLLIN | EPOLLET;
            ev.data.fd = fd;
            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
            return;
        }

        chat::ChatPacket end_packet;
        end_packet.set_type(chat::ChatPacket::FILE);
        end_packet.set_file_id(ctx.file_id);
        end_packet.set_offset(ctx.download_offset);
        end_packet.clear_payload();

        string body;
        if (!end_packet.SerializeToString(&body)) {
            cerr << "[DOWNLOAD] serialize end packet failed, fd=" << fd << endl;
            close_connection(fd);
            return;
        }
        if (body.size() > UINT32_MAX) {
            cerr << "[DOWNLOAD] protobuf body too large, fd=" << fd << endl;
            close_connection(fd);
            return;
        }

        uint32_t body_len = htonl(static_cast<uint32_t>(body.size()));
        ctx.download_chunk.clear();
        ctx.download_chunk.reserve(sizeof(body_len) + body.size());

        const char* len_ptr = reinterpret_cast<const char*>(&body_len);
        ctx.download_chunk.insert(ctx.download_chunk.end(), len_ptr, len_ptr + sizeof(body_len));
        ctx.download_chunk.insert(ctx.download_chunk.end(), body.begin(), body.end());

        ctx.chunk_sent = 0;
        ctx.download_state = DOWNLOAD_FINISHED;
        send_next_chunk(fd);
        return;
    }

    // 3. 检查文件描述符
    if (ctx.download_file_fd < 0) {
        cerr << "[DOWNLOAD] invalid download_file_fd, fd=" << fd << endl;
        close_connection(fd);
        return;
    }

    // 4. 读取下一块文件
    constexpr size_t CHUNK_SIZE = 1024 * 1024; // 1 MB
    vector<char> file_data(CHUNK_SIZE);
    ssize_t n = read(ctx.download_file_fd, file_data.data(), file_data.size());

    if (n < 0) {
        if (errno == EINTR) return;
        perror("[DOWNLOAD] read");
        close_connection(fd);
        return;
    }

    // EOF
    if (n == 0) {
        ctx.file_read_done = true;
        close(ctx.download_file_fd);
        ctx.download_file_fd = -1;
        send_next_chunk(fd);
        return;
    }

    // 5. 构造 Protobuf ChatPacket
    chat::ChatPacket packet;
    packet.set_type(chat::ChatPacket::FILE);
    packet.set_file_id(ctx.file_id);
    packet.set_offset(ctx.download_offset);
    packet.set_payload(file_data.data(), static_cast<size_t>(n));

    string body;
    if (!packet.SerializeToString(&body)) {
        cerr << "[DOWNLOAD] protobuf serialize failed, fd=" << fd << endl;
        close_connection(fd);
        return;
    }
    if (body.size() > UINT32_MAX) {
        cerr << "[DOWNLOAD] protobuf body too large, fd=" << fd << endl;
        close_connection(fd);
        return;
    }

    // 6. 构造 [4字节长度][protobuf body]
    uint32_t body_len = htonl(static_cast<uint32_t>(body.size()));
    ctx.download_chunk.clear();
    ctx.download_chunk.reserve(sizeof(body_len) + body.size());

    const char* len_ptr = reinterpret_cast<const char*>(&body_len);
    ctx.download_chunk.insert(ctx.download_chunk.end(), len_ptr, len_ptr + sizeof(body_len));
    ctx.download_chunk.insert(ctx.download_chunk.end(), body.begin(), body.end());

    ctx.chunk_sent = 0;
    ctx.download_offset += static_cast<uint64_t>(n);

    // 7. 立即尝试发送
    send_next_chunk(fd);
}

// ============================================================
// 处理文件上传（使用 Protobuf）
// ============================================================
void process_upload(int fd, redisContext* redis, const chat::ChatPacket& packet) {
    auto fit = file_contexts.find(fd);
    if (fit == file_contexts.end()) {
        cerr << "[PROCESS] no file context, fd=" << fd << endl;
        close_connection(fd);
        return;
    }

    FILETRANSFER& ctx = fit->second;
    string file_id = packet.file_id();
    uint64_t offset = packet.offset();
    const string& data = packet.payload();

    if (file_id.empty()) {
        cerr << "[PROCESS] empty file_id, fd=" << fd << endl;
        send_message(fd, "file_id 为空\n");
        close_connection(fd);
        return;
    }

    // 绑定 file_id
    if (ctx.file_id.empty()) {
        ctx.file_id = file_id;
    } else if (ctx.file_id != file_id) {
        cerr << "[PROCESS] file_id mismatch, fd=" << fd
             << ", context=" << ctx.file_id
             << ", packet=" << file_id << endl;
        send_message(fd, "file_id 不匹配\n");
        close_connection(fd);
        return;
    }

    string meta_key = "file:meta:" + file_id;

    // 检查文件状态
    redisReply* reply_status = (redisReply*)redis_command(redis, "HGET %s status", meta_key.c_str());
    if (!reply_status || reply_status->type != REDIS_REPLY_STRING || string(reply_status->str) != "uploading") {
        cerr << "[PROCESS] invalid file status, file_id=" << file_id << endl;
        if (reply_status) freeReplyObject(reply_status);
        send_message(fd, "文件状态无效或未上传\n");
        close_connection(fd);
        return;
    }
    ctx.status = reply_status->str;
    freeReplyObject(reply_status);

    // 获取文件总大小
    redisReply* reply_size = (redisReply*)redis_command(redis, "HGET %s filesize", meta_key.c_str());
    if (!reply_size || reply_size->type != REDIS_REPLY_STRING) {
        if (reply_size) freeReplyObject(reply_size);
        send_message(fd, "获取文件大小失败\n");
        close_connection(fd);
        return;
    }
    try {
        ctx.filesize = stoull(reply_size->str);
    } catch (...) {
        freeReplyObject(reply_size);
        send_message(fd, "文件大小数据错误\n");
        close_connection(fd);
        return;
    }
    freeReplyObject(reply_size);

    // 打开临时文件
    string tmp_path = "./files/" + file_id + ".tmp";
    if (ctx.tmp_fd == -1) {
        ctx.tmp_fd = open(tmp_path.c_str(), O_WRONLY | O_CREAT, 0644);
        if (ctx.tmp_fd < 0) {
            perror("open upload temp file");
            send_message(fd, "打开临时文件失败\n");
            close_connection(fd);
            return;
        }
    }

    // 获取当前服务器已接收大小
    off_t current_offset = lseek(ctx.tmp_fd, 0, SEEK_END);
    if (current_offset == (off_t)-1) {
        perror("lseek upload temp file");
        send_message(fd, "获取文件偏移失败\n");
        close_connection(fd);
        return;
    }
    ctx.upload_offset = static_cast<uint64_t>(current_offset);

    // 检查 offset 是否匹配
    if (offset != ctx.upload_offset) {
        cerr << "[PROCESS] offset mismatch, file_id=" << file_id
             << ", client_offset=" << offset
             << ", server_offset=" << ctx.upload_offset << endl;
        send_message(fd, "偏移量不匹配\n");
        close_connection(fd);
        return;
    }

    // 处理文件数据或结束包
    if (!data.empty()) {
        // 文件数据
        if (offset + data.size() > ctx.filesize) {
       /*     cerr << "[PROCESS] file data exceeds filesize, file_id=" << file_id
                 << ", offset=" << offset
                 << ", data=" << data.size()
                 << ", filesize=" << ctx.filesize << endl;
         */   send_message(fd, "文件数据超过声明大小\n");
            close_connection(fd);
            return;
        }

        const char* ptr = data.data();
        size_t remaining = data.size();
        while (remaining > 0) {
            ssize_t written = write(ctx.tmp_fd, ptr, remaining);
            if (written > 0) {
                ptr += written;
                remaining -= static_cast<size_t>(written);
                continue;
            }
            if (written < 0 && errno == EINTR) continue;
            perror("write upload data");
            send_message(fd, "写入文件失败\n");
            close_connection(fd);
            return;
        }

        ctx.upload_offset += static_cast<uint64_t>(data.size());
        redisReply* progress_reply = (redisReply*)redis_command(redis,
            "SET file:progress:%s %llu", file_id.c_str(), (unsigned long long)ctx.upload_offset);
        if (progress_reply) freeReplyObject(progress_reply);

     /*   cerr << "[PROCESS] received file data: file_id=" << file_id
             << ", offset=" << offset
             << ", bytes=" << data.size()
             << ", progress=" << ctx.upload_offset << "/" << ctx.filesize << endl;
    */}

    // 判断文件是否完整
    if (ctx.upload_offset >= ctx.filesize) {
        if (ctx.upload_offset != ctx.filesize) {
            cerr << "[PROCESS] upload offset exceeds filesize" << endl;
            send_message(fd, "文件大小异常\n");
            close_connection(fd);
            return;
        }

        // 关闭临时文件
        if (ctx.tmp_fd != -1) {
            fsync(ctx.tmp_fd);
            close(ctx.tmp_fd);
            ctx.tmp_fd = -1;
        }

        // 获取文件名
        string filename = get_filename_meta(file_id, redis);
        if (filename.empty()) {
            cerr << "[PROCESS] filename metadata empty, file_id=" << file_id << endl;
            send_message(fd, "获取文件名失败\n");
            close_connection(fd);
            return;
        }

        // 重命名临时文件
        string final_path = "./files/" + file_id + "_" + filename;
        if (rename(tmp_path.c_str(), final_path.c_str()) != 0) {
            perror("rename upload temp file");
            send_message(fd, "重命名临时文件失败\n");
            close_connection(fd);
            return;
        }

        cerr << "[PROCESS] upload complete: " << file_id << endl;

        // Redis 状态改为 complete
        redisReply* complete_reply = (redisReply*)redis_command(redis, "HSET %s status complete", meta_key.c_str());
        if (complete_reply) freeReplyObject(complete_reply);

        // 发送完成消息
        string complete_msg = "UPLOAD_COMPLETE " + file_id + "\n";
        send_message(fd, complete_msg);

        // 通知接收者
        notify_reciver(redis, file_id);
        cout << "Upload complete, notifying receiver..." << endl;
        return;
    }
}

// ============================================================
// 处理文件下载请求（使用 Protobuf）
// ============================================================
void process_download(int fd, redisContext* redis, const chat::ChatPacket& packet) {
    cerr << "[DOWNLOAD_REQUEST] START, fd=" << fd << endl;
    
    string file_id = packet.file_id();
    uint64_t offset = packet.offset();
    
    cerr << "[DOWNLOAD_REQUEST] file_id=" << file_id << ", offset=" << offset << endl;

    if (file_id.empty()) {
        cerr << "[DOWNLOAD_REQUEST] empty file_id" << endl;
        send_message(fd, "file_id 为空\n");
        close_connection(fd);
        return;
    }

    string meta_key = "file:meta:" + file_id;

    // 检查文件是否存在
    redisReply* reply1 = (redisReply*)redis_command(redis, "EXISTS %s", meta_key.c_str());
    if (!reply1 || reply1->type != REDIS_REPLY_INTEGER || reply1->integer != 1) {
        if (reply1) freeReplyObject(reply1);
        cerr << "[DOWNLOAD_REQUEST] file not found: " << file_id << endl;
        send_message(fd, "文件不存在\n");
        close_connection(fd);
        return;
    }
    freeReplyObject(reply1);
    cerr << "[DOWNLOAD_REQUEST] file exists" << endl;

    // 检查文件状态
    redisReply* reply2 = (redisReply*)redis_command(redis, "HGET %s status", meta_key.c_str());
    if (!reply2 || reply2->type != REDIS_REPLY_STRING || string(reply2->str) != "complete") {
        if (reply2) freeReplyObject(reply2);
        cerr << "[DOWNLOAD_REQUEST] file not complete, status=" 
             << (reply2 ? reply2->str : "null") << endl;
        send_message(fd, "文件未上传完成，不能下载\n");
        close_connection(fd);
        return;
    }
    freeReplyObject(reply2);
    cerr << "[DOWNLOAD_REQUEST] file status: complete" << endl;

    // ============================================================
    // 修改：从文件连接中获取用户名
    // 文件连接没有登录状态，但 file_id 的 metadata 中有 sender 信息
    // 我们需要从 Redis 获取文件的发送者，然后验证权限
    // ============================================================
    
    // 获取文件的发送者
    redisReply* sender_reply = (redisReply*)redis_command(redis, "HGET %s sender", meta_key.c_str());
    if (!sender_reply || sender_reply->type != REDIS_REPLY_STRING) {
        if (sender_reply) freeReplyObject(sender_reply);
        cerr << "[DOWNLOAD_REQUEST] cannot get sender" << endl;
        send_message(fd, "无法获取文件信息\n");
        close_connection(fd);
        return;
    }
    string sender = sender_reply->str;
    freeReplyObject(sender_reply);
    
    // 获取目标（接收者）
    redisReply* target_reply = (redisReply*)redis_command(redis, "HGET %s target", meta_key.c_str());
    if (!target_reply || target_reply->type != REDIS_REPLY_STRING) {
        if (target_reply) freeReplyObject(target_reply);
        cerr << "[DOWNLOAD_REQUEST] cannot get target" << endl;
        send_message(fd, "无法获取文件目标\n");
        close_connection(fd);
        return;
    }
    string target = target_reply->str;
    freeReplyObject(target_reply);

    // 检查是否是群文件
    redisReply* group_reply = (redisReply*)redis_command(redis, "HGET %s is_group", meta_key.c_str());
    bool is_group = false;
    if (group_reply && group_reply->type == REDIS_REPLY_STRING && string(group_reply->str) == "1") {
        is_group = true;
    }
    if (group_reply) freeReplyObject(group_reply);

    // 对于文件下载，我们需要验证下载者是否是目标接收者或群成员
    // 但这里无法获取下载者的用户名，因为文件连接没有登录状态
    // 解决方法：通过主连接的用户名来验证，或者允许任何人下载（已经通过 is_target 验证）
    
    // 注意：在 handle_command 中已经调用了 is_target 验证权限
    // 所以这里不再重复检查

    // 获取文件名和大小
    string filename = get_filename_meta(file_id, redis);
    cerr << "[DOWNLOAD_REQUEST] filename=" << filename << endl;
    
    long long filesize = get_file_size(file_id, redis);
    cerr << "[DOWNLOAD_REQUEST] filesize=" << filesize << endl;
    
    if (filesize < 0) {
        send_message(fd, "获取文件信息失败\n");
        close_connection(fd);
        return;
    }

    // 检查本地文件
    string final_path = "./files/" + file_id + "_" + filename;
    cerr << "[DOWNLOAD_REQUEST] final_path=" << final_path << endl;

    // 检查文件是否存在
    if (access(final_path.c_str(), F_OK) != 0) {
        cerr << "[DOWNLOAD_REQUEST] file not found on disk: " << final_path << endl;
        send_message(fd, "文件在磁盘上不存在\n");
        close_connection(fd);
        return;
    }

    auto fit = file_contexts.find(fd);
    if (fit == file_contexts.end()) {
        // 如果没有上下文，创建一个
        FILETRANSFER ctx{};
        ctx.state = PARSE_HEADER;
        ctx.header_bytes = 0;
        ctx.total_len = 0;
        ctx.tmp_fd = -1;
        ctx.download_state = DOWNLOAD_IDLE;
        ctx.download_file_fd = -1;
        ctx.download_offset = 0;
        ctx.total_sent = 0;
        ctx.chunk_sent = 0;
        file_contexts[fd] = std::move(ctx);
        cerr << "[DOWNLOAD_REQUEST] created new file context for fd=" << fd << endl;
        fit = file_contexts.find(fd);
    }

    FILETRANSFER& ctx = fit->second;

    // 打开文件
    if (ctx.download_file_fd == -1) {
        ctx.download_file_fd = open(final_path.c_str(), O_RDONLY);
        if (ctx.download_file_fd < 0) {
            perror("open file for download");
            cerr << "[DOWNLOAD_REQUEST] open failed: " << strerror(errno) << endl;
            send_message(fd, "打开文件失败\n");
            close_connection(fd);
            return;
        }
        cerr << "[DOWNLOAD_REQUEST] file opened, fd=" << ctx.download_file_fd << endl;
    }

    // 设置下载状态
    ctx.file_id = file_id;
    ctx.download_state = DOWNLOAD_SENDING;
    ctx.download_offset = offset;
    ctx.total_sent = 0;
    ctx.download_chunk.clear();
    ctx.chunk_sent = 0;
    ctx.file_read_done = false;

    // 定位到请求的偏移位置
    if (lseek(ctx.download_file_fd, offset, SEEK_SET) == -1) {
        perror("lseek");
        cerr << "[DOWNLOAD_REQUEST] lseek failed: " << strerror(errno) << endl;
        close(ctx.download_file_fd);
        ctx.download_file_fd = -1;
        close_connection(fd);
        return;
    }
    cerr << "[DOWNLOAD_REQUEST] lseek success, offset=" << offset << endl;

    // 开始发送
    cerr << "[DOWNLOAD_REQUEST] starting send_next_chunk" << endl;
    send_next_chunk(fd);
}
// ============================================================
// 处理完整 Protobuf 数据包
// ============================================================
void process_packet(int fd, redisContext* redis, const chat::ChatPacket& packet) {
    if (packet.type() != chat::ChatPacket::FILE) {
        cerr << "[PROCESS] invalid packet type=" << packet.type() << endl;
        return;
    }

    const string& payload = packet.payload();

    // 判断是上传请求、上传数据、还是下载请求
    if (payload.empty()) {
        // payload 为空：可能是下载请求或完成通知
        uint64_t offset = packet.offset();
        if (offset == 0) {
            // offset=0 且 payload 为空：可能是下载请求或初始包
            // 检查是否有文件数据待处理，没有就认为是下载请求
            auto fit = file_contexts.find(fd);
            if (fit != file_contexts.end() && !fit->second.file_id.empty()) {
                // 已经在上传过程中，可能是结束包
                process_upload(fd, redis, packet);
            } else {
                // 下载请求
                process_download(fd, redis, packet);
            }
        } else {
            // offset > 0 且 payload 为空：上传完成通知
            process_upload(fd, redis, packet);
        }
    } else {
        // payload 非空：上传数据
        process_upload(fd, redis, packet);
    }
}

// ============================================================
// 文件数据入口
// ============================================================
void on_file_data(int fd, redisContext* redis) {
    auto fit = file_contexts.find(fd);
    if (fit == file_contexts.end()) {
        cerr << "[FILE] no file context, fd=" << fd << endl;
        close_connection(fd);
        return;
    }

    // 如果正在下载发送，继续发送
    if (fit->second.download_state == DOWNLOAD_SENDING) {
        send_next_chunk(fd);
        return;
    }

    constexpr size_t READ_SIZE = 1024 * 1024;
    char read_buf[READ_SIZE];

    while (true) {
        auto client = get_client(fd);
        if (!client || !client->ssl) {
            cerr << "[FILE] invalid client, fd=" << fd << endl;
            close_connection(fd);
            return;
        }

        int n = SSL_read(client->ssl, read_buf, sizeof(read_buf));

        if (n > 0) {
            lock_guard<recursive_mutex> lock(file_mutex);
            auto it = file_contexts.find(fd);
            if (it == file_contexts.end()) {
                return;
            }
            // 追加到缓冲区
            it->second.buffer.insert(it->second.buffer.end(), read_buf, read_buf + n);

            // 从缓冲区提取完整 protobuf 包
            while (true) {
                vector<char> packet_data;
                {
                    auto it2 = file_contexts.find(fd);
                    if (it2 == file_contexts.end()) break;
                    FILETRANSFER& ctx = it2->second;

                    if (ctx.state == PARSE_HEADER) {
                        if (ctx.buffer.size() < sizeof(uint32_t)) {
                            break;
                        }
                        uint32_t net_len = 0;
                        memcpy(&net_len, ctx.buffer.data(), sizeof(net_len));
                        ctx.total_len = ntohl(net_len);

                        if (ctx.total_len > 16 * 1024 * 1024) {
                            cerr << "[FILE] invalid protobuf body length=" << ctx.total_len << ", fd=" << fd << endl;
                            close_connection(fd);
                            return;
                        }
                        ctx.buffer.erase(ctx.buffer.begin(), ctx.buffer.begin() + sizeof(uint32_t));
                        ctx.state = PARSE_BODY;
                    }

                    if (ctx.state == PARSE_BODY) {
                        if (ctx.buffer.size() < ctx.total_len) {
                            break;
                        }
                        packet_data.assign(ctx.buffer.begin(), ctx.buffer.begin() + ctx.total_len);
                        ctx.buffer.erase(ctx.buffer.begin(), ctx.buffer.begin() + ctx.total_len);
                        ctx.state = PARSE_HEADER;
                        ctx.total_len = 0;
                    }
                }

                if (packet_data.empty()) {
                    break;
                }

                // 解析并处理 protobuf 包
                chat::ChatPacket packet;
                if (!packet.ParseFromArray(packet_data.data(), static_cast<int>(packet_data.size()))) {
                    cerr << "[FILE] protobuf parse failed, fd=" << fd << endl;
                    close_connection(fd);
                    return;
                }

                process_packet(fd, redis, packet);

                lock_guard<recursive_mutex> lock(file_mutex);
                if (file_contexts.find(fd) == file_contexts.end()) {
                    return;
                }
            }
            continue;
        }

        int ssl_err = SSL_get_error(client->ssl, n);

        if (ssl_err == SSL_ERROR_WANT_READ) {
            break;
        }

        if (ssl_err == SSL_ERROR_WANT_WRITE) {
            epoll_event ev{};
            ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
            ev.data.fd = fd;
            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
            break;
        }

        if (ssl_err == SSL_ERROR_ZERO_RETURN) {
            cerr << "[FILE] TLS connection closed, fd=" << fd << endl;
            close_connection(fd);
            return;
        }

        cerr << "[FILE] SSL_read failed, fd=" << fd << ", error=" << ssl_err << endl;
        ERR_print_errors_fp(stderr);
        close_connection(fd);
        return;
    }
}

void on_file_connection(int fd, bool connected) {
    lock_guard<recursive_mutex> lock(file_mutex);

    if (connected) {
        FILETRANSFER ctx{};
        ctx.state = PARSE_HEADER;
        ctx.header_bytes = 0;
        ctx.total_len = 0;
        ctx.tmp_fd = -1;
        ctx.download_state = DOWNLOAD_IDLE;
        ctx.download_file_fd = -1;
        ctx.download_offset = 0;
        ctx.total_sent = 0;
        ctx.chunk_sent = 0;
        file_contexts[fd] = std::move(ctx);
        return;
    }

    auto it = file_contexts.find(fd);
    if (it == file_contexts.end()) return;

    if (it->second.tmp_fd != -1) {
        close(it->second.tmp_fd);
        it->second.tmp_fd = -1;
    }

    if (it->second.download_file_fd != -1) {
        close(it->second.download_file_fd);
        it->second.download_file_fd = -1;
    }
    file_contexts.erase(it);
}

void Resend_file(int fd, const string& sender, const string& filename, redisContext* redis) {
    string key1 = "filename_to_id:" + sender;
    redisReply* reply2 = (redisReply*)redis_command(redis, "HGET %s %s", key1.c_str(), filename.c_str());
    if (!reply2 || reply2->type != REDIS_REPLY_STRING) {
        send_message(fd, "查找file_id失败\n");
        if (reply2) freeReplyObject(reply2);
        return;
    }
    string file_id = string(reply2->str);
    freeReplyObject(reply2);

    string meta_key = "file:meta:" + file_id;
    redisReply* reply1 = (redisReply*)redis_command(redis, "EXISTS %s", meta_key.c_str());
    if (!reply1 || reply1->type != REDIS_REPLY_INTEGER || reply1->integer != 1) {
        send_message(fd, "找不到该文件\n");
        if (reply1) freeReplyObject(reply1);
        return;
    }
    freeReplyObject(reply1);

    redisReply* reply3 = (redisReply*)redis_command(redis, "HGET %s status", meta_key.c_str());
    if (!reply3 || reply3->type != REDIS_REPLY_STRING) {
        send_message(fd, "网络错误\n");
        if (reply3) freeReplyObject(reply3);
        return;
    }

    if (string(reply3->str) == "complete") {
        send_message(fd, "文件已经上传完毕\n");
        freeReplyObject(reply3);
        return;
    }

    if (string(reply3->str) != "uploading") {
        send_message(fd, "文件状态异常，无法续传\n");
        freeReplyObject(reply3);
        return;
    }
    freeReplyObject(reply3);

    string tmp_path = string(path) + file_id + ".tmp";
    struct stat st;
    off_t file_size = 0;
    if (stat(tmp_path.c_str(), &st) == 0) {
        file_size = st.st_size;
    } else {
        file_size = 0;
    }

    send_message(fd, "PROGRESS " + file_id + " " + to_string(file_size) + "\n");
}