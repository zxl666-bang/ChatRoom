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
#include<time.h>
#include<unistd.h>
#include<fcntl.h>
#include<iostream>
#include<ctime>
#include<vector>
#include <cstdlib>
#include<sys/stat.h>
#include <sys/socket.h>
#include<filesystem>
#include "server.h"
using namespace std;
namespace fs=filesystem;
map<std::string, std::string> filename_to_file_id;
redisContext*g_redis;
const char*path="./files/";
map<int,FILETRANSFER> file_contexts;
std::recursive_mutex file_mutex;
string get_filename_meta(const string&file_id,redisContext*redis)
{
    string key="file:meta:"+file_id;
    redisReply*reply=(redisReply*)redis_command(redis,"HGET %s filename",key.c_str());
    if(!reply||reply->type!=REDIS_REPLY_STRING)
    {
        if(reply)
        {
            freeReplyObject(reply);
        }
        cout << "DEBUG: filename meta = unknow" << endl;
        return "unknow";
    }
    else
    {
        string name=string(reply->str);
        freeReplyObject(reply);
        cout << "DEBUG: filename meta = " << name << endl;
        return name;
    }
}

long long get_file_size(const string&file_id,redisContext*redis)
{
    string key="file:meta:"+file_id;
    redisReply*reply=(redisReply*)redis_command(redis,"HGET %s filesize",key.c_str());
    if(reply==nullptr||reply->type!=REDIS_REPLY_STRING)
    {
        if(reply)
        {
            freeReplyObject(reply);
        }
        return -1;
    }
    long long Size=stoull(reply->str);
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

            if (age.count() < EXPIRY_HOURS) continue;  // 未超时，跳过

            string file_id = filename.substr(0, filename.find(".tmp"));

          try {fs::remove(entry.path());
} catch (const fs::filesystem_error& e) {
    cerr << "删除临时文件失败: " << e.what() << endl;
    continue;
}

            string progress_key = "file:progress:" + file_id;
            redisReply* reply_progress = (redisReply*)redis_command(redis, "DEL %s", progress_key.c_str());
            if (!reply_progress || reply_progress->type != REDIS_REPLY_INTEGER) {
                cerr << "删除进度键失败: " << progress_key << endl;
            }
            if (reply_progress) freeReplyObject(reply_progress);

            string meta_key = "file:meta:" + file_id;
            redisReply* reply_meta = (redisReply*)redis_command(redis, "DEL %s", meta_key.c_str());
            if (!reply_meta || reply_meta->type != REDIS_REPLY_INTEGER) {
                cerr << "删除元信息键失败: " << meta_key << endl;
            }
            if (reply_meta) freeReplyObject(reply_meta);
        }
    } catch (const fs::filesystem_error& e) {
        cerr << "清理临时文件发生错误: " << e.what() << endl;
    }
}

void notify_reciver(redisContext* redis, const string& file_id) {
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
     cout << "notify_reciver called for file_id: " << file_id << endl;
       cout << "notify_reciver called, is_group=" << is_group << endl;
    if (!is_group) {
       
       int target_fd = find_client_fd_by_name(target);

if (target_fd != -1) {

    cout << "====================================" << endl;
    cout << "FILE NOTIFY DEBUG" << endl;
    cout << "target username = [" << target << "]" << endl;
    cout << "target fd       = " << target_fd << endl;

    auto client_it = get_client(target_fd);

    if (!client_it) {

        cerr << "ERROR: target fd not found in clients"
             << endl;

    } else {

        cout << "actual client username = ["
             << client_it->username
             << "]" << endl;

        cout << "logged_in = "
             << client_it->logged_in
             << endl;

        cout << "handshake = "
             << client_it->handshak_down
             << endl;

        if (client_it->username != target) {

            cerr << "!!! USERNAME -> FD MAPPING ERROR !!!"
                 << endl;

            cerr << "name_to_fd[" << target << "] = "
                 << target_fd << endl;

            cerr << "but clients[" << target_fd << "].username = "
                 << client_it->username
                 << endl;
        }
        else {

            cout << "Mapping correct, sending FILE_NOTIFY"
                 << endl;

            send_message(target_fd, notify_msg);
           string place=sender<target?sender+":"+target:target+":"+sender;
           store_history(sender, place, notify_msg);
        }
    }
    cout << "===================================="
         << endl;
}
else {

    cout << "Target offline: ["
         << target
         << "]"
         << endl;

    redis_command(
        redis,
        "RPUSH %s %s",
        ("offline:" + target).c_str(),
        notify_msg.c_str()
    );
             string key="files:"+target;
           redisCommand(redis,"RPUSH %s %s",key.c_str(),notify_msg.c_str());
    cout << "========== STORE FILE HISTORY ==========" << endl;
cout << "sender = [" << sender << "]" << endl;
cout << "target = [" << target << "]" << endl;
cout << "notify_msg = [" << notify_msg << "]" << endl;
string place=sender<target?sender+":"+target:target+":"+sender;
store_history(sender, place, notify_msg);

cout << "========== STORE FILE HISTORY DONE ==========" << endl;
}
    }  else {
    string members_key = "group:" + target+":members:";
    redisReply* members_reply = (redisReply*)redis_command(redis, "SMEMBERS %s", members_key.c_str());
    if (members_reply && members_reply->type == REDIS_REPLY_ARRAY) {
        for(size_t i=0;i<members_reply->elements;i++)
        {
        string member = members_reply->element[i]->str;
        int member_fd = find_client_fd_by_name(member);
        if (member_fd != -1) {
            send_message(member_fd, notify_msg);
            store_history(sender,member,notify_msg);
        } else {
            redis_command(redis, "RPUSH %s %s", ("offline:" + member).c_str(), notify_msg.c_str());
            store_history(sender,member,notify_msg);
        }
        string key="files:"+member;
        redisCommand(redis_conn,"RPUSH %s %s",key.c_str(),file_id.c_str());
    }
    }
    else {
        cerr << "获取群成员列表失败: " << members_key << endl;
    }
    if (members_reply) freeReplyObject(members_reply);
}
}

void init_file_transfer(redisContext* redis)
{
    if(mkdir(path,0755)!=0)
    {
        if(errno!=EEXIST)
        {
            exit(1);
        }
    }
    cleanup_temp_files(redis);
   return;
}

void handle_file_command(redisContext*redis,int fd,const string&sender,const string&target, const string&filename,size_t Size)
{
    string is_group="0";
    string key1="friends:"+sender;
    redisReply*reply1=(redisReply*)redis_command(redis,"SISMEMBER %s %s",key1.c_str(),target.c_str());
    if(!reply1||reply1->type!=REDIS_REPLY_INTEGER||reply1->integer==0)
    {
        string key2="group:"+target+":members:";
         redisReply*reply2=(redisReply*)redis_command(redis,"SISMEMBER %s %s",key2.c_str(),sender.c_str());
          if(!reply2||reply2->type!=REDIS_REPLY_INTEGER||reply2->integer==0)
          {
           send_message(fd,"不是好友也不是群成员，不能发送文件\n");
            if(reply2)
            {
                freeReplyObject(reply2);
                if(reply1) freeReplyObject(reply1);
            }
           return;
          }
          freeReplyObject(reply2);
          is_group="1";
        
    }
      if(reply1)
          {
            freeReplyObject(reply1);
          }
    string file_id=to_string(time(nullptr))+"_"+to_string(rand()%100000);
  
    string filepath=path+file_id+".tmp";
   
   int nfd=open(filepath.c_str(),O_CREAT|O_WRONLY|O_TRUNC,0644);
   if(nfd<0)
   {
    send_message(fd,"创建临时文件失败\n");
    return;
   }
   close(nfd);
   cout << "handle_file_command: sender=" << sender 
     << ", target=" << target 
     << ", filename=" << filename 
     << ", filesize=" << Size << endl;
    string key="file:meta:"+file_id;
    redisReply*reply=(redisReply*)redis_command(redis,"HSET %s sender %s target %s filename %s is_group %s filesize %llu status uploading",key.c_str(),sender.c_str(),target.c_str(),filename.c_str(),is_group.c_str(),(unsigned long long)Size);
    if(!reply||reply->type!=REDIS_REPLY_INTEGER)
    {
       
        if(reply)
        {
            if (!reply || reply->type != REDIS_REPLY_INTEGER) {
    if (reply) {
        cerr << "HSET failed, type=" << reply->type 
             << ", str=" << (reply->str ? reply->str : "null") << endl;
        freeReplyObject(reply);
    }
   send_message(fd, "reids存储哈希失败\n");
    return;
}
            freeReplyObject(reply);
        }
        send_message(fd,"reids存储哈希失败\n");
        return;
    }
    freeReplyObject(reply);
    redisReply*reply2=(redisReply*)redis_command(redis,"SET file:progress:%s 0",file_id.c_str());
    if(!reply2||reply2->type!=REDIS_REPLY_STATUS||string(reply2->str)!="OK")
    {
        send_message(fd,"reids存储SET失败\n");
        if(reply2)
        {
            freeReplyObject(reply2);
        }
        return;
    }
     freeReplyObject(reply2);
    string key2="filename_to_id:"+sender;
    redisReply*reply3=(redisReply*)redis_command(redis,"HSET %s %s %s",key2.c_str(),filename.c_str(),file_id.c_str());
     if(!reply3||reply3->type!=REDIS_REPLY_INTEGER)
    {
       
        if(reply3)
        {
            freeReplyObject(reply3);
        }
        send_message(fd,"reids存储哈希失败\n");
        return;
    }
    freeReplyObject(reply3);
    
    string msg="UPLOAD_READY:"+file_id+"\n";
  send_message(fd,msg);
    return;
}

void send_next_chunk(int fd) {
    lock_guard<recursive_mutex> file_lock(file_mutex);

    auto client = get_client(fd);
    if (!client) return;
    lock_guard<recursive_mutex> client_lock(*client->state_mutex);

    auto fit = file_contexts.find(fd);
    if (fit == file_contexts.end()) return;
    auto& ctx = fit->second;
    if (ctx.download_state != DOWNLOAD_SENDING) return;

    constexpr size_t CHUNK_SIZE = 64 * 1024;
    constexpr size_t MAX_BYTES_PER_EVENT = 256 * 1024;
    size_t budget = MAX_BYTES_PER_EVENT;

    while (budget > 0) {
        if (ctx.chunk_sent >= ctx.download_chunk.size()) {
            ctx.download_chunk.clear();
            ctx.chunk_sent = 0;

            vector<char> data(CHUNK_SIZE);
            ssize_t bytes_read = read(ctx.download_file_fd, data.data(), CHUNK_SIZE);
            if (bytes_read > 0) {
                data.resize(static_cast<size_t>(bytes_read));
                const size_t body_len = 1 + 16 + 8 + data.size();
                if (body_len > UINT32_MAX) {
                    close_connection(fd);
                    return;
                }

                uint32_t net_len = htonl(static_cast<uint32_t>(body_len));
                ctx.download_chunk.resize(4 + body_len);
                memcpy(ctx.download_chunk.data(), &net_len, 4);
                ctx.download_chunk[4] = static_cast<char>(0x83);

                char file_id_buf[16];
                memset(file_id_buf, ' ', sizeof(file_id_buf));
                memcpy(file_id_buf, ctx.file_id.data(), min(ctx.file_id.size(), sizeof(file_id_buf)));
                memcpy(ctx.download_chunk.data() + 5, file_id_buf, 16);

                uint64_t net_offset = htobe64(ctx.download_offset + ctx.total_sent);
                memcpy(ctx.download_chunk.data() + 21, &net_offset, 8);
                memcpy(ctx.download_chunk.data() + 29, data.data(), data.size());
            } else if (bytes_read == 0) {
                close(ctx.download_file_fd);
                ctx.download_file_fd = -1;
                ctx.download_state = DOWNLOAD_IDLE;
                close_connection(fd);
                return;
            } else {
                perror("read file error");
                close_connection(fd);
                return;
            }
        }

        const size_t remain = ctx.download_chunk.size() - ctx.chunk_sent;
        const size_t to_write = min(remain, budget);
        const char* data = ctx.download_chunk.data() + ctx.chunk_sent;
        ssize_t n = tls_write(fd, data, to_write);

        if (n > 0) {
            ctx.chunk_sent += static_cast<size_t>(n);
            budget -= static_cast<size_t>(n);
            if (ctx.chunk_sent == ctx.download_chunk.size()) {
                const size_t payload_len = ctx.download_chunk.size() - 4 - 1 - 16 - 8;
                ctx.total_sent += payload_len;
                ctx.download_chunk.clear();
                ctx.chunk_sent = 0;
            }
            continue;
        }

        if (n == -2 || n == -3) {
            epoll_event ev{};
            ev.events = EPOLLIN | EPOLLOUT;
            ev.data.fd = fd;
            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
            return;
        }

        close_connection(fd);
        return;
    }

    epoll_event ev{};
    ev.events = EPOLLIN | EPOLLOUT;
    ev.data.fd = fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
}


void process(int fd,redisContext*redis,const vector<char>&buf)
{
    if (buf.size() < 25) {
    cerr << "Invalid file packet, size="
         << buf.size() << endl;

    close_connection(fd);
    return;
}
    uint8_t cmd = buf[0];
    char file_id_buf[17] = {0};
    memcpy(file_id_buf, buf.data() + 1, 16);
    string file_id(file_id_buf);
    size_t space = file_id.find(' ');
    if (space != string::npos) file_id = file_id.substr(0, space);

    uint64_t offset = 0;
    memcpy(&offset, buf.data() + 1 + 16, 8);
    offset = be64toh(offset);
    cerr << "on_file_data: cmd=" << (int)cmd << ", file_id=" << file_id << ", offset=" << offset << endl;

    if (cmd == 0x01) {
        uint32_t data_len = buf.size() - 1 - 16 - 8;
        const char* data = buf.data() + 1 + 16 + 8;
    cout << "DEBUG: Entering completion block" << endl;
   string meta_key = "file:meta:" + file_id;
    redisReply* reply1 = (redisReply*)redis_command(redis, "HGET %s status", meta_key.c_str());
    if (!reply1 || reply1->type != REDIS_REPLY_STRING || string(reply1->str) != "uploading") {
        send_message(fd, "文件状态无效或未上传\n");
        if (reply1) freeReplyObject(reply1);
        close_connection(fd);
        return;
    }
    freeReplyObject(reply1);

    redisReply* reply2 = (redisReply*)redis_command(redis, "HGET %s filesize", meta_key.c_str());
    if (!reply2 || reply2->type != REDIS_REPLY_STRING) {
        send_message(fd, "获取文件大小失败\n");
        if (reply2) freeReplyObject(reply2);
        
       close_connection(fd);
        return;
    }
    size_t filesize = stoull(reply2->str);
    freeReplyObject(reply2);

    string progress_key = "file:progress:" + file_id; 
    redisReply* reply3 = (redisReply*)redis_command(redis, "GET %s", progress_key.c_str());
    if (!reply3 || reply3->type != REDIS_REPLY_STRING) {
        send_message(fd, "获取进度失败\n");
        if (reply3) freeReplyObject(reply3);
     
       close_connection(fd);
        return;
    }
    size_t current_offset = stoull(reply3->str);
    freeReplyObject(reply3);

    if (offset != current_offset) {
        send_message(fd, "偏移量不匹配\n");
       close_connection(fd);
        return;
    }

    string filename = get_filename_meta(file_id, redis);

    string tmp_path = "./files/" + file_id + ".tmp";
    int tmp_fd = open(tmp_path.c_str(), O_WRONLY);
    if (tmp_fd < 0) {
        send_message(fd, "打开临时文件失败\n");
       close_connection(fd);
        return;
    }
    lseek(tmp_fd, offset, SEEK_SET);
    ssize_t written = write(tmp_fd, data, data_len);
    close(tmp_fd);

    if (written != (ssize_t)data_len) {
        send_message(fd, "写入数据失败\n");
      close_connection(fd);
        return;
    }

    redisReply* reply4 = (redisReply*)redis_command(redis, "INCRBY %s %d", progress_key.c_str(), data_len);
    if (!reply4 || reply4->type != REDIS_REPLY_INTEGER) {
        send_message(fd, "更新进度失败\n");
        if (reply4) freeReplyObject(reply4);
      close_connection(fd);
        return;
    }
    long long new_progress = reply4->integer;
    freeReplyObject(reply4);
    cout << "DEBUG: new_progress=" << new_progress << ", filesize=" << filesize << endl;
   
    if (new_progress >= (long long)filesize) {
     
        string final_path = "./files/" + file_id + "_" + filename;
        cout << "DEBUG: tmp_path=" << tmp_path << endl;
        cout << "DEBUG: final_path=" << final_path << endl;
        if (rename(tmp_path.c_str(), final_path.c_str()) != 0)
{
    send_message(fd,"重命名临时文件失败\n");
   
   close_connection(fd);
    return;
}
cout << "DEBUG: rename result:success"  << endl;
    
      redis_command(redis, "HSET %s status complete", meta_key.c_str());
    redis_command(redis, "DEL %s", progress_key.c_str());

    // 向发送端发送成功确认
    string complete_msg = "UPLOAD_COMPLETE " + file_id + "\n";
    send_message(fd, complete_msg);

    cout << "DEBUG: About to call notify_reciver" << endl;
    notify_reciver(redis, file_id);
    cout << "Upload complete, notifying receiver..." << endl;

    return;

    }

  
    return;
}
    else if (cmd == 0x03) 
   {
    string meta_key = "file:meta:" + file_id;
    redisReply* reply1 = (redisReply*)redis_command(redis, "HGET %s status", meta_key.c_str());
    if (!reply1 || reply1->type != REDIS_REPLY_STRING || string(reply1->str) != "complete") 
    {
        if (reply1) freeReplyObject(reply1);
       
      close_connection(fd);
        return;
    }
    freeReplyObject(reply1);
  
    string filename = get_filename_meta(file_id, redis);
    string final_path = "./files/" + file_id + "_" + filename;

    int file_fd = open(final_path.c_str(), O_RDONLY);
    if (file_fd < 0) 
    {
        
       
        perror("open file for download");
        close_connection(fd);
        return;
    }

   if (lseek(file_fd, offset, SEEK_SET) == -1) 
   {
    perror("lseek");
    close(file_fd);
    close_connection(fd);
    return;
    }
    {
        lock_guard<recursive_mutex> file_lock(file_mutex);
        auto& ctx = file_contexts[fd];
        ctx.file_id = file_id;
        ctx.download_state = DOWNLOAD_SENDING;
        ctx.download_file_fd = file_fd;
        ctx.download_offset = offset;
        ctx.total_sent = 0;
        ctx.download_chunk.clear();
        ctx.chunk_sent = 0;
    }

    send_next_chunk(fd);
   
}
    else {
    cerr << "Unknown command: " << (int)cmd << endl;
   
    close_connection(fd);
    return;
}
}

void on_file_data(int fd, redisContext* redis)
{
    lock_guard<recursive_mutex> file_lock(file_mutex);

    cerr << "[FILE] on_file_data fd=" << fd << endl;

    auto fit = file_contexts.find(fd);

    if (fit == file_contexts.end()) {
        cerr << "[FILE] no file context, fd=" << fd << endl;
        close_connection(fd);
        return;
    }

    FILETRANSFER& ctx = fit->second;

    if (ctx.download_state == DOWNLOAD_SENDING) {
        send_next_chunk(fd);
        return;
    }

    char buf[16 * 1024];

    while (true) {

        ssize_t n = tls_read(
            fd,
            buf,
            sizeof(buf)
        );

        if (n > 0) {

            cerr << "[FILE] tls_read fd="
                 << fd
                 << " bytes="
                 << n
                 << endl;

            ctx.buffer.insert(
                ctx.buffer.end(),
                buf,
                buf + n
            );

        }
        else if (n == -2) {

            cerr << "[FILE] WANT_READ fd="
                 << fd
                 << ", buffered="
                 << ctx.buffer.size()
                 << endl;

            struct epoll_event ev{};

            ev.events = EPOLLIN;
            ev.data.fd = fd;

            epoll_ctl(
                epoll_fd,
                EPOLL_CTL_MOD,
                fd,
                &ev
            );

            return;
        }
        else if (n == -3) {

            cerr << "[FILE] WANT_WRITE fd="
                 << fd
                 << endl;

            struct epoll_event ev{};

            ev.events =
                EPOLLIN | EPOLLOUT;

            ev.data.fd = fd;

            epoll_ctl(
                epoll_fd,
                EPOLL_CTL_MOD,
                fd,
                &ev
            );

            return;
        }
        else if (n == 0) {

            cerr << "[FILE] peer closed fd="
                 << fd
                 << ", buffered="
                 << ctx.buffer.size()
                 << endl;

            close_connection(fd);
            return;
        }
        else {

            cerr << "[FILE] tls_read error fd="
                 << fd
                 << endl;

            close_connection(fd);
            return;
        }


        while (true) {

            if (ctx.state == PARSE_HEADER) {

                if (ctx.buffer.size() < 4) {

                    cerr << "[FILE] "
                         << "waiting header: "
                         << ctx.buffer.size()
                         << "/4"
                         << endl;

                    return;
                }

                uint32_t net_len = 0;

                memcpy(
                    &net_len,
                    ctx.buffer.data(),
                    sizeof(net_len)
                );

                ctx.total_len =
                    ntohl(net_len);

                ctx.buffer.erase(
                    ctx.buffer.begin(),
                    ctx.buffer.begin() + 4
                );

                ctx.header_bytes = 0;


                const uint32_t HEADER_SIZE =
                    1 + 16 + 8;

                const uint32_t MAX_BODY_SIZE =
                    HEADER_SIZE + 64 * 1024;

                if (ctx.total_len < HEADER_SIZE ||
                    ctx.total_len > MAX_BODY_SIZE) {

                    cerr << "[FILE] "
                         << "invalid packet length="
                         << ctx.total_len
                         << endl;

                    close_connection(fd);
                    return;
                }

                cerr << "[FILE] "
                     << "new packet body length="
                     << ctx.total_len
                     << endl;

                ctx.state = PARSE_BODY;
            }


            if (ctx.state == PARSE_BODY) {

                if (ctx.buffer.size() <
                    ctx.total_len) {

                    cerr << "[FILE] "
                         << "waiting body: buffered="
                         << ctx.buffer.size()
                         << ", need="
                         << ctx.total_len
                         << endl;

                    return;
                }

                vector<char> packet(
                    ctx.buffer.begin(),
                    ctx.buffer.begin()
                        + ctx.total_len
                );

                ctx.buffer.erase(
                    ctx.buffer.begin(),
                    ctx.buffer.begin()
                        + ctx.total_len
                );

                ctx.state = PARSE_HEADER;
                ctx.header_bytes = 0;
                ctx.total_len = 0;

                cerr << "[FILE] "
                     << "complete packet received, "
                     << "size="
                     << packet.size()
                     << ", remain_buffer="
                     << ctx.buffer.size()
                     << endl;


                process(
                    fd,
                    redis,
                    packet
                );

                if (!get_client(fd)) {

                    return;
                }

                if (file_contexts.find(fd) ==
                    file_contexts.end()) {

                    return;
                }


                fit = file_contexts.find(fd);

                if (fit == file_contexts.end())
                    return;

                FILETRANSFER& new_ctx =
                    fit->second;

                if (new_ctx.download_state ==
                    DOWNLOAD_SENDING) {

                    send_next_chunk(fd);
                    return;
                }


                continue;
            }

            break;
        }

    }
}

void on_file_connection(int fd, bool connected) {
    lock_guard<recursive_mutex> file_lock(file_mutex);

    cerr << "on_file_connection: fd=" << fd
         << ", connected=" << connected << endl;

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


void Resend_file(int fd,const string&sender, const string& filename, redisContext* redis) {
   string key1="filename_to_id:"+sender;
   redisReply*reply2=(redisReply*)redis_command(redis,"HGET %s %s",key1.c_str(),filename.c_str());
   if(!reply2||reply2->type!=REDIS_REPLY_STRING)
   {
    send_message(fd,"查找file_id失败\n");
    if(reply2)
    {
        freeReplyObject(reply2);
    }
    return;
   }
   string file_id=string(reply2->str);
   freeReplyObject(reply2);
    string meta_key = "file:meta:" + file_id;
    redisReply* reply1 = (redisReply*)redis_command(redis, "EXISTS %s", meta_key.c_str());
    if (!reply1 || reply1->type != REDIS_REPLY_INTEGER || reply1->integer != 1) {
        send_message(fd, "找不到该文件\n");
        if (reply1) freeReplyObject(reply1);
        return;
    }
    freeReplyObject(reply1);
    redisReply*reply3=(redisReply*)redis_command(redis,"HGET %s status",meta_key.c_str());
    if(!reply3||reply3->type!=REDIS_REPLY_STRING)
    {
        send_message(fd,"网络错误\n");
        if(reply3)
        {
            freeReplyObject(reply3);
        }
        return;
    }
    if(string(reply3->str)=="complete")
    {
        send_message(fd,"文件已经上传完毕\n");
        freeReplyObject(reply3);
        return;
    }
    if (string(reply3->str) != "uploading" ) 
    {
    send_message(fd, "文件状态异常，无法续传\n");
    freeReplyObject(reply3);
    return;
    }
    freeReplyObject(reply3);
    string progress_key = "file:progress:" + file_id;   // 修正冒号
    redisReply* reply = (redisReply*)redis_command(redis, "GET %s", progress_key.c_str());
    if (!reply) {
        send_message(fd, "网络错误，无法获取进度\n");
        return;
    }
    if (reply->type != REDIS_REPLY_STRING) {
        send_message(fd, "PROGRESS " + file_id + " 0\n");
        freeReplyObject(reply);
        return;
    }
    string offset = reply->str;
    freeReplyObject(reply);

    send_message(fd, "PROGRESS " + file_id + " " + offset + "\n");
}

