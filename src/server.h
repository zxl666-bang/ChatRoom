#ifndef SERVER_H
#define SERVER_H

#include <curl/curl.h>
#include <cstring>
#include <deque>
#include <functional>
#include <leveldb/options.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <mutex>
#include <map>
#include <string>
#include <set>
#include <memory>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <hiredis/hiredis.h>
#include <leveldb/db.h>
#include <vector>
#include <cstdint>
#include <atomic>
#include <memory>

using namespace std;

struct Client {
    int fd = -1;
    string username;
    bool logged_in = false;
    SSL* ssl = nullptr;
    bool handshak_down = false;

    // Only the epoll thread performs SSL_read/SSL_write.
    // Worker threads only append to the outgoing buffer.
    string send_buffer;
    size_t send_offset = 0;
    string recv_buffer;

    // Stable per-client synchronization objects. shared_ptr keeps Client copyable.
    shared_ptr<recursive_mutex> state_mutex = make_shared<recursive_mutex>();
    shared_ptr<recursive_mutex> send_mutex = make_shared<recursive_mutex>();
    shared_ptr<recursive_mutex> io_mutex = make_shared<recursive_mutex>();
    shared_ptr<recursive_mutex> route_mutex = make_shared<recursive_mutex>();

    atomic<bool> closing{false};
    uint64_t generation = 0;
    pmr::deque<function<void()>>task;
    mutex task_lock;
    bool is_process;
    bool is_chat;
};

extern mutex file_clients_mtu;
extern map<string,vector<string>> offlinemsg;
void store_history(const string&sender,const string&place,const string&content);
extern map<string,string>chat;
extern map<string,string>chat_group;
extern std::map<int, std::shared_ptr<Client>> clients;
extern map<string, int> name_to_fd;
extern set<int> file_client_fds;
extern std::recursive_mutex file_mutex;
extern SSL*ssl;
extern int epoll_fd;
extern redisContext* redis_conn;

// Thread-safe hiredis wrapper. All server/file-transfer Redis calls should use it.
redisReply* redis_command(redisContext* c, const char* fmt, ...);
shared_ptr<Client> get_client(int fd);
int find_client_fd_by_name(const string& name);

ssize_t tls_write(int fd,const void*data,size_t size);
ssize_t tls_read(int fd,void*data,size_t size);
void lixian(int fd);
void Read(int fd);
void close_connection(int fd);
void flush_send_buffer(int fd);
void send_message(int fd, const std::string& msg);
void siliao(int sender_fd, const string& target_name, const string& content);
void qunliao(int fd,const string&qun,const string&content);
void qunliao(int sender_fd, const string& qun, const string& content);
void xitongbobao(const string&name,const string&msg);
void jiesan(int fd,const string&qun);
bool is_friend(const string& user, const string& target);
void send_pending_data(int fd);   // 只发送缓冲区数据，不修改 epoll 事件
#endif
