#ifndef SERVER_H
#define SERVER_H

#include <curl/curl.h>
#include <cstring>
#include <leveldb/options.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>
#include <string>
#include<set>
#include <openssl/ssl.h>      // 核心 SSL/TLS 函数，如 SSL_new、SSL_read、SSL_write
#include <openssl/err.h>      // 错误处理，如 ERR_print_errors_fp、ERR_get_error
#include <openssl/crypto.h>  
#include <hiredis/hiredis.h>
#include <leveldb/db.h>
#include<vector>
using namespace std;
 struct Client 
{
    int fd;
    string username;
    bool logged_in;
   SSL*ssl;
   bool handshak_down;
   string send_buffer;   // 待发送数据
    size_t send_offset;   // 已发送位置
    string recv_buffer;
};
extern map<string,vector<string>>offlinemsg;
void store_history(const string&sender,const string&place,const string&content);
extern std::map<int, Client> clients;
extern map<string, int> name_to_fd;
extern set<int> file_client_fds;
extern SSL*ssl;
extern int epoll_fd;
ssize_t  tls_write(int fd,const void*data,size_t size);
ssize_t tls_read(int fd,void*data,size_t size);
void lixian(int fd);
void Read(int fd);
void close_connection(int fd);
void flush_send_buffer(int fd);
void send_message(int fd, const std::string& msg);
void siliao(int sender_fd, const string& target_name, const string& content) ;
void qunliao(int sender_fd, const string& qun, const string& content);
void xitongbobao(const string&name,const string&msg);
bool is_friend(const string& user, const string& target);
#endif