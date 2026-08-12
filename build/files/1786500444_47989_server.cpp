#include <mysql/field_types.h>
#include <openssl/evp.h>
#ifndef my_bool
#define my_bool unsigned char
#endif
#include <openssl/ssl.h>      // 核心 SSL/TLS 函数，如 SSL_new、SSL_read、SSL_write
#include <openssl/err.h>      // 错误处理，如 ERR_print_errors_fp、ERR_get_error
#include <openssl/crypto.h>   // 加密基础函数（可选，但若使用锁回调则需）
#include <curl/curl.h>
#include <iostream>
#include <cstring>
#include <leveldb/options.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include<algorithm>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>
#include <string>
#include<vector>
#include <sstream>
#include<chrono>
#include <signal.h>
#include<mysql/mysql.h>
#include<set>
#include <hiredis/hiredis.h>
#include <leveldb/db.h>
#include "send_email.h"
#include "server.h"
#include "file_transfer.h"
using namespace std;
const int MAX_EVENTS = 64;
const int PORT = 8888;
const int FILEPORT=8889;

leveldb::DB*history_db=nullptr;
map<int, Client> clients;
set<int> file_client_fds;
map<string, int> name_to_fd;
redisContext* redis_conn = nullptr;
int epoll_fd;
MYSQL*mysql_conn=nullptr;
// 去除字符串首尾空白字符（包括 \r, \n, 空格, \t）
string trim(const string& s) {
    size_t start = s.find_first_not_of(" \t\n\r");
    if (start == string::npos) return "";
    size_t end = s.find_last_not_of(" \t\n\r");
    return s.substr(start, end - start + 1);
}
ssize_t tls_read(int fd, void* buf, size_t size) {
    auto it = clients.find(fd);
    if (it == clients.end() || !it->second.ssl || !it->second.handshak_down) {
        return -1;
    }

    ERR_clear_error();
    int ret = SSL_read(it->second.ssl, buf, static_cast<int>(size));
    if (ret > 0) return ret;

    int err = SSL_get_error(it->second.ssl, ret);
    if (err == SSL_ERROR_WANT_READ) return -2;
    if (err == SSL_ERROR_WANT_WRITE) return -3;
    if (err == SSL_ERROR_ZERO_RETURN) return 0;
    if (err == SSL_ERROR_SYSCALL && ERR_get_error() == 0) return 0;

    cerr << "SSL_read error on fd " << fd << ": ";
    ERR_print_errors_fp(stderr);
    return -1;
}

ssize_t tls_write(int fd, const void* buf, size_t size) {
    auto it = clients.find(fd);
    if (it == clients.end() || !it->second.ssl || !it->second.handshak_down) {
        return -1;
    }

    ERR_clear_error();
    int ret = SSL_write(it->second.ssl, buf, static_cast<int>(size));
    if (ret > 0) return ret;

    int err = SSL_get_error(it->second.ssl, ret);
    if (err == SSL_ERROR_WANT_READ) return -2;
    if (err == SSL_ERROR_WANT_WRITE) return -3;
    if (err == SSL_ERROR_ZERO_RETURN) return 0;

    cerr << "SSL_write error on fd " << fd << ": ";
    ERR_print_errors_fp(stderr);
    return -1;
}

void close_connection(int fd) {
    if (clients.find(fd) == clients.end()) return;
    Client& c = clients[fd];

    // 1. 清理登录相关（但不广播）
    if (c.logged_in && !c.username.empty()) {
        name_to_fd.erase(c.username);
        // 不再调用 broadcast，由调用者决定是否发送
    }

    // 2. 从 epoll 移除
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr);

    // 3. 文件传输清理
    if (file_client_fds.find(fd) != file_client_fds.end()) {
        file_client_fds.erase(fd);
        on_file_connection(fd, false);
    }

    // 4. 释放 SSL
    if (c.ssl) {
        SSL_shutdown(c.ssl);
        SSL_free(c.ssl);
        c.ssl = nullptr;
    }

    // 5. 关闭 socket
    close(fd);

    // 6. 从 clients 删除
    clients.erase(fd);
}



void flush_send_buffer(int fd) {
    if (clients.find(fd) == clients.end()) return;
    Client& c = clients[fd];
    if (c.send_buffer.empty()) {
        // 缓冲区空，可禁用写事件（但保留读事件）
        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.fd = fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
        return;
    }

    const char* data = c.send_buffer.data() + c.send_offset;
    size_t remain = c.send_buffer.size() - c.send_offset;

    while (remain > 0) {
       cerr << "[FLUSH] fd="
     << fd
     << " remain="
     << remain
     << endl;

int n = tls_write(fd, data, remain);

cerr << "[FLUSH] tls_write returned "
     << n
     << endl;
        if (n > 0) {
            c.send_offset += n;
            remain -= n;
            data += n;
        } 
        else if(n==-2 || n==-3)
        {
            struct epoll_event ev{};
            ev.events = EPOLLIN | EPOLLOUT;
            ev.data.fd = fd;
            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
            return;
        }
        else 
        {
            cerr << "SSL_write error: " << ERR_reason_error_string(ERR_get_error()) << endl;
            close_connection(fd);
            return;
        }
    }

    // 全部发送完毕，清空缓冲区
    c.send_buffer.clear();
    c.send_offset = 0;
    // 禁用写事件
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
}

void send_message(int fd, const string& msg) {

    cerr << "\n========== send_message ==========\n";
    cerr << "fd = " << fd << endl;
    cerr << "msg = [" << msg << "]" << endl;

    auto it = clients.find(fd);

    if (it == clients.end()) {
        cerr << "ERROR: fd not found in clients"
             << endl;
        return;
    }

    cerr << "username = ["
         << it->second.username
         << "]"
         << endl;

    cerr << "logged_in = "
         << it->second.logged_in
         << endl;

    cerr << "ssl = "
         << it->second.ssl
         << endl;

    cerr << "handshake = "
         << it->second.handshak_down
         << endl;

    if (!it->second.ssl ||
        !it->second.handshak_down) {

        cerr << "ERROR: TLS not ready"
             << endl;

        return;
    }

    it->second.send_buffer.append(msg);

    cerr << "send_buffer size = "
         << it->second.send_buffer.size()
         << endl;

    flush_send_buffer(fd);

    cerr << "flush_send_buffer finished"
         << endl;

    cerr << "==================================\n";
}

bool init_mysql()
{
    
    mysql_conn=mysql_init(nullptr);
     if (!mysql_conn) {
        cerr << "mysql_init failed" << endl;
        return false;
    }
    if (!mysql_real_connect(mysql_conn, "127.0.0.1", "chat_user", "chat123456", 
                            "chat_db", 3306, nullptr, 0)) 
    {
        cerr<<"初始化mysql失败"<<mysql_error(mysql_conn)<<endl;
        mysql_close(mysql_conn);
        mysql_conn = nullptr;
        return false;
    }
    if (mysql_set_character_set(mysql_conn, "utf8mb4")) {
        cerr << "mysql_set_character_set failed: " << mysql_error(mysql_conn) << endl;
        mysql_close(mysql_conn);
        mysql_conn=nullptr;
        return false;
    }
    return true;
}

vector<vector<string>>excute_select(const string&sql,const vector<string>&param={})
{
    if (mysql_conn == nullptr) {
    cerr << "MySQL connection not initialized" << endl;
    return {}; // 或 return -1;
}
    vector<vector<string>>rows;
    MYSQL_STMT*stmt=mysql_stmt_init(mysql_conn);
    if(!stmt)
    {
        cerr<<"初始化stmt失败"<<mysql_error(mysql_conn)<<endl;
        return rows;
    }
    if(mysql_stmt_prepare(stmt,sql.c_str(),sql.length()))
    {
        cerr<<"mysql_stmt_prepare失败"<<mysql_stmt_error(stmt)<<endl;
        mysql_stmt_close(stmt);
        return rows;
    }
    if(!param.empty())
    {
        vector<MYSQL_BIND>bind(param.size());
        memset(bind.data(),0,sizeof(MYSQL_BIND)*param.size());
        for(size_t i=0;i<param.size();i++)
        {
            bind[i].buffer_type=MYSQL_TYPE_STRING;
            bind[i].buffer_length=param[i].length();
            bind[i].buffer= const_cast<char*>(param[i].c_str());
        }
        if (mysql_stmt_bind_param(stmt, bind.data())) {
            cerr << "mysql_stmt_bind_param failed: " << mysql_stmt_error(stmt) << endl;
            mysql_stmt_close(stmt);
            return rows;
        }
    }
    if(mysql_stmt_execute(stmt))
    {
        cerr<<"nysql_stmt_excute失败"<<mysql_stmt_error(stmt)<<endl;
        mysql_stmt_close(stmt);
        return rows;
    }
     MYSQL_RES* res = mysql_stmt_result_metadata(stmt);
    if (!res)
    {
        mysql_stmt_close(stmt);
        return rows;
    }
    int nums=mysql_num_fields(res);
    vector<MYSQL_BIND>result_bind(nums);
    vector<vector<char>>buffer(nums);
    vector<unsigned long>length(nums);
    vector<my_bool>is_null(nums);
    for(int i=0;i<nums;i++)
    {
         buffer[i].resize(1024);
        memset(&result_bind[i],0,sizeof(MYSQL_BIND));
        result_bind[i].buffer_type=MYSQL_TYPE_STRING;
        result_bind[i].buffer=buffer[i].data();
        result_bind[i].buffer_length=buffer[i].size();
        result_bind[i].length=&length[i];
      result_bind[i].is_null = reinterpret_cast<bool*>(&is_null[i]);
    }
    if(mysql_stmt_bind_result(stmt,result_bind.data()))
    {
        cerr<<"mysql_stmt_bind_result失败"<<mysql_stmt_error(stmt)<<endl;
        mysql_free_result(res);
        mysql_stmt_close(stmt);
        return rows;
    }
    if(mysql_stmt_store_result(stmt))
    {
          cerr<<"mysql_stmt_store_result失败"<<mysql_stmt_error(stmt)<<endl;
        mysql_free_result(res);
        mysql_stmt_close(stmt);
        return rows;
    }
    while(mysql_stmt_fetch(stmt)==0)
    {
        vector<string>row;
        for(int i=0;i<nums;i++)
        {
            if(is_null[i])
            {
                row.push_back("");
            }
            else
            {
                  string val(buffer[i].data(), length[i]);
                row.push_back(val);
            }
        }
        rows.push_back(row);
    }
    mysql_free_result(res);
    mysql_stmt_close(stmt);
    return rows;
}

int64_t excute_updata(const string&sql,const vector<string>&param={})
{
    if (mysql_conn == nullptr) {
    cerr << "MySQL connection not initialized" << endl;
    return -1;
}
    MYSQL_STMT*stmt=mysql_stmt_init(mysql_conn);
    if(stmt==nullptr)
    {
        cerr<<"mysql_stmt_init失败"<<mysql_error(mysql_conn)<<endl;
        return -1;
    }
    if(mysql_stmt_prepare(stmt,sql.c_str(),sql.length()))
    {
        cerr<<"mysql_stmt_prepare失败"<<mysql_stmt_error(stmt)<<endl;
        mysql_stmt_close(stmt);
        return -1;
    }
    if(!param.empty())
    {
        vector<MYSQL_BIND>bind(param.size());
        memset(bind.data(), 0, sizeof(MYSQL_BIND) * param.size());
        for(size_t i=0;i<param.size();i++)
        {
            bind[i].buffer_type=MYSQL_TYPE_STRING;
            bind[i].buffer_length=param[i].length();
            bind[i].buffer=const_cast<char*>(param[i].c_str());
        }
        if(mysql_stmt_bind_param(stmt,bind.data()))
        {
            cerr<<"mysql_stmt_bind_param"<<mysql_stmt_error(stmt)<<endl;
            mysql_stmt_close(stmt);
            return -1;
        }
    }
    if(mysql_stmt_execute(stmt))
    {
        cerr<<"mysql_stmt_execute"<<mysql_stmt_error(stmt)<<endl;
        mysql_stmt_close(stmt);
        return -1;
    }
   int64_t affected_rows=mysql_stmt_affected_rows(stmt);
   mysql_stmt_close(stmt);
   return affected_rows;
}
int set_nonblocking(int fd) 
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) 
    {return -1;
    }
        return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}


bool init_redis() {
    redis_conn = redisConnect("127.0.0.1", 6379);
    if (redis_conn == nullptr || redis_conn->err) {
        cerr << "Redis connection error: "
             << (redis_conn ? redis_conn->errstr : "null") << endl;
        return false;
    }
    cout << "Connected to Redis" << endl;
    return true;
}

void init_leveldb()
{
    leveldb::Options option;
    leveldb::Status status;
    option.create_if_missing=true;
    string filename="./history_db";
    status=leveldb::DB::Open(option, filename, &history_db);
    if(!status.ok())
    {
        cerr<<"初始化leveldb失败 "<<status.ToString()<<endl;
       exit(1);
    }
    else
    {
        cerr<<"初始化leveldb成功"<<endl;
        return;
    }
}

void store_history(const string&sender,const string&place,const string&content)
{
    auto now=chrono::system_clock::now();
    auto ms=chrono::duration_cast<chrono::milliseconds>(now.time_since_epoch()).count();
    string key="history:"+place+":"+to_string(ms)+":"+to_string(rand());
    string value=sender+":"+content;
    if(history_db==nullptr)
    {
        cerr<<"历史数据未初始化，先初始化\n";
        return;
    }
    leveldb::Status status=history_db->Put(leveldb::WriteOptions(),key,value);
    if(!status.ok())
    {

        cerr<<"聊天记录存储失败"<<status.ToString()<<endl;
    }
    return;
}

bool user_exists2(const string& username) {
    string key = "user:" + username;
    redisReply* reply = (redisReply*)redisCommand(redis_conn, "EXISTS %s", key.c_str());
    if (reply == nullptr) return false;
    bool exists = (reply->type == REDIS_REPLY_INTEGER && reply->integer == 1);
    freeReplyObject(reply);
    return exists;
}

bool user_exists1(const string&name)
{
    string sql="SELECT id FROM users WHERE username = ?";
    auto it=excute_select(sql,{name});
    return (!it.empty());
}

string generat_captcha()
{
    string code;
    for(int i=0;i<6;i++)
    {
        code+='0'+rand()%10;
    }
    return code;
}

void GET_CAPTCHA(int ufd,const string&email)
{
     cout << "收到验证码请求，邮箱: " << email << endl; 
   size_t pos=email.find("@163.com");
    if(pos==string::npos)
    {
        send_message(ufd,"请使用163邮箱\n");
        return;
    }
    string key1="captcha:limit:"+email;
    redisReply*reply1=(redisReply*)redisCommand(redis_conn,"GET %s",key1.c_str());
    if(!reply1)
    {
        send_message(ufd,"网不好\n");
        return;
    }
    if(reply1->type==REDIS_REPLY_STRING&&reply1->str!=nullptr)
    {
        send_message(ufd,"不要频繁发送\n");
        freeReplyObject(reply1);
        return;
    }
    freeReplyObject(reply1);
   string code=generat_captcha();
   string key2="captcha:code:"+email;
   redisReply*reply2=(redisReply*)redisCommand(redis_conn,"SET %s %s EX 300",key2.c_str(),code.c_str());
   if(!reply2||reply2->type!=REDIS_REPLY_STATUS||strcmp(reply2->str,"OK")!=0)
   {
    send_message(ufd,"验证码设置失败\n");
    if(reply2)
    {
        freeReplyObject(reply2);
    }
    return;
   }
   freeReplyObject(reply2);
   string key3="captcha:limit:"+email;
   redisCommand(redis_conn,"SET %s 1 EX 60",key3.c_str());
   bool send_successe=send_email(email,"验证码","你的验证码是: "+code);
   if(send_successe)
   {
    send_message(ufd,"验证码发送成功\n");
    return;
   }
   else
   {
    send_message(ufd,"验证码发送失败\n");
    return;
   }

}

bool is_email2(const string& username, const string& email) {
    string key = "user:" + username;
    redisReply* reply = (redisReply*)redisCommand(redis_conn, "HGET %s email", key.c_str());
    if (!reply || reply->type != REDIS_REPLY_STRING) {
        if (reply) freeReplyObject(reply);
        return false;
    }
    bool ok = (string(reply->str) == email);
    freeReplyObject(reply);
    return ok;
}

bool verify_captcha(int ufd,const string&email,const string&code)
{
   cout << "verify_captcha: email = " << email << endl;
   cout << "verify_captcha: key = " << "captcha:code:" + email << endl;
    string key1="captcha:code:"+email;
    redisReply*reply1=(redisReply*)redisCommand(redis_conn,"GET %s",key1.c_str());
    if(!reply1)
    {
        send_message(ufd,"网不好\n");
        return false;
    }
    if (reply1) 
    {
    cout << "reply1->type = " << reply1->type << endl;
} 
    if(reply1->type!=REDIS_REPLY_STRING)
    {
        send_message(ufd,"获取验证码失败\n");
        freeReplyObject(reply1);
        return false;
    }
    if(string(reply1->str)==code)
    {
         send_message(ufd,"验证码正确\n");
         freeReplyObject(reply1);
         redisCommand(redis_conn,"DEL %s",key1.c_str());
         return true;
    }
    send_message(ufd,"验证码错误\n");
    freeReplyObject(reply1);
    return false;
}

bool regiser_user1(int ufd, const string& username, const string& pwd_hash, const string& email, const string& code) {
    // 1. 检查用户名是否存在
    cout << "regiser_user: email = " << email << ", code = " << code << endl;
    if (user_exists1(username)) {
        send_message(ufd, "用户名已存在\n");
        return false;
    }

    // 2. 检查邮箱是否已被绑定
    string email_key = "email:" + email;
    redisReply* reply = (redisReply*)redisCommand(redis_conn, "EXISTS %s", email_key.c_str());
    if (reply && reply->type == REDIS_REPLY_INTEGER && reply->integer == 1) {
        send_message(ufd, "邮箱已被注册\n");
        freeReplyObject(reply);
        return false;
    }
    if (reply) freeReplyObject(reply);

    // 3. 验证验证码（内部已自动删除验证码）
    if (!verify_captcha(ufd, email, code)) {
        // verify_captcha 会发送错误消息，无需额外处理
        return false;
    }

    // 4. 创建用户记录（同时设置 password 和 email）
    string user_key = "user:" + username;
    redisReply* reply2 = (redisReply*)redisCommand(redis_conn, "HSET %s password %s email %s",
                                                    user_key.c_str(), pwd_hash.c_str(), email.c_str());
    if (!reply2 || reply2->type != REDIS_REPLY_INTEGER || reply2->integer != 2) {
        send_message(ufd, "注册失败，请重试\n");
        if (reply2) freeReplyObject(reply2);
        return false;
    }
    freeReplyObject(reply2);

    // 5. 存储反向映射（邮箱 -> 用户名）
    redisCommand(redis_conn, "SET %s %s", email_key.c_str(), username.c_str());

    send_message(ufd, "注册成功\n");
    return true;
}

bool registeruser(int fd,const string&name,const string&password,const string&email,const string&code)
{
    string sql1="SELECT id FROM users WHERE email=?";
    auto it1=excute_select(sql1,{email});
    if(!it1.empty())
    {
        send_message(fd,"邮箱已经被注册过\n");
        return false;
    }
    string sql="INSERT INTO users (username,password_hash,email) VALUES (?,?,?)";
    if(user_exists1(name))
    {
        send_message(fd,"该用户已存在\n");
        return false;
    }
    if(!verify_captcha(fd,email,code))
    {
        return false;
    }
    auto it=excute_updata(sql,{name,password,email});
    if(it==1)
    {
        send_message(fd,"注册成功，请登录\n");
        return true;
    }
    else
    {
        send_message(fd,"注册失败\n");
        return false;
    }
}
bool is_email1(const string&name,const string&email)
{
    string sql="SELECT email FROM users WHERE username=?";
    auto it=excute_select(sql,{name});
    if(it.empty())
    {
        return false;
    }
   return (it[0][0]==email);
}
bool login(int fd,const string&name,const string&password,const string&email,const string&code)
{
    if(!user_exists1(name))
    {
        send_message(fd,"用户不存在\n");
        return false;
    }
    if(!verify_captcha(fd,email,code))

    {
        return false;
    }
    string sql="SELECT password_hash, email FROM users WHERE username= ? ";
    vector<vector<string>>res=excute_select(sql,{name});
    if(res.empty())
    {
        return false;
    }
    
        if(res[0][0]==password&&res[0][1]==email)
        {
             clients[fd].logged_in = true;
              clients[fd].username = name;
             name_to_fd[name] = fd;
            return true;
        }
        else if(res[0][0]==password)
        {
            send_message(fd,"邮箱错误\n");
            return false;
        }
        else if(res[0][1]==email)
        {
            send_message(fd,"密码错误\n");
            return false;
        }
        else
        {send_message(fd,"邮箱密码错误\n");
        return false;
        }
}

void findpassword1(int fd,const string&name,const string&email,const string&code,const string&password)
{
    if(!user_exists1(name))
    {
        send_message(fd,"用户不存在,重置密码失败\n");
        return;
    }
   string sql1="SELECT email FROM users WHERE username= ? ";
   auto it1=excute_select(sql1,{name});
   if(it1.empty()||it1[0][0]!=email)
   {
    send_message(fd,"邮箱错误\n");
    return;
   }
    if(!verify_captcha(fd,email,code))
    {
        return;
    }
    string sql="UPDATE users SET password_hash= ? WHERE username= ? ";
    auto it=excute_updata(sql,{password,name});
    if(it==1)
    {
        send_message(fd,"重置密码成功\n");
        return;
    }
    send_message(fd,"重置密码失败\n");
    return;
}

bool authenticate1(int ufd, const string& username, const string& password_hash, const string& email, const string& code) {
    // 1. 验证密码
    string key = "user:" + username;
    redisReply* reply = (redisReply*)redisCommand(redis_conn, "HGET %s password", key.c_str());
    if (!reply || reply->type != REDIS_REPLY_STRING) {
        if (reply) freeReplyObject(reply);
        return false;
    }
    string stored = reply->str;
    freeReplyObject(reply);
    if (stored != password_hash) {
        return false;   // 密码错误
    }

    // 2. 密码正确后，验证邮箱和验证码（如果启用）
    // 如果不需要邮箱验证，可以跳过这部分
    if (!email.empty() && !code.empty()) {
        if (!is_email1(username,email)) {
            // 可发送错误消息（由调用方处理）
            return false;
        }
        if (!verify_captcha(ufd, email, code)) {
            // verify_captcha 内部会发送错误消息
            return false;
        }
    }
    return true;
}

void findpassword2(int ufd,const string&name,const string&email,const string&code,const string&password)
{
    if(!is_email1(name,email))
    {
        send_message(ufd,"邮箱匹配错误\n");
        return;
    }
    if(verify_captcha(ufd,email,code))
    {
        string key1="user:"+name;
       redisReply*reply2=(redisReply*)redisCommand(redis_conn,"HSET %s password %s",key1.c_str(),password.c_str());
       if(!reply2||reply2->type!=REDIS_REPLY_INTEGER)
       {
        send_message(ufd,"设置新密码失败\n");
        if(reply2)
        {
            freeReplyObject(reply2);
        }
        return;
       }
       send_message(ufd,"设置新密码成功,请重新登录\n");
       freeReplyObject(reply2);

    }
    else
    {
        return;
    }
    return;
}
void set_online(const string& username) 
{
    string key = "online:" + username;
    redisCommand(redis_conn, "SET %s 1 EX 60", key.c_str());
}

bool is_online(const string& username) 
{
    string key = "online:" + username;
    redisReply* reply = (redisReply*)redisCommand(redis_conn, "EXISTS %s", key.c_str());
    if (reply == nullptr) return false;
    bool online = (reply->type == REDIS_REPLY_INTEGER && reply->integer == 1);
    freeReplyObject(reply);
    return online;
}

void refresh_online(const string& username) {
    if (!username.empty())
     {
        string key = "online:" + username;
        redisCommand(redis_conn, "EXPIRE %s 60", key.c_str());
    }
}

void xitongbobao(const string&name,const string&msg)
{
    auto it=name_to_fd.find(name);
    if(it!=name_to_fd.end())
    {
        send_message(it->second,msg);
        return;
    }
    else
    {
        string key="offline:"+name;
        redisCommand(redis_conn,"RPUSH %s %s",key.c_str(),msg.c_str());
        return;
    }
}

bool is_friend(const string& user, const string& target)
 {
    string key = "friends:" + user;
    redisReply* reply = (redisReply*)redisCommand(redis_conn, "SISMEMBER %s %s", key.c_str(), target.c_str());
    if (reply == nullptr || reply->type != REDIS_REPLY_INTEGER) 
    {
        if (reply) freeReplyObject(reply);
        return false;
    }
    bool res = (reply->integer == 1);
    freeReplyObject(reply);
    return res;
}

void get_hisory(int ufd,const string&target)
{
    if(history_db==nullptr)
    {
        cerr<<"历史数据未初始化"<<endl;
        return;
    }
    if(clients[ufd].logged_in==false)
    {
        send_message(ufd,"先登录\n");
        return;
    }
    bool firend=true;
    if(is_friend(clients[ufd].username,target)==false)
    {
        firend=false;
        string key="user:"+clients[ufd].username+":groups:";
        redisReply*reply1=(redisReply*)redisCommand(redis_conn,"SISMEMBER %s %s",key.c_str(),target.c_str());
        if(!reply1||reply1->type!=REDIS_REPLY_INTEGER||reply1->integer==0)
        {
            send_message(ufd,"不是好友也不是群成员无法查询历史记录\n");
            return;
        }
    }

  leveldb::ReadOptions readoption;
  string value="history:";
  if(firend)
  {
    value+=(clients[ufd].username<target)?clients[ufd].username+":"+target+":":target+":"+clients[ufd].username+":";
  }
  else
  {
    value+="group:"+target+":";
  }
  leveldb::Iterator*it=history_db->NewIterator(readoption);
  it->Seek(value);
  vector<string>msg;
  while(it->Valid()&&it->key().starts_with(value))
  {
    string content=it->value().ToString()+"\n";
    msg.push_back(content);
    it->Next();
  }
  if(!it->status().ok())
  {
    cerr<<"迭代器错误"<<it->status().ToString()<<endl;
    delete it;
    return;
  }
  delete it;
  if(msg.empty())
  {
    send_message(ufd,"没有聊天记录\n");
    return;
  }
  if(msg.size()>20)
  {
    msg.erase(msg.begin(),msg.begin()+(msg.size()-20));
  }
  reverse(msg.begin(),msg.end());
  send_message(ufd,"近"+to_string(msg.size())+"条聊天记录\n");
  for(size_t i=0;i<msg.size();i++)
  {
    send_message(ufd,msg[i]);
  }
  send_message(ufd,"聊天记录加载完毕\n");
  return;
}


void addfirends(int fd,const string &target)
{
    Client&c=clients[fd];
   if(clients[fd].logged_in==false)
   {
    send_message(fd,"先登录\n");
   }
   if (target == c.username)
     { 
        send_message(fd, "不能添加自己\n");
         return; 
    }
    if (!user_exists1(target))
     {
         send_message(fd, "用户不存在\n");
          return;
     }
     if(is_friend(c.username,target))
     {
        send_message(fd,"已经是好友\n");
        return;
     }
     string key1="haoyoushenqing:"+clients[fd].username;
     redisReply*reply1=(redisReply*)redisCommand(redis_conn,"SISMEMBER %s %s",key1.c_str(),target.c_str());
     if (reply1 && reply1->type == REDIS_REPLY_INTEGER && reply1->integer == 1)
{
    send_message(fd, "对方已经发送了申请\n");
    freeReplyObject(reply1);
    return;
}
     freeReplyObject(reply1);
     string key2="haoyoushenqing:"+target;
     redisReply*reply2=(redisReply*)redisCommand(redis_conn,"SADD %s %s",key2.c_str(),clients[fd].username.c_str());
    if (reply2 && reply2->type == REDIS_REPLY_INTEGER)
     {
        send_message(fd, (reply2->integer == 1) ? "发送好友申请成功\n" : "网不好");
    } 
    else 
    {
        send_message(fd, "发送失败\n");
    }
    if (reply2) 
    freeReplyObject(reply2);
     string msg=clients[fd].username+"发来好友申请,用'/list_request'查看,并回复'/accept name'或者'/reject name'"+'\n';
     xitongbobao(target,msg);
     return;
}

void list_firends_requests(int ufd)
{
     if(clients[ufd].logged_in==false)
     {
        send_message(ufd,"先登录\n");
        return;
     }
     string key1="haoyoushenqing:"+clients[ufd].username;
     redisReply*reply1=(redisReply*)redisCommand(redis_conn,"SMEMBERS %s",key1.c_str());
     if(reply1==nullptr)
     {
     
       send_message(ufd,"网不好\n");
       return;
    }
    if(reply1->type==REDIS_REPLY_ARRAY)
    {
        if(reply1->elements==0)
        {
            send_message(ufd,"没有好友申请\n");
            freeReplyObject(reply1);
            return;
        }
        for(size_t i=0;i<reply1->elements;i++)
        {
            string msg1="请求添加你为好友";
            string msg=reply1->element[i]->str+msg1+'\n';
            send_message(ufd,msg);
        }
    }
    if(reply1)
    {
        freeReplyObject(reply1);
    }
        return;
}

void accept_friends(int ufd, const string& name) {
    if (!clients[ufd].logged_in) {
        send_message(ufd, "请先登录\n");
        return;
    }

    string current_user = clients[ufd].username;
    string request_key = "haoyoushenqing:" + current_user;

    // 1. 验证申请是否存在
    redisReply* reply1 = (redisReply*)redisCommand(redis_conn, "SISMEMBER %s %s", request_key.c_str(), name.c_str());
    if (!reply1 || reply1->type != REDIS_REPLY_INTEGER || reply1->integer != 1) {
        send_message(ufd, "没有来自 " + name + " 的好友申请\n");
        if (reply1) freeReplyObject(reply1);
        return;
    }
    freeReplyObject(reply1);

    // 2. 从申请列表移除
    redisReply* reply2 = (redisReply*)redisCommand(redis_conn, "SREM %s %s", request_key.c_str(), name.c_str());
    if (!reply2 || reply2->type != REDIS_REPLY_INTEGER || reply2->integer != 1) {
        send_message(ufd, "移除申请失败\n");
        if (reply2) freeReplyObject(reply2);
        return;
    }
    freeReplyObject(reply2);

    // 3. 双向添加好友
    string friends_self = "friends:" + current_user;
    string friends_target = "friends:" + name;

    redisReply* reply3 = (redisReply*)redisCommand(redis_conn, "SADD %s %s", friends_self.c_str(), name.c_str());
    if (!reply3 || reply3->type != REDIS_REPLY_INTEGER) {
        send_message(ufd, "添加好友失败（本地列表）\n");
        if (reply3) freeReplyObject(reply3);
        // 回滚：恢复申请（因为已经删除了）
        redisCommand(redis_conn, "SADD %s %s", request_key.c_str(), name.c_str());
        return;
    }
    freeReplyObject(reply3);

    redisReply* reply4 = (redisReply*)redisCommand(redis_conn, "SADD %s %s", friends_target.c_str(), current_user.c_str());
    if (!reply4 || reply4->type != REDIS_REPLY_INTEGER || reply4->integer != 1) 
    {
        send_message(ufd, "添加好友失败（对方列表）\n");
        if (reply4) freeReplyObject(reply4);
        // 回滚：从当前用户的好友列表中移除对方
        redisCommand(redis_conn, "SREM %s %s", friends_self.c_str(), name.c_str());
        // 恢复申请
        redisCommand(redis_conn, "SADD %s %s", request_key.c_str(), name.c_str());
        return;
    }
    freeReplyObject(reply4);

    send_message(ufd, "已成功添加 " + name + " 为好友\n");
    xitongbobao(name, current_user + " 已同意您的好友申请\n");
}

void reject_friends(int ufd, const string&name)
{
    if(clients[ufd].logged_in==false)
    {
        send_message(ufd,"先登录\n");
           return;
    }
    string key1="haoyoushenqing:"+clients[ufd].username;
    redisReply*reply1=(redisReply*)redisCommand(redis_conn,"SISMEMBER %s %s",key1.c_str(),name.c_str());
    if(reply1==nullptr)
    {
        send_message(ufd,"网不好\n");
        return;
    }
   if(reply1->type!=REDIS_REPLY_INTEGER||reply1->integer!=1)
   {
    send_message(ufd,"没有这条好友申请\n");
    freeReplyObject(reply1);
    return;
   }
   freeReplyObject(reply1);
   redisReply*reply2=(redisReply*)redisCommand(redis_conn,"SREM %s %s",key1.c_str(),name.c_str());
   if(reply2==nullptr)
   {
    send_message(ufd,"网不好\n");
    return;
   }
   if(reply2->type!=REDIS_REPLY_INTEGER||reply2->integer!=1)
   {
    send_message(ufd,"拒绝"+name+"好友申请失败\n");
   }
   else
   {
    send_message(ufd,"拒绝"+name+"好友申请成功\n");
    xitongbobao(name,clients[ufd].username+"拒绝你的好友申请\n");
   }
   freeReplyObject(reply2);
   return;
}
void del_friend(int fd, const string& target) 
{
    Client& c = clients[fd];
    if (!c.logged_in) 
    { 
        send_message(fd, "请先登录\n");
         return; 
    }
    string key = "friends:" + c.username;
    redisReply* reply = (redisReply*)redisCommand(redis_conn, "SREM %s %s", key.c_str(), target.c_str());
   
    if(!reply||reply->type!=REDIS_REPLY_INTEGER||reply->integer!=1)
    {
        if(reply->integer==0)
        {
            send_message(fd,"你们不是好友\n");
        }
        else send_message(fd,"删除失败\n");
        if(reply)
        {
            freeReplyObject(reply);
        }
        return;
    }
    freeReplyObject(reply);
      string key1="friends:"+target;
       redisReply*reply1=(redisReply*)redisCommand(redis_conn,"SREM %s %s",key1.c_str(),c.username.c_str());
    if(!reply1||reply1->type!=REDIS_REPLY_INTEGER||reply1->integer!=1)
    {
        send_message(fd,"删除失败\n");
        if(reply1)
        {
            freeReplyObject(reply1);
        }
        redisCommand(redis_conn,"SADD %s %s",key.c_str(),target.c_str());
        return;
    }
    freeReplyObject(reply1);
    send_message(fd,"删除成功\n");
    string msg=c.username+"删除了你\n";
    xitongbobao(target,msg);
}

void list_friends(int fd) 
{
    Client& c = clients[fd];
    if (!c.logged_in) 
    {
         send_message(fd, "请先登录\n");
         return; 
     }
    string key = "friends:" + c.username;
    redisReply* reply = (redisReply*)redisCommand(redis_conn, "SMEMBERS %s", key.c_str());
    if (reply && reply->type == REDIS_REPLY_ARRAY)
     {
        string res = "好友: ";
        for (size_t i = 0; i < reply->elements; ++i) 
        {
            if (i > 0) res += ", ";
            res += reply->element[i]->str;
            if(is_online(string(reply->element[i]->str)))
            {
                res+=" [在线]";
            }
            else
            {
                res+=" [离线]";
            }
        }
        res += "\n";
        send_message(fd, res);
    } 
    else
     {
        send_message(fd, "获取好友列表失败\n");
    }
    if (reply) 
    freeReplyObject(reply);
}

void pingbi(int ufd,const string&name)
{
    if(clients[ufd].logged_in==false)
    {
        send_message(ufd,"先登录\n");
        return;
    }
    if(!is_friend(clients[ufd].username,name))
    {
       send_message(ufd,"你们不是好友\n");
       return;
    }
    string key1="blocklist:"+clients[ufd].username;
    redisReply*reply2=(redisReply*)redisCommand(redis_conn,"SISMEMBER %s %s",key1.c_str(),name.c_str());
    if(reply2==nullptr)
    {
        send_message(ufd,"网不好\n");
        return;
    }
    if(reply2->type!=REDIS_REPLY_INTEGER)
    {
        send_message(ufd,"系统错误\n");
        freeReplyObject(reply2);
        return;
    }
    if(reply2->integer==1)
    {
        send_message(ufd,"不可重复屏蔽\n");
        freeReplyObject(reply2);
        return;
    }
    freeReplyObject(reply2);
    redisReply*reply1=(redisReply*)redisCommand(redis_conn,"SADD %s %s",key1.c_str(),name.c_str());
    if(!reply1||reply1->type!=REDIS_REPLY_INTEGER||reply1->integer!=1)
    {
        send_message(ufd,"屏蔽失败\n");
        if(reply1)
        {
            freeReplyObject(reply1);
        }
        return;
    }
    else
    {
        send_message(ufd,"屏蔽"+name+"成功\n");
        freeReplyObject(reply1);
        return;
    }
}

void jiechupinbi(int ufd,const string&name)
{
    if(clients[ufd].logged_in==false)
    {
        send_message(ufd,"先登录\n");
        return;
    }
    string key1="blocklist:"+clients[ufd].username;
    redisReply*reply1=(redisReply*)redisCommand(redis_conn,"SISMEMBER %s %s",key1.c_str(),name.c_str());
    if(reply1==nullptr)
    {
        send_message(ufd,"网不好\n");
        return;
    }
    if(reply1->type!=REDIS_REPLY_INTEGER||reply1->integer!=1)
    {
        send_message(ufd,"你没有屏蔽他\n");
        freeReplyObject(reply1);
        return;
    }
    freeReplyObject(reply1);
    redisReply*reply2=(redisReply*)redisCommand(redis_conn,"SREM %s %s",key1.c_str(),name.c_str());
    if(!reply2||reply2->type!=REDIS_REPLY_INTEGER||reply2->integer!=1)
    {
        send_message(ufd,"解除屏蔽失败\n");
        if(reply2)
        {
            freeReplyObject(reply2);
        }
        return;
    }
    send_message(ufd,"解除屏蔽成功\n");
    freeReplyObject(reply2);
    return;

}
void siliao(int sender_fd, const string& target_name, const string& content) 
{
    Client& c = clients[sender_fd];
    if (!c.logged_in) 
    {
         send_message(sender_fd, "请先登录\n");
          return; 
    }
    if (c.username == target_name) 
    {
         send_message(sender_fd, "不能和自己私聊\n");
          return;
     }
    if (content.empty())
     {
         send_message(sender_fd, "消息不能为空\n");
          return;
     }
    if (!user_exists1(target_name))
     { 
        send_message(sender_fd, "用户不存在\n");
         return;
     }
    if (!is_friend(c.username, target_name)) 
    { 
        send_message(sender_fd, "不是好友，不能私聊\n");
         return; 
    }
string block="blocklist:"+target_name;
     redisReply*reply=(redisReply*)redisCommand(redis_conn,"SISMEMBER %s %s",block.c_str(),clients[sender_fd].username.c_str());
     if(reply==nullptr)
     {
        send_message(sender_fd,"网不好\n");
        return;
     }
     if(reply->type==REDIS_REPLY_INTEGER&&reply->integer==1)
     {
        send_message(sender_fd,"你被"+target_name+"屏蔽\n");
        freeReplyObject(reply);
        return;
     }
     freeReplyObject(reply);
    string msg = "[私聊]" + c.username + ":" + content + "\n";
    auto it = name_to_fd.find(target_name);
    if (it != name_to_fd.end()) 
    {
            send_message(it->second, msg);
            send_message(sender_fd, "发送完成\n");
           string place=(c.username<target_name)?c.username+":"+target_name:target_name+":"+c.username;
           store_history(c.username,place,content);
          
    } 
    else
     {
        send_message(sender_fd, "对方离线，已存储\n");
        string key = "offline:" + target_name;
        redisCommand(redis_conn, "RPUSH %s %s", key.c_str(), msg.c_str());
        string place=(c.username<target_name)?c.username+":"+target_name:target_name+":"+c.username;
           store_history(c.username,place,content);
    }
}

void chuangqun(int ufd, const string& qun)
 {
    if (!clients[ufd].logged_in) 
    { 
        send_message(ufd, "请先登录\n");
         return;
     }
    if (qun.empty())
     {
         send_message(ufd, "群名不能为空\n");
          return; 
    }
    string group_key = "group:" + qun;
    string members_key = group_key + ":members:";
    string user_groups_key = "user:" + clients[ufd].username + ":groups:";
    redisReply* reply = (redisReply*)redisCommand(redis_conn, "EXISTS %s", group_key.c_str());
    if (reply == nullptr) 
    { 
        send_message(ufd, "网络错误\n"); 
        return;
     }
    if (reply->type == REDIS_REPLY_INTEGER && reply->integer == 1) 
    {
        send_message(ufd, "群名已存在\n");
        freeReplyObject(reply);
        return;
    }
    freeReplyObject(reply);
    reply = (redisReply*)redisCommand(redis_conn, "HSET %s owner %s", group_key.c_str(), clients[ufd].username.c_str());
    if (reply == nullptr || reply->type != REDIS_REPLY_INTEGER || reply->integer != 1) 
    {
        send_message(ufd, "创建群失败\n");
        if (reply) freeReplyObject(reply);
        return;
    }
    freeReplyObject(reply);
    reply = (redisReply*)redisCommand(redis_conn, "SADD %s %s", members_key.c_str(), clients[ufd].username.c_str());
    if (reply == nullptr || reply->type != REDIS_REPLY_INTEGER) 
    {
        send_message(ufd, "加入群成员失败\n");
        if (reply) freeReplyObject(reply);
        return;
    }
    freeReplyObject(reply);
    reply = (redisReply*)redisCommand(redis_conn, "SADD %s %s", user_groups_key.c_str(), qun.c_str());
    if (reply == nullptr || reply->type != REDIS_REPLY_INTEGER) 
    {
        send_message(ufd, "更新用户群列表失败\n");
        if (reply) 
        {freeReplyObject(reply);}
        return;
    }
    freeReplyObject(reply);
    send_message(ufd, "群创建成功\n");
}
void guanli(int ufd,const string&qun1,const string&name)
{
     string qun = trim(qun1);
      cout << "guanli: qun=[" << qun << "], len=" << qun.size() << ", name=[" << name << "]" << endl;
    if(clients[ufd].logged_in==false)
    {
        send_message(ufd,"先登陆\n");
        return;
    }
     string key = "group:" + qun;
    redisReply* reply = (redisReply*)redisCommand(redis_conn, "HGET %s owner", key.c_str());
    if (!reply) {
        send_message(ufd, "网络错误\n");
        return;
    }
    // 不提前检查类型，直接与 jiesan 一致的处理方式
    if (reply->type != REDIS_REPLY_STRING || string(reply->str) != clients[ufd].username) {
        send_message(ufd, "不是群主没有权限添加管理员\n");
        freeReplyObject(reply);
        return;
    }
    freeReplyObject(reply);
    string key3="group:"+qun+":members:";
    redisReply*reply3=(redisReply*)redisCommand(redis_conn,"SISMEMBER %s %s",key3.c_str(),name.c_str());
    if(reply3==nullptr)
    {
        send_message(ufd,"网不好\n");
        return;
    }
    if(reply3->type!=REDIS_REPLY_INTEGER||reply3->integer!=1)
    {
        send_message(ufd,"该用户不是群内成员\n");
        freeReplyObject(reply3);
        return;
    }
    freeReplyObject(reply3);
    string key2="group:"+qun+":guanli:";
    redisReply*reply2=(redisReply*)redisCommand(redis_conn,"SADD %s %s",key2.c_str(),name.c_str());
    if(reply2==nullptr)
    {
        send_message(ufd,"网不好\n");
        return;
    }
   if(reply2->type==REDIS_REPLY_INTEGER)
   {
    if(reply2->integer==1)
    {
        send_message(ufd,"添加管理员成功\n");
    }
    else if(reply2->integer==0)
    {
        send_message(ufd,"已经是管理员\n");
        freeReplyObject(reply2);
        return;
    }
    else
    {
        send_message(ufd,"添加管理员失败\n");
        freeReplyObject(reply2);
        return;
    }
   }
   else
    {
        send_message(ufd,"添加管理员失败\n");
        freeReplyObject(reply2);
        return;
    }
    freeReplyObject(reply2);
    string msg=clients[ufd].username+"将你设置为"+qun+"管理员"+'\n';
    auto it=name_to_fd.find(name);
    if(it!=name_to_fd.end())
    {
        send_message(it->second,msg);
    }
    else
    {
       string key4="offline:"+name;
       redisCommand(redis_conn,"RPUSH %s %s",key4.c_str(),msg.c_str());
    }
    return;
}
void shanguan(int ufd,const string&qun,const string &name)
{
    if(clients[ufd].logged_in==false)
    {
        send_message(ufd,"先登陆\n");
        return;
    }
    string key="group:"+qun;
    redisReply*reply=(redisReply*)redisCommand(redis_conn,"HGET %s owner",key.c_str());
    if(reply==nullptr)
    {
        send_message(ufd,"网不好\n");
        return;
    }
    if(reply->type!=REDIS_REPLY_STRING||string(reply->str)!=clients[ufd].username)
    {
        send_message(ufd,"你不是群主无法删除管理员\n");
        freeReplyObject(reply);
        return;
    }
    freeReplyObject(reply);
    string key2="group:"+qun+":guanli:";
    redisReply*reply2=(redisReply*)redisCommand(redis_conn,"SISMEMBER %s %s",key2.c_str(),name.c_str());
    if(reply2==nullptr)
    {
        send_message(ufd,"网不好\n");
        return;
    }
    if(reply2->type!=REDIS_REPLY_INTEGER||reply2->integer!=1)
    {
        send_message(ufd,"该用户不是管理员\n");
        freeReplyObject(reply2);
        return;
    }
    freeReplyObject(reply2);
        redisReply*reply3=(redisReply*)redisCommand(redis_conn,"SREM %s %s",key2.c_str(),name.c_str());
    if(reply3==nullptr)
    {
        send_message(ufd,"网不好\n");
        return;
    }
    if(reply3->type!=REDIS_REPLY_INTEGER||reply3->integer!=1)
    {
        send_message(ufd,"删除管理员失败\n");
        freeReplyObject(reply3);
        return;
    }
    freeReplyObject(reply3);
    send_message(ufd,"删除管理员成功\n");
    string msg=clients[ufd].username+"删除了你在群"+qun+"的管理员身份\n";
   xitongbobao(name,msg);
   return;
}


void add_group(int ufd, const string& qun) {
    // 1. 登录检查
    if (!clients[ufd].logged_in) {
        send_message(ufd, "请先登录\n");
        return;
    }

    // 2. 检查群是否存在
    string group_key = "group:" + qun;
    redisReply* reply = (redisReply*)redisCommand(redis_conn, "EXISTS %s", group_key.c_str());
    if (!reply) {
        send_message(ufd, "网络错误\n");
        return;
    }
    if (reply->type != REDIS_REPLY_INTEGER || reply->integer == 0) {
        send_message(ufd, "群聊不存在\n");
        freeReplyObject(reply);
        return;
    }
    freeReplyObject(reply);

    // 3. 检查是否已是群成员
    string members_key = group_key + ":members:";
    reply = (redisReply*)redisCommand(redis_conn, "SISMEMBER %s %s", members_key.c_str(), clients[ufd].username.c_str());
    if (!reply) {
        send_message(ufd, "网络错误\n");
        return;
    }
    if (reply->type != REDIS_REPLY_INTEGER) {
        send_message(ufd, "系统错误\n");
        freeReplyObject(reply);
        return;
    }
    if (reply->integer == 1) {
        send_message(ufd, "您已是群成员\n");
        freeReplyObject(reply);
        return;
    }
    freeReplyObject(reply);

    // 4. 检查是否已发送过申请
    string requests_key = "jiaqunshengqing:" + qun;
    reply = (redisReply*)redisCommand(redis_conn, "SISMEMBER %s %s", requests_key.c_str(), clients[ufd].username.c_str());
    if (!reply) {
        send_message(ufd, "网络错误\n");
        return;
    }
    if (reply->type != REDIS_REPLY_INTEGER) {
        send_message(ufd, "系统错误\n");
        freeReplyObject(reply);
        return;
    }
    if (reply->integer == 1) {
        send_message(ufd, "您已发送过加群申请，请等待审批\n");
        freeReplyObject(reply);
        return;
    }
    freeReplyObject(reply);

    // 5. 发送申请
    redisReply* reply2 = (redisReply*)redisCommand(redis_conn, "SADD %s %s", requests_key.c_str(), clients[ufd].username.c_str());
    if (!reply2) {
        send_message(ufd, "网络错误\n");
        return;
    }
    if (reply2->type != REDIS_REPLY_INTEGER || reply2->integer != 1) {
        send_message(ufd, "加群申请发送失败\n");
        freeReplyObject(reply2);
        return;
    }
    freeReplyObject(reply2);  // 释放成功后的 reply2

    // 6. 给申请者确认反馈
    send_message(ufd, "加群申请已发送，等待群主或管理员审批\n");

    // 7. 通知群主
    reply = (redisReply*)redisCommand(redis_conn, "HGET %s owner", group_key.c_str());
    if (reply && reply->type == REDIS_REPLY_STRING) {
        string owner = reply->str;
        string notify_msg = clients[ufd].username + " 申请加入群 " + qun +
                            "，请使用 /list_group " + qun + " 查看，并回复 /approve " + qun + " <用户名> 或 /rejectgroup " + qun + " <用户名>\n";
        xitongbobao(owner, notify_msg);
        freeReplyObject(reply);
    } else {
        if (reply) freeReplyObject(reply);
    }

    // 8. 通知管理员（不包括群主）
    string admins_key = group_key + ":guanli:";
    reply = (redisReply*)redisCommand(redis_conn, "SMEMBERS %s", admins_key.c_str());
    if (reply && reply->type == REDIS_REPLY_ARRAY) {
        string notify_msg = clients[ufd].username + " 申请加入群 " + qun +
                            "，请使用 /list_group " + qun + " 查看，并回复 /approve " + qun + " <用户名> 或 /rejectgroup " + qun + " <用户名>\n";
        for (size_t i = 0; i < reply->elements; ++i) {
            string admin = reply->element[i]->str;
            // 避免重复通知群主（群主已经在上面通知过）
            if (admin != clients[ufd].username) {
                xitongbobao(admin, notify_msg);
            }
        }
        freeReplyObject(reply);
    } else {
        if (reply) freeReplyObject(reply);
        // 没有管理员是正常情况，不报错
    }
}

void list_group(int ufd,const string&group)
{
    if(clients[ufd].logged_in==false)
    {
        send_message(ufd,"先登录\n");
        return;
    }
     // 2. 检查群是否存在
    string group_key = "group:" + group;
    redisReply* reply = (redisReply*)redisCommand(redis_conn, "EXISTS %s", group_key.c_str());
    if (!reply) {
        send_message(ufd, "网络错误\n");
        return;
    }
    if (reply->type != REDIS_REPLY_INTEGER || reply->integer == 0) 
    {
        send_message(ufd, "群聊不存在\n");
        freeReplyObject(reply);
        return;
    }
    freeReplyObject(reply);

    bool a=false;
    string key1="group:"+group;
    redisReply*reply1=(redisReply*)redisCommand(redis_conn,"HGET %s owner",key1.c_str());
    if(reply1==nullptr)
    {
        send_message(ufd,"网不好\n");
        return;
    }
    if(reply1->type!=REDIS_REPLY_STRING)
    {
        send_message(ufd,"系统错误\n");
        freeReplyObject(reply1);
        return;
    }
    if(string(reply1->str)==clients[ufd].username)
    {
        a=true;
    }
    freeReplyObject(reply1);
    string key2="group:"+group+":guanli:";
    redisReply*reply2=(redisReply*)redisCommand(redis_conn,"SMEMBERS %s",key2.c_str());
     if(!reply2)
     {
        send_message(ufd,"网不好\n");
        return;
     }
     if(reply2->type==REDIS_REPLY_ARRAY)
     {
        for(size_t i=0;i<reply2->elements;i++)
        {
            if(clients[ufd].username==reply2->element[i]->str)
            {
                a=true;
                break;
            }
        }
     }
     freeReplyObject(reply2);
     if(!a)
     {
        send_message(ufd,"无查看群申请权限\n");
        return;
     }
     string key3="jiaqunshengqing:"+group;
     redisReply*reply3=(redisReply*)redisCommand(redis_conn,"SMEMBERS %s",key3.c_str());
     if(reply3==nullptr)
     {
        send_message(ufd,"网不好\n");
        return;
     }
     if(reply3->type!=REDIS_REPLY_ARRAY)
     {
        send_message(ufd,"系统错误\n");
        freeReplyObject(reply3);
        return;
     }
     if(reply3->elements==0)
     {
        send_message(ufd,"没有加群申请\n");
        freeReplyObject(reply3);
        return;
     }

     for(size_t i=0;i<reply3->elements;i++)
     {
      send_message(ufd,string(reply3->element[i]->str)+"申请加入群聊"+group+"\n");
     }
     freeReplyObject(reply3);
     return;
}

void accept_group(int ufd, const string& group, const string& name) {
    if (!clients[ufd].logged_in) {
        send_message(ufd, "请先登录\n");
        return;
    }

    // 1. 检查群是否存在
    string group_key = "group:" + group;
    redisReply* reply = (redisReply*)redisCommand(redis_conn, "EXISTS %s", group_key.c_str());
    if (!reply) {
        send_message(ufd, "网络错误\n");
        return;
    }
    if (reply->type != REDIS_REPLY_INTEGER || reply->integer == 0) {
        send_message(ufd, "群聊不存在\n");
        freeReplyObject(reply);
        return;
    }
    freeReplyObject(reply);

    // 2. 检查申请是否存在
    string requests_key = "jiaqunshengqing:" + group;
    reply = (redisReply*)redisCommand(redis_conn, "SISMEMBER %s %s", requests_key.c_str(), name.c_str());
    if (!reply) {
        send_message(ufd, "网络错误\n");
        return;
    }
    if (reply->type != REDIS_REPLY_INTEGER) {
        send_message(ufd, "系统错误\n");
        freeReplyObject(reply);
        return;
    }
    if (reply->integer != 1) {
        send_message(ufd, "该用户未申请加入本群\n");
        freeReplyObject(reply);
        return;
    }
    freeReplyObject(reply);

    // 3. 权限检查（群主或管理员）
    bool has_permission = false;
    reply = (redisReply*)redisCommand(redis_conn, "HGET %s owner", group_key.c_str());
    if (!reply) {
        send_message(ufd, "网络错误\n");
        return;
    }
    if (reply->type == REDIS_REPLY_STRING && string(reply->str) == clients[ufd].username) {
        has_permission = true;
    }
    freeReplyObject(reply);

    if (!has_permission) {
        string admins_key = group_key + ":guanli:";
        reply = (redisReply*)redisCommand(redis_conn, "SMEMBERS %s", admins_key.c_str());
        if (!reply) {
            send_message(ufd, "网络错误\n");
            return;
        }
        if (reply->type == REDIS_REPLY_ARRAY) {
            for (size_t i = 0; i < reply->elements; ++i) {
                if (string(reply->element[i]->str) == clients[ufd].username) {
                    has_permission = true;
                    break;
                }
            }
        }
        freeReplyObject(reply);
    }

    if (!has_permission) {
        send_message(ufd, "您没有权限批准入群\n");
        return;
    }

    // 4. 执行批准操作（不考虑成员已存在）
    string members_key = group_key + ":members:";
    string user_groups_key = "user:" + name + ":groups:";

    // 4a. 添加群成员
    redisReply* r1 = (redisReply*)redisCommand(redis_conn, "SADD %s %s", members_key.c_str(), name.c_str());
    if (!r1 || r1->type != REDIS_REPLY_INTEGER) {
        send_message(ufd, "批准失败（添加群成员失败）\n");
        if (r1) freeReplyObject(r1);
        return;
    }
    bool ok1 = (r1->integer >= 0);  // 0 表示已存在，也算成功
    freeReplyObject(r1);

    // 4b. 添加用户群列表
    redisReply* r2 = (redisReply*)redisCommand(redis_conn, "SADD %s %s", user_groups_key.c_str(), group.c_str());
    if (!r2 || r2->type != REDIS_REPLY_INTEGER) {
        // 回滚：移除群成员
        redisCommand(redis_conn, "SREM %s %s", members_key.c_str(), name.c_str());
        send_message(ufd, "批准失败（更新用户群列表失败）\n");
        if (r2) freeReplyObject(r2);
        return;
    }
    bool ok2 = (r2->integer >= 0);
    freeReplyObject(r2);

    if (ok1 && ok2) {
        // 删除申请
        redisCommand(redis_conn, "SREM %s %s", requests_key.c_str(), name.c_str());
        send_message(ufd, "已成功批准 " + name + " 加入群 " + group + "\n");
        xitongbobao(name, clients[ufd].username + " 批准您加入群 " + group + "\n");
    } else {
        // 理论上不会走到这里，但保留
        send_message(ufd, "批准失败，请重试\n");
    }
}

void reject_group(int ufd,const string&group,const string&name)
{
      if (!clients[ufd].logged_in) {
        send_message(ufd, "请先登录\n");
        return;
    }

    // 1. 检查群是否存在
    string group_key = "group:" + group;
    redisReply* reply = (redisReply*)redisCommand(redis_conn, "EXISTS %s", group_key.c_str());
    if (!reply) {
        send_message(ufd, "网络错误\n");
        return;
    }
    if (reply->type != REDIS_REPLY_INTEGER || reply->integer == 0) {
        send_message(ufd, "群聊不存在\n");
        freeReplyObject(reply);
        return;
    }
    freeReplyObject(reply);

    // 2. 检查申请是否存在
    string requests_key = "jiaqunshengqing:" + group;
    reply = (redisReply*)redisCommand(redis_conn, "SISMEMBER %s %s", requests_key.c_str(), name.c_str());
    if (!reply) {
        send_message(ufd, "网络错误\n");
        return;
    }
    if (reply->type != REDIS_REPLY_INTEGER) {
        send_message(ufd, "系统错误\n");
        freeReplyObject(reply);
        return;
    }
    if (reply->integer != 1) {
        send_message(ufd, "该用户未申请加入本群\n");
        freeReplyObject(reply);
        return;
    }
    freeReplyObject(reply);

    // 3. 权限检查（群主或管理员）
    bool has_permission = false;
    reply = (redisReply*)redisCommand(redis_conn, "HGET %s owner", group_key.c_str());
    if (!reply) {
        send_message(ufd, "网络错误\n");
        return;
    }
    if (reply->type == REDIS_REPLY_STRING && string(reply->str) == clients[ufd].username) {
        has_permission = true;
    }
    freeReplyObject(reply);

    if (!has_permission) {
        string admins_key = group_key + ":guanli:";
        reply = (redisReply*)redisCommand(redis_conn, "SMEMBERS %s", admins_key.c_str());
        if (!reply) {
            send_message(ufd, "网络错误\n");
            return;
        }
        if (reply->type == REDIS_REPLY_ARRAY) {
            for (size_t i = 0; i < reply->elements; ++i) {
                if (string(reply->element[i]->str) == clients[ufd].username) {
                    has_permission = true;
                    break;
                }
            }
        }
        freeReplyObject(reply);
    }

    if (!has_permission) {
        send_message(ufd, "您没有权限拒绝入群\n");
        return;
    }
  
     redisReply* del_reply = (redisReply*)redisCommand(redis_conn, "SREM %s %s", requests_key.c_str(), name.c_str());
    if (!del_reply || del_reply->type != REDIS_REPLY_INTEGER || del_reply->integer != 1)
    {
        send_message(ufd, "拒绝失败，请重试\n");
        if (del_reply) freeReplyObject(del_reply);
        return;
    }
    freeReplyObject(del_reply);
      xitongbobao(name,"群聊"+group+"拒绝你的进群申请\n");
      send_message(ufd,"以拒绝"+name+"的申请\n");
    return;
}

void shanchenyuan(int ufd,const string&group,const string&name)
{
    if (!clients[ufd].logged_in) {
        send_message(ufd, "请先登录\n");
        return;
    }

    // 1. 检查群是否存在
    string group_key = "group:" + group;
    redisReply* reply = (redisReply*)redisCommand(redis_conn, "EXISTS %s", group_key.c_str());
    if (!reply) {
        send_message(ufd, "网络错误\n");
        return;
    }
    if (reply->type != REDIS_REPLY_INTEGER || reply->integer == 0) {
        send_message(ufd, "群聊不存在\n");
        freeReplyObject(reply);
        return;
    }
    freeReplyObject(reply);

    // 3. 权限检查（群主或管理员）
    bool has_permission = false;
    reply = (redisReply*)redisCommand(redis_conn, "HGET %s owner", group_key.c_str());
    if (!reply) {
        send_message(ufd, "网络错误\n");
        return;
    }
    if (reply->type == REDIS_REPLY_STRING && string(reply->str) == clients[ufd].username) {
        has_permission = true;
    }
    freeReplyObject(reply);

    if (!has_permission) {
        string admins_key = group_key + ":guanli:";
        reply = (redisReply*)redisCommand(redis_conn, "SMEMBERS %s", admins_key.c_str());
        if (!reply) {
            send_message(ufd, "网络错误\n");
            return;
        }
        if (reply->type == REDIS_REPLY_ARRAY) {
            for (size_t i = 0; i < reply->elements; ++i) {
                if (string(reply->element[i]->str) == clients[ufd].username) {
                    has_permission = true;
                    break;
                }
            }
        }
        freeReplyObject(reply);
    }

    if (!has_permission) {
        send_message(ufd, "您没有权限删除成员\n");
        return;
    }
     
    string key1="group:"+group+":members:";
    redisReply*reply1=(redisReply*)redisCommand(redis_conn,"SISMEMBER %s %s",key1.c_str(),name.c_str());
    if(!reply1)
    {
        send_message(ufd,"网不好\n");
        return;
    }
    if(reply1->type!=REDIS_REPLY_INTEGER)
    {
        send_message(ufd,"系统错误\n");
        freeReplyObject(reply1);
        return;
    }
    if(reply1->integer!=1)
    {
        send_message(ufd,"用户不是群聊成员\n");
        freeReplyObject(reply1);
        return;
    }
    freeReplyObject(reply1);
    redisReply*reply2=(redisReply*)redisCommand(redis_conn,"SREM %s %s",key1.c_str(),name.c_str());
    if(reply2==nullptr)
    {
        send_message(ufd,"网不好\n");
        return;
    }
    if(reply2->type!=REDIS_REPLY_INTEGER)
    {
        send_message(ufd,"系统错误\n");
        freeReplyObject(reply2);
        return;
    }
    if(reply2->integer==1)
    {
        string key3="user:"+name+":groups:";
       redisReply*reply3=(redisReply*)redisCommand(redis_conn,"SREM %s %s",key3.c_str(),group.c_str());
      if(!reply3||reply3->type!=REDIS_REPLY_INTEGER||reply3->integer!=1)
      {
        send_message(ufd,"移除失败\n");
        redisCommand(redis_conn,"SADD %s %s",key1.c_str(),name.c_str());
        if(reply3)
        {
            freeReplyObject(reply3);
        }
        freeReplyObject(reply2);
        return;
      }
      else
       {
        send_message(ufd,"移除成功\n");
        xitongbobao(name,"你被"+group+"移除\n");
       }
        freeReplyObject(reply3);
    }
    freeReplyObject(reply2);
    return;
   
}

void qunliao(int sender_fd, const string& qun, const string& content) 
{
    if (!clients[sender_fd].logged_in) 
    { 
        send_message(sender_fd, "请先登录\n");
         return; 
    }
    if (qun.empty() || content.empty()) 
    { 
        send_message(sender_fd, "群名或消息不能为空\n");
         return; 
    }
    string group_key = "group:" + qun;
    string members_key = group_key + ":members:";
    redisReply* reply = (redisReply*)redisCommand(redis_conn, "EXISTS %s", group_key.c_str());
    if (reply == nullptr) 
    {
         send_message(sender_fd, "网络错误\n");
          return;
     }
    if (reply->type != REDIS_REPLY_INTEGER || reply->integer != 1) 
    {
        send_message(sender_fd, "群不存在\n");
        if (reply) freeReplyObject(reply);
        return;
    }
    freeReplyObject(reply);
    reply = (redisReply*)redisCommand(redis_conn, "SISMEMBER %s %s", members_key.c_str(), clients[sender_fd].username.c_str());
    if (reply == nullptr) 
    {
         send_message(sender_fd, "网络错误\n"); 
         return;
     }
    if (reply->type != REDIS_REPLY_INTEGER || reply->integer != 1)
     {
        send_message(sender_fd, "你不是群成员\n");
        if (reply) freeReplyObject(reply);
        return;
    }
    freeReplyObject(reply);
    string msg = "[群聊 " + qun + "] " + clients[sender_fd].username + ": " + content + "\n";
    reply = (redisReply*)redisCommand(redis_conn, "SMEMBERS %s", members_key.c_str());
    if (reply == nullptr || reply->type != REDIS_REPLY_ARRAY)
     {
        send_message(sender_fd, "获取成员列表失败\n");
        if (reply)
         freeReplyObject(reply);
        return;
    }
    for (size_t i = 0; i < reply->elements; ++i) 
    {
        string member = reply->element[i]->str;
        if (member == clients[sender_fd].username) 
        {continue;}
        auto it = name_to_fd.find(member);
        if (it != name_to_fd.end()) 
        {
            send_message(it->second, msg);
        } 
        else
         {
            string key = "offline:" + member;
            redisCommand(redis_conn, "RPUSH %s %s", key.c_str(), msg.c_str());
        }
    }
    freeReplyObject(reply);
    string place="group:"+qun;
    store_history(clients[sender_fd].username,place,content);
    send_message(sender_fd, "群发完成\n");
}

void chachengyuan(int ufd, const string& qun)
 {
    if (!clients[ufd].logged_in)
     {
         send_message(ufd, "请先登录\n"); 
         return;
     }
    string group_key = "group:" + qun;
    string members_key = group_key + ":members:";
    redisReply* reply = (redisReply*)redisCommand(redis_conn, "EXISTS %s", group_key.c_str());
    if (reply == nullptr)
     { 
        send_message(ufd, "网络错误\n"); 
        return; 
    }
    if (reply->type != REDIS_REPLY_INTEGER || reply->integer != 1)
     {
        send_message(ufd, "群不存在\n");
        if (reply) freeReplyObject(reply);
        return;
    }
    freeReplyObject(reply);
    reply = (redisReply*)redisCommand(redis_conn, "SISMEMBER %s %s", members_key.c_str(), clients[ufd].username.c_str());
    if (reply == nullptr) 
    {
         send_message(ufd, "网络错误\n"); 
         return;
     }
    if (reply->type != REDIS_REPLY_INTEGER || reply->integer != 1)
     {
        send_message(ufd, "你不是群成员\n");
        if (reply) freeReplyObject(reply);
        return;
    }
    freeReplyObject(reply);
    reply = (redisReply*)redisCommand(redis_conn, "SMEMBERS %s", members_key.c_str());
    if (reply == nullptr || reply->type != REDIS_REPLY_ARRAY) 
    {
        send_message(ufd, "获取成员列表失败\n");
        if (reply) freeReplyObject(reply);
        return;
    }
    if (reply->elements <= 1)
    {
        send_message(ufd, "群中只有你自己\n");
        freeReplyObject(reply);
        return;
    }
    send_message(ufd, "群成员:\n");
    for (size_t i = 0; i < reply->elements; ++i) 
    {
        string name = reply->element[i]->str;
        send_message(ufd, name + "\n");
    }
    freeReplyObject(reply);
    send_message(ufd, "成员列表结束\n");
}

void chaqun(int ufd) 
{
    if (!clients[ufd].logged_in)
    {
        send_message(ufd, "请先登录\n");
        return;
    }
    string key = "user:" + clients[ufd].username + ":groups:";
    cout << "chaqun: key = " << key << endl;  
    redisReply* reply = (redisReply*)redisCommand(redis_conn, "SMEMBERS %s", key.c_str());
    if (reply == nullptr)
     {
        send_message(ufd, "网络错误\n");
        return;
    }
    if (reply->type != REDIS_REPLY_ARRAY) 
    {
        send_message(ufd, "获取群列表失败\n");
        if (reply) freeReplyObject(reply);
        return;
    }
    cout << "chaqun: elements = " << reply->elements << endl;
    if (reply->elements == 0) 
    {
        send_message(ufd, "未加入任何群\n");
        freeReplyObject(reply);
        return;
    }
    send_message(ufd, "我加入的群:\n");
    for (size_t i = 0; i < reply->elements; ++i)
     {
        string group_name = reply->element[i]->str;
        cout << "chaqun: group = " << group_name << endl;   
        send_message(ufd, group_name + "\n");
    }
    freeReplyObject(reply);
    send_message(ufd, "列表结束\n");
}

void lixian(int ufd) 
{
    string key = "offline:" + clients[ufd].username;
    redisReply* reply = (redisReply*)redisCommand(redis_conn, "LRANGE %s 0 -1", key.c_str());
    if (reply == nullptr) 
    { 
        send_message(ufd, "拉取离线消息失败\n"); 
        return; 
    }
    if (reply->type != REDIS_REPLY_ARRAY)
     {

        send_message(ufd, "离线消息格式错误\n");
        if (reply) freeReplyObject(reply);
        return;
    }
    if (reply->elements == 0)
     {
        send_message(ufd, "无离线消息\n");
        freeReplyObject(reply);
        return;
    }
    for (size_t i = 0; i < reply->elements; ++i) 
    {
        string msg = string(reply->element[i]->str) + '\n';
        send_message(ufd, msg);
    }
    freeReplyObject(reply);
    redisCommand(redis_conn, "DEL %s", key.c_str());
    send_message(ufd, "离线消息拉取完成\n");
}

void tuiqun(int ufd,const string&qun)
{
    if(clients[ufd].logged_in==false)
    {
        send_message(ufd,"先登陆\n");
        return;
    }
   string key1="user:"+clients[ufd].username+":groups:";
   redisReply*reply1=(redisReply*)redisCommand(redis_conn,"SISMEMBER %s %s",key1.c_str(),qun.c_str());
   if(reply1==nullptr)
   {
    send_message(ufd,"网不好\n");
    return;
   }
   if(reply1->type!=REDIS_REPLY_INTEGER||reply1->integer!=1)
   {
    send_message(ufd,"不在群聊里\n");
    freeReplyObject(reply1);
    return;
   }
   freeReplyObject(reply1);
   string key2="group:"+qun;
   redisReply*reply2=(redisReply*)redisCommand(redis_conn,"HGET %s owner",key2.c_str());
   if(reply2==nullptr)
   {
    send_message(ufd,"网不好\n");
    return;
   }
   if(reply2->type==REDIS_REPLY_STRING)
   {
    if(reply2->str==clients[ufd].username)
    {
        send_message(ufd,"你是群主，请先转让群主\n");
        freeReplyObject(reply2);
        return;
    }
   }
   freeReplyObject(reply2);
   string key4="group:"+qun+":members:";
   redisReply*reply4=(redisReply*)redisCommand(redis_conn,"SREM %s %s",key4.c_str(),clients[ufd].username.c_str());
   if(reply4==nullptr)
   {
    send_message(ufd,"网不好\n");
    return;
   }
   if(reply4->type==REDIS_REPLY_INTEGER&&reply4->integer==1)
   {
    send_message(ufd,"退群成功\n");
   }
   else
   {
    send_message(ufd,"退群失败\n");
   freeReplyObject(reply4);
  return;
   }
   freeReplyObject(reply4);
   string key3="user:"+clients[ufd].username+":groups:";
   redisReply*reply3=(redisReply*)redisCommand(redis_conn,"SREM %s %s",key3.c_str(),qun.c_str());
   if(reply3==nullptr)
   {
    send_message(ufd,"网不好\n");
    return;
   }
   if(reply3->type==REDIS_REPLY_INTEGER&&reply3->integer==1)
   {
         send_message(ufd,"从用户列表删除成功");
   }
   else
   {
    send_message(ufd,"从用户列表删除失败\n");
    string key="group:"+qun+":members:";
    redisCommand(redis_conn,"SADD %s %s",key.c_str(),clients[ufd].username.c_str());
   }
     freeReplyObject(reply3);
   return;
}
void jiesan(int ufd,const string&qun)
{
    if(clients[ufd].logged_in==false)
    {
        send_message(ufd,"先登陆\n");
        return;
    }
    string key="group:"+qun;
    redisReply*reply=(redisReply*)redisCommand(redis_conn,"HGET %s owner",key.c_str());
    if(reply==nullptr)
    {
        send_message(ufd,"网不好\n");
        return;
    }
    if(reply->type!=REDIS_REPLY_STRING||string(reply->str)!=clients[ufd].username)
    {
        send_message(ufd,"你不是群主\n");
        freeReplyObject(reply);
        return;
    }
    freeReplyObject(reply);
    string key2="group:"+qun+":members:";
    redisReply*reply3=(redisReply*)redisCommand(redis_conn,"SMEMBERS %s",key2.c_str());
    if(reply3==nullptr)
    {
        send_message(ufd,"网不好\n");
        return;
    }
    if(reply3->type==REDIS_REPLY_ARRAY)
    {
        int n=reply3->elements;
        for(int i=0;i<n;i++)
        {
           string name=reply3->element[i]->str;
            string key4="user:"+name+":groups:";
          redisReply*reply4=(redisReply*)redisCommand(redis_conn,"SREM %s %s",key4.c_str(),qun.c_str());
          if(reply4==nullptr)
          {
            send_message(ufd,"网不好\n");
            freeReplyObject(reply3);
            return;
          }
          if(reply4->type!=REDIS_REPLY_INTEGER||reply4->integer!=1)
          {
               string msg="用户"+name+"删除群聊失败"+'\n';
               send_message(ufd,msg);
               freeReplyObject(reply4);
               continue;
          }
          freeReplyObject(reply4);
        }
    }
    else
    {
        send_message(ufd,"查找群聊列表失败\n");
        freeReplyObject(reply3);
        return;
    }
    freeReplyObject(reply3);
    redisReply*reply2=(redisReply*)redisCommand(redis_conn,"DEL %s",key2.c_str());
    if(reply2==nullptr)
    {
        send_message(ufd,"网不好\n");
        return;
    }
    if(reply2->type!=REDIS_REPLY_INTEGER||reply2->integer!=1)
    {
        send_message(ufd,"解散群聊失败\n");
        freeReplyObject(reply2);
        return;
    }
    freeReplyObject(reply2);
    string key3="group:"+qun;
    redisReply*reply4=(redisReply*)redisCommand(redis_conn,"DEL %s",key3.c_str());
    if(reply4==nullptr)
    {
        send_message(ufd,"网不好\n");
        return;
    }
    if(reply4->type==REDIS_REPLY_INTEGER&&reply4->integer>=0)
    {
        send_message(ufd,"解散群聊成功\n");
        freeReplyObject(reply4);
        return;
    }
    send_message(ufd,"命令执行失败\n");
    freeReplyObject(reply4);
    return;
}

void broadcast(int sender_fd, const string& msg)
 {
    vector<int> fds;
    fds.reserve(clients.size());
    for (const auto& pair : clients) {
        if (pair.first != sender_fd && pair.second.logged_in)
            fds.push_back(pair.first);
    }
    for (int fd : fds) {
        send_message(fd, msg);
    }
}


void handle_command(int fd, const string& line)
 {
    
    cerr << "handle_command: " << line << endl;
    Client& client = clients[fd];
    istringstream iss(line);
    string cmd;
    iss >> cmd;
    cerr << "handle_command: received line = [" << line << "]" << endl;
    if (cmd == "发送验证码") 
    {
        string email;
        iss>>email;
        GET_CAPTCHA(fd,email);
    }
    else if(cmd =="注册")
    {
        string name,pwd,email,code;
          if (!(iss >> name >> pwd >> email >> code)) {
        send_message(fd, "用法: 注册 <用户名> <密码> <邮箱> <验证码>\n");
        return;
    }
        if(registeruser(fd,name,pwd,email,code))
        {
            send_message(fd,"注册成功\n");
        }
        else
        {
            send_message(fd,"注册失败\n");
        }
    }
    else if (cmd == "登录") {
    string username, password_hash, email, code;
    if (!(iss >> username >> password_hash >> email >> code)) {
        send_message(fd, "用法: 登录 <用户名> <密码> <邮箱> <验证码>\n");
        return;
    }
    if (login(fd, username, password_hash, email, code)) {
        // 登录成功：设置状态、广播上线等
        clients[fd].logged_in = true;
        clients[fd].username = username;
        name_to_fd[username] = fd;
        set_online(username);
        send_message(fd, "LOGIN_OK "+username+"\n");
        broadcast(fd, "[系统] " + username + " 加入了聊天。\n");
        lixian(fd);
    } else {
        send_message(fd, "登录失败（用户名、密码、邮箱或验证码错误）\n");
    }
   }
    else if(cmd=="忘记密码")
    {
         string username, password_hash, email, code;
    if (!(iss >> username >> password_hash >> email >> code)) {
        send_message(fd, "用法: 忘记密码 <用户名> <密码> <邮箱> <验证码>\n");
        return;
    }
    findpassword1(fd,username,email,code,password_hash);
    }
    else if (cmd == "心跳") 
    {
        if (client.logged_in) {
            refresh_online(client.username);
            send_message(fd, "PONG\n");
        } else {
            send_message(fd, "未登录\n");
        }
    }
    else if (cmd == "添加好友") 
    {
        string target;
        iss >> target;
       addfirends(fd,target);
    }
    else if (cmd == "列出好友申请") 
    {
        list_firends_requests(fd);
    }
    else if(cmd == "同意添加好友")
    {
        string target;
        iss >> target;
        accept_friends(fd, target);
    }
    else if(cmd=="拒绝添加好友")
    {
        string target;
        iss >> target;
        reject_friends(fd, target);
    }
    else if (cmd == "删除好友")
     {
        string target;
        iss >> target;
        del_friend(fd, target);
    }
    else if (cmd == "好友列表")
     {
        list_friends(fd);
    }
    else if(cmd=="屏蔽")
    {
        string target;
        iss >> target;
       pingbi(fd, target);
    }
    else if(cmd=="解除屏蔽")
    {
         string target;
        iss >> target;
        jiechupinbi(fd, target);
    }
    else if (cmd == "私聊")
     {
        string target, content;
        iss >> target;
        if (target.empty())
         { 
            send_message(fd, "好友不能为空\n"); 
            return; 
        }
        getline(iss, content);
        size_t pos = content.find_first_not_of(" ");
        if (pos == string::npos) 
        { 
            send_message(fd, "消息不能为空\n"); 
            return; 
        }
        content = content.substr(pos);
        siliao(fd, target, content);
    }
    else if (cmd == "创建群聊")
     {
        string qun;
        if (!(iss >> qun)) 
        { 
            send_message(fd, "群名不能为空\n");
             return; 
        }
        chuangqun(fd, qun);
    }
    else if (cmd == "加入群聊")
     {
        string qun;
        if (!(iss >> qun))
         { 
            send_message(fd, "群名不能为空\n"); 
            return;
         }
       add_group(fd, qun);
    }
    else if(cmd=="查看群聊申请列表")
    {
       string qun;
        if (!(iss >> qun))
         { 
            send_message(fd, "群名不能为空\n"); 
            return;
         }
       list_group(fd, qun);
    }
    else if(cmd=="同意加入群聊")
    {
        string qun,name;
        iss>>qun>>name;
        if(qun.empty())
        {
            send_message(fd,"群名不能为空\n");
            return;
        }
        if(name.empty())
        {
            send_message(fd,"用户名不能为空\n");
            return;
        }
        accept_group(fd,qun,name);
    }
    else if(cmd=="拒绝加入群聊")
    {
        string qun,name;
        iss>>qun>>name;
        if(qun.empty())
        {
            send_message(fd,"群名不能为空\n");
            return;
        }
        if(name.empty())
        {
            send_message(fd,"用户名不能为空\n");
            return;
        }
        reject_group(fd,qun,name);
    }
    else if (cmd == "群聊")
     {
        string qun, content;
        iss >> qun;
        if (qun.empty())
         { 
            send_message(fd, "群名不能为空\n");
             return; 
        }
        getline(iss, content);
        size_t pos = content.find_first_not_of(" ");
        if (pos == string::npos) 
        { 
            send_message(fd, "消息不能为空\n");
             return;
         }
        content = content.substr(pos);
        qunliao(fd, qun, content);
    }
    else if(cmd=="解散群聊")
    {
        string group;
        if(!(iss>>group))
        {
            send_message(fd,"群名不能为空\n");
        }
        jiesan(fd,group);
    }
    else if(cmd =="移除成员")
    {
         string qun, content;
        iss >> qun;
        if (qun.empty())
         { 
            send_message(fd, "群名不能为空\n");
             return; 
        }
        getline(iss, content);
        size_t pos = content.find_first_not_of(" ");
        if (pos == string::npos) 
        { 
            send_message(fd, "用户名不能为空\n");
             return;
         }
        content = content.substr(pos);
        shanchenyuan(fd, qun, content);
    }
    else if (cmd == "查看群成员")
     {
        string qun;
        if (!(iss >> qun))
         { 
            send_message(fd, "群名不能为空\n"); 
            return; 
        }
        chachengyuan(fd, qun);
    }
    else if (cmd == "查看群聊列表") 
    {
        chaqun(fd);
    }
    else if(cmd=="查看聊天记录")
    {
        string name;
        if(!(iss>>name))
        {
            send_message(fd,"对象不能为空\n");
            return;
        }
        get_hisory(fd,name);
    }
    else if(cmd=="设置管理员")
    {
        string group,name;
        if(!(iss>>group>>name))
        {
            send_message(fd,"群名或者管理员名字不能为空\n");
            return;
        }
        guanli(fd,group,name);
    }
    else if(cmd=="删除管理员")
    {

        string group,name;
        if(!(iss>>group>>name))
        {
            send_message(fd,"群名或者管理员名字不能为空\n");
            return;
        }
        shanguan(fd,group,name);
    }
    else if(cmd=="退出群聊")
    {
        string group;
        if(!(iss>>group))
        {
            send_message(fd,"群名不能为空\n");
            return;
        }
        tuiqun(fd,group);
    }
    else if (cmd == "UPLOAD_FILE") {
    string target, filename, filesize_str;
    if (!(iss >> target >> filename >> filesize_str)) {
        send_message(fd, "用法: UPLOAD_FILE <目标> <文件名> <文件大小>\n");
        return;
    }

    // 1. 检查发送者是否已登录
    if (!clients[fd].logged_in) {
        send_message(fd, "请先登录\n");
        return;
    }

    // 2. 解析文件大小
    size_t filesize;
    try {
        filesize = stoull(filesize_str);
    } catch (...) {
        send_message(fd, "文件大小格式错误\n");
        return;
    }
    if (filesize == 0) {
        send_message(fd, "文件大小不能为0\n");
        return;
    }

    // 3. 获取发送者用户名
    string sender = clients[fd].username;

    // 4. 调用文件传输初始化函数（权限检查、创建临时文件、存储元信息等）
    handle_file_command(redis_conn, fd, sender, target, filename, filesize);
}
    else if (cmd == "RESUME_UPLOAD") {
        if (!clients[fd].logged_in) {
        send_message(fd, "请先登录\n");
        return;
    }
    string filename;
    if (!(iss >> filename)) {
        send_message(fd, "用法: RESUME_UPLOAD <filename>\n");
        return;
    }
    string sender = clients[fd].username;
   Resend_file(fd,sender,filename,redis_conn);
}
    else if (cmd == "DOWNLOAD_FILE") {
    string file_id;
    if (!(iss >> file_id)) {
        send_message(fd, "用法: DOWNLOAD_FILE <file_id>\n");
        return;
    }

    // 1. 检查用户是否已登录
    if (!clients[fd].logged_in) {
        send_message(fd, "请先登录\n");
        return;
    }

    // 2. 检查文件是否存在且状态为 complete
    string meta_key = "file:meta:" + file_id;
    redisReply* reply = (redisReply*)redisCommand(redis_conn, "EXISTS %s", meta_key.c_str());
    if (!reply || reply->type != REDIS_REPLY_INTEGER || reply->integer != 1) {
        send_message(fd, "文件不存在\n");
        if (reply) freeReplyObject(reply);
        return;
    }
    freeReplyObject(reply);

    // 3. 检查文件状态是否为 complete
    reply = (redisReply*)redisCommand(redis_conn, "HGET %s status", meta_key.c_str());
    if (!reply || reply->type != REDIS_REPLY_STRING || string(reply->str) != "complete") {
        send_message(fd, "文件未上传完成，无法下载\n");
        if (reply) freeReplyObject(reply);
        return;
    }
    freeReplyObject(reply);

    // 4. 权限检查（目标接收者或群成员）
    if (!is_target(fd, redis_conn, file_id, clients[fd].username)) {
        // is_target 内部已发送错误消息
        return;
    }

    // 5. 获取文件名和大小
    string filename = get_filename_meta(file_id, redis_conn);
    long long filesize = get_file_size(file_id, redis_conn);
    if (filesize < 0) {
        send_message(fd, "获取文件信息失败\n");
        return;
    }

    // 6. 返回 FILE_INFO
    string msg = "FILE_INFO " + filename + " " + to_string(filesize) + " " + file_id + "\n";
    send_message(fd, msg);
}
    else if (cmd == "退出")
     {
        // 用户执行 /quit
   string leave_msg = "[系统] " + clients[fd].username + " 离开了。\n";
broadcast(fd, leave_msg);   // 发送广播
close_connection(fd);       // 然后清理
      
    }
    else {
        if (client.logged_in) 
        {
            string msg = client.username + ": " + line + "\n";
            broadcast(fd, msg);
            cout << msg;
        } 
        else
         {
            send_message(fd, "请先登录\n");
        }
    }
}
 bool do_handshake(int fd) {
    auto it = clients.find(fd);
    if (it == clients.end() || !it->second.ssl) return false;

    Client& c = it->second;
    if (c.handshak_down) return true;

    ERR_clear_error();
    int ret = SSL_accept(c.ssl);

    if (ret == 1) {
        c.handshak_down = true;
        cerr << "TLS handshake success for fd " << fd << endl;

        struct epoll_event ev{};
        ev.events = EPOLLIN;
        ev.data.fd = fd;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev) == -1) {
            perror("epoll_ctl MOD after handshake");
            close_connection(fd);
            return false;
        }
        return true;
    }

    int err = SSL_get_error(c.ssl, ret);
    struct epoll_event ev{};
    ev.data.fd = fd;

    if (err == SSL_ERROR_WANT_READ) {
        ev.events = EPOLLIN;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
        return false;
    }

    if (err == SSL_ERROR_WANT_WRITE) {
        ev.events = EPOLLOUT;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
        return false;
    }

    cerr << "TLS handshake failed for fd " << fd << endl;
    ERR_print_errors_fp(stderr);
    close_connection(fd);
    return false;
}

void cleancurl()
{
    curl_global_cleanup();
    return;
}
int main() 
{
    signal(SIGPIPE, SIG_IGN);
    if (!init_redis())return 1;
     srand((unsigned int)(time(nullptr)));
     CURLcode curl_init_res=curl_global_init(CURL_GLOBAL_DEFAULT);
     if (!init_mysql()) {
    cerr << "MySQL initialization failed, exiting." << endl;
    return 1;
    }
     if(curl_init_res!=CURLE_OK)
     {
        cerr<<"全局初始化失败:"<<curl_easy_strerror(curl_init_res)<<endl;
        return 1;
     }
     atexit(cleancurl);
    init_leveldb();
    init_file_transfer(redis_conn);
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_print_errors_fp(stderr);
    ERR_clear_error();
    SSL_CTX*ctx=SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    if (SSL_CTX_use_certificate_file(ctx,"./server.crt",SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx,"./server.key",SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return 1;
    }
    if(SSL_CTX_check_private_key(ctx)!=1)
    {
        cerr<<"ssl私钥和证书不匹配"<<endl;
        return 1;
    }
    SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,NULL);
    SSL_CTX_set_verify_depth(ctx,10);
    epoll_fd = epoll_create1(0);
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int file_listen_fd=socket(AF_INET,SOCK_STREAM,0);
    int opt = 1;
    int file_opt=1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(file_listen_fd, SOL_SOCKET, SO_REUSEADDR, &file_opt, sizeof(file_opt));
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);
    struct sockaddr_in file_addr{};
    file_addr.sin_family = AF_INET;
    file_addr.sin_addr.s_addr = INADDR_ANY;
    file_addr.sin_port = htons(FILEPORT);
    if(bind(listen_fd, (sockaddr*)&addr, sizeof(addr))<0)
    {
          perror("bind");
          exit(1);
    }
     if(bind(file_listen_fd, (sockaddr*)&file_addr, sizeof(file_addr))<0)
    {
          perror("bind");
          exit(1);
    }
    listen(listen_fd, SOMAXCONN);
    listen(file_listen_fd, SOMAXCONN);
    set_nonblocking(listen_fd);
     set_nonblocking(file_listen_fd);
    struct epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd =listen_fd;
    struct epoll_event file_ev{};
    file_ev.events = EPOLLIN;
    file_ev.data.fd = file_listen_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev);
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, file_listen_fd, &file_ev);
    cout << "Server started on port " << PORT << endl;
    cout << "Server Filesend started on port " << FILEPORT << endl;
    struct epoll_event events[MAX_EVENTS];
    while (true) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }

        for (int i = 0; i < nfds; ++i) {
            int fd = events[i].data.fd;
            uint32_t revents = events[i].events;

            if (fd == listen_fd || fd == file_listen_fd) {
                const bool is_file_listener = (fd == file_listen_fd);
                while (true) {
                    int client_fd = accept(fd, nullptr, nullptr);
                    if (client_fd < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        if (errno == EINTR) continue;
                        perror("accept");
                        break;
                    }

                    if (set_nonblocking(client_fd) < 0) {
                        perror("set_nonblocking client");
                        close(client_fd);
                        continue;
                    }

                    SSL* ssl = SSL_new(ctx);
                    if (!ssl) {
                        ERR_print_errors_fp(stderr);
                        close(client_fd);
                        continue;
                    }
                    SSL_set_fd(ssl, client_fd);

                    Client& c = clients[client_fd];
                    c.ssl = ssl;
                    c.handshak_down = false;

                    struct epoll_event cev{};
                    cev.events = EPOLLIN;
                    cev.data.fd = client_fd;
                    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &cev) < 0) {
                        perror("epoll_ctl ADD client");
                        SSL_free(ssl);
                        close(client_fd);
                        clients.erase(client_fd);
                        continue;
                    }

                    if (is_file_listener) {
                        file_client_fds.insert(client_fd);
                        on_file_connection(client_fd, true);
                    }

                    // Try the first handshake immediately. If it needs more I/O,
                    // do_handshake() changes the epoll interest set accordingly.
                    do_handshake(client_fd);
                }
                continue;
            }
auto cit = clients.find(fd);
if (cit == clients.end())
    continue;

// ======================================================
// TLS handshake
// ======================================================

if (!cit->second.handshak_down) {

    do_handshake(fd);

    // do_handshake 可能因为错误直接关闭 fd
    if (clients.find(fd) == clients.end())
        continue;

    continue;
}

// ======================================================
// 判断是否文件连接
// ======================================================

const bool is_file =
    (file_client_fds.find(fd) != file_client_fds.end());

// ======================================================
// 文件连接
//
// ★ 非常重要：
// ★ EPOLLIN 必须优先处理。
// ★ 即使同时收到 EPOLLRDHUP，也先把数据读出来。
// ======================================================

if (is_file) {

    auto fit = file_contexts.find(fd);

    bool downloading =
        (fit != file_contexts.end() &&
         fit->second.download_state == DOWNLOAD_SENDING);

    // -----------------------------
    // 先处理已经到达的数据
    // -----------------------------

    if ((downloading &&
         (revents & (EPOLLIN | EPOLLOUT))) ||
        (!downloading &&
         (revents & EPOLLIN))) {

        on_file_data(fd, redis_conn);
    }

    // on_file_data 可能已经关闭 fd
    if (clients.find(fd) == clients.end())
        continue;

    // -----------------------------
    // 再处理写事件
    // -----------------------------

    if (revents & EPOLLOUT) {
        flush_send_buffer(fd);
    }

    // flush_send_buffer 可能已经关闭 fd
    if (clients.find(fd) == clients.end())
        continue;

    // -----------------------------
    // 最后处理断开
    // -----------------------------

    if (revents & (EPOLLERR |
                   EPOLLHUP |
                   EPOLLRDHUP)) {

        cerr << "[EPOLL] file fd="
             << fd
             << " received HUP/RDHUP"
             << endl;

        close_connection(fd);
    }

    continue;
}

// ======================================================
// 普通聊天连接
// ======================================================

if (revents & EPOLLIN) {

    char buf[4096];

    ssize_t n =
        tls_read(fd, buf, sizeof(buf));

    if (n > 0) {

        cit = clients.find(fd);

        if (cit == clients.end())
            continue;

        cit->second.recv_buffer.append(
            buf,
            static_cast<size_t>(n)
        );

        size_t pos;

        while ((pos =
                cit->second.recv_buffer.find('\n'))
               != string::npos) {

            string line =
                cit->second.recv_buffer.substr(
                    0,
                    pos
                );

            cit->second.recv_buffer.erase(
                0,
                pos + 1
            );

            if (!line.empty() &&
                line.back() == '\r') {

                line.pop_back();
            }

            if (!line.empty()) {

                handle_command(
                    fd,
                    line
                );
            }

            if (clients.find(fd) ==
                clients.end()) {

                break;
            }

            cit = clients.find(fd);

            if (cit == clients.end())
                break;
        }

    } else if (n == -2) {

        struct epoll_event ev{};

        ev.events = EPOLLIN;
        ev.data.fd = fd;

        epoll_ctl(
            epoll_fd,
            EPOLL_CTL_MOD,
            fd,
            &ev
        );

    } else if (n == -3) {

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

    } else if (n == 0 || n == -1) {

        close_connection(fd);
        continue;
    }
}

// ======================================================
// 普通连接写事件
// ======================================================

if (clients.find(fd) == clients.end())
    continue;

if (revents & EPOLLOUT) {

    flush_send_buffer(fd);
}

if (clients.find(fd) == clients.end())
    continue;

// ======================================================
// 普通连接最后处理 HUP
// ======================================================

if (revents & (EPOLLERR |
               EPOLLHUP |
               EPOLLRDHUP)) {

    close_connection(fd);
}
        

            
        }
    }

    SSL_CTX_free(ctx);
    close(listen_fd);
    close(file_listen_fd);
    return 0;
}
