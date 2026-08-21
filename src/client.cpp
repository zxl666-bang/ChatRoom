#include <cstdint>
#include <cerrno>
#include <fcntl.h>
#include <hiredis/hiredis.h>
#include <iostream>
#include <cstring>
#include <termios.h>
#include <unistd.h>
#include <sys/socket.h>
#include<iomanip>
#include <netinet/in.h>
#include<vector>
#include<endian.h>
#include<sys/select.h>
#include<sys/stat.h>
#include <arpa/inet.h>
#include<mutex>
#include <thread>
#include <chrono>
#include<fstream>
#include <sstream>
#include<termio.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>      // 核心 SSL/TLS 函数，如 SSL_new、SSL_read、SSL_write
#include <openssl/err.h>      // 错误处理，如 ERR_print_errors_fp、ERR_get_error
#include <openssl/crypto.h>   // 加密基础函数（可选，但若使用锁回调则需）
using namespace std;
const string SALT="chatroomsalt";
string pending_file_id;
string pending_target;
string pending_file_path;
bool upload_ready = false;
bool should_close;
mutex close_mtu;
SSL_CTX*ctx;
SSL*ssl;
mutex ssl_mtu;
mutex state_mtu;
mutex menu_lock;
bool menu=true;
bool send_error_occurred = false;
mutex error_mtu;
bool is_upload=false;
mutex upload_mtu;
size_t wrong=0;
char*ip;
string simplifyPath(string path) {
        vector<string> stack;
        string component;
        
        path += '/';
        
        for (char ch : path) {
            if (ch == '/') {
                if (component == "..") {
                    if (!stack.empty()) stack.pop_back();
                } else if (!component.empty() && component != ".") {
                    stack.push_back(component);
                }
                component.clear();  
            } else {
                component += ch;
            }
        }
        
        if (stack.empty()) return "/";
        string result;
        for (const string& dir : stack) {
            result += "/" + dir;
        }
        return result;
    }
void send_menu()
{
    cerr << "send_menu called" << endl;
    cerr << "=============================================\n";
    cerr << left << setw(20) << "/5 添加好友"
         << setw(20) << "/6 列出好友申请" << "\n";
    cerr << left << setw(20) << "/7 同意好友申请"
         << setw(20) << "/8 拒绝好友申请" << "\n";
    cerr << left << setw(20) << "/9 好友列表"
         << setw(20) << "/10 私聊" << "\n";
    cerr << left << setw(20) << "/11 屏蔽好友"
         << setw(20) << "/12 解除屏蔽" << "\n";
    cerr << left << setw(20) << "/13 申请加入群聊"
         << setw(20) << "/14 退出群聊" << "\n";
    cerr << left << setw(20) << "/15 群聊"
         << setw(20) << "/16 创建群聊" << "\n";
    cerr << left << setw(20) << "/17 查看群成员"
         << setw(20) << "/18 查看自己的群聊" << "\n";
    cerr << left << setw(20) << "/19 查看群申请"
         << setw(20) << "/20 同意加群申请" << "\n";
    cerr << left << setw(20) << "/21 拒绝加群申请"
         << setw(20) << "/22 删除群成员" << "\n";
    cerr << left << setw(20) << "/23 设置管理员"
         << setw(20) << "/24 删除管理员" << "\n";
    cerr << left << setw(20) << "/25 解散群聊"
         << setw(20) << "/26 发送文件" << "\n";
    cerr << left << setw(20) << "/27 下载文件"
         << setw(20) << "/28 查看历史记录" << "\n";
    cerr << left << setw(20) << "/29 删除好友"
         << setw(20) << "/30 手动续传" << "\n";
    cerr << left << setw(20) << "/32 读取未读消息"
         << setw(20) << "/36 退出登录" << "\n";
    cerr << "/37 列出命令目录\n";
    cerr << "/38 列出文件\n";
    cerr << "=============================================\n";
}

string SHA256(const string& input)
 {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);   
    EVP_DigestUpdate(ctx, input.c_str(), input.size());
    EVP_DigestFinal_ex(ctx, digest, &digest_len);
    EVP_MD_CTX_free(ctx);
    char out[65];
    for (unsigned int i = 0; i < digest_len; ++i)
        sprintf(out + i*2, "%02x", digest[i]);
    return string(out);
}
string get_password()
{
    struct termios old,newt;
    tcgetattr(STDIN_FILENO,&old);
    newt=old;
    newt.c_lflag&=~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW,&newt);
    string password;
    getline(cin,password);
    tcsetattr(STDIN_FILENO,TCSANOW,&old);
    return password;
}

int sockfd;
bool logged_in = false;
string username;

bool SSL_write1(SSL* s, const void* buf, int num) {
    if (!s || num < 0) return false;
    lock_guard<mutex> lock(ssl_mtu);

    const char* data = static_cast<const char*>(buf);
    int sent = 0;
    while (sent < num) {
        int n = SSL_write(s, data + sent, num - sent);
        if (n > 0) {
            sent += n;
            continue;
        }

        int err = SSL_get_error(s, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            this_thread::yield();
            continue;
        }

        cerr << "SSL_write error: " << err << endl;
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}

static bool SSL_read_all(SSL* s, void* buf, size_t len) {
    if (!s) return false;
    char* p = static_cast<char*>(buf);
    size_t got = 0;

    while (got < len) {
        int n = SSL_read(s, p + got, static_cast<int>(len - got));
        if (n > 0) {
            got += static_cast<size_t>(n);
            continue;
        }
        int err = SSL_get_error(s, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            this_thread::yield();
            continue;
        }
        if (err == SSL_ERROR_ZERO_RETURN) return false;
        cerr << "SSL_read error: " << err << endl;
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}

void start_upload(const string& file_id, const string& filepath, size_t offset)
{
    cerr << "start_upload: filepath=[" << filepath << "], offset=" << offset  << endl;

    int file_sock = socket(AF_INET, SOCK_STREAM, 0);

    if (file_sock < 0) {
        perror("socket");
        return;
    }

    SSL* ssl1 = SSL_new(ctx);

    if (!ssl1) {
        ERR_print_errors_fp(stderr);
        close(file_sock);
        return;
    }

    SSL_set_fd(ssl1, file_sock);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8889);

    if (inet_pton(AF_INET,ip,&addr.sin_addr) != 1) {

        cerr << "服务器地址错误" << endl;

        SSL_free(ssl1);
        close(file_sock);

        return;
    }

    if (connect(file_sock,(sockaddr*)&addr, sizeof(addr)) < 0) {

        perror("连接文件服务器失败");

        SSL_free(ssl1);
        close(file_sock);

        return;
    }

    cerr << "[UPLOAD] TCP connected to 8889"
         << endl;

    if (SSL_connect(ssl1) != 1) {

        cerr << "TLS 文件上传握手失败"
             << endl;

        ERR_print_errors_fp(stderr);

        SSL_free(ssl1);
        close(file_sock);

        return;
    }

    cerr << "[UPLOAD] TLS handshake success"<< endl;

    ifstream file(filepath, ios::binary);

    if (!file) {

        cerr << "无法重新打开文件"<< endl;

        SSL_shutdown(ssl1);
        SSL_free(ssl1);
        close(file_sock);

        return;
    }

    file.seekg(
        static_cast<streamoff>(offset)
    );

    if (!file) {

        cerr << "定位文件偏移失败"<< endl;

        file.close();

        SSL_shutdown(ssl1);
        SSL_free(ssl1);
        close(file_sock);

        return;
    }

    const size_t CHUNK_SIZE = 64 * 1024;

    vector<char> buffer(CHUNK_SIZE);

    bool success = true;

    while (file.good()) {

        file.read(buffer.data(),static_cast<streamsize>(buffer.size()));

        streamsize got = file.gcount();

        if (got <= 0)
            break;

        size_t read_len =
            static_cast<size_t>(got);

        uint32_t body_len =static_cast<uint32_t>(1 + 16 + 8 + read_len);

        uint32_t net_len =
            htonl(body_len);

        

        if (!SSL_write1(ssl1, &net_len, sizeof(net_len))) {

            cerr << "[UPLOAD] "   << "发送长度头失败" << endl;

            ERR_print_errors_fp(stderr);

            success = false;
            break;
        }

    

        vector<char> packet(body_len);

        packet[0] = 0x01;

        char file_id_buf[16];

        memset( file_id_buf,' ', sizeof(file_id_buf));
        memcpy( file_id_buf,file_id.data(),min( file_id.size(), sizeof(file_id_buf)));
        memcpy( packet.data() + 1, file_id_buf, sizeof(file_id_buf));

        uint64_t net_offset =htobe64(offset);

        memcpy(packet.data() + 1 + 16, &net_offset,  sizeof(net_offset));

        memcpy(packet.data() + 1 + 16 + 8, buffer.data(), read_len);
        if (!SSL_write1(
                ssl1,
                packet.data(),
                static_cast<int>(packet.size()))) {

            cerr << "[UPLOAD] "
                 << "发送文件数据包失败"
                 << endl;

            ERR_print_errors_fp(stderr);

            success = false;
            break;
        }

        offset += read_len;

        cerr << "[UPLOAD] sent chunk="
             << read_len
             << ", total="
             << offset
             << endl;
    }

    file.close();

    if (!success) {

        cerr << "[UPLOAD] "
             << "文件发送失败"
             << endl;

        SSL_shutdown(ssl1);
        SSL_free(ssl1);
        close(file_sock);

        return;
    }


    cerr << "[UPLOAD] "
         << "所有文件数据已经发送，"
         << "等待服务器 UPLOAD_COMPLETE..."
         << endl;

    string response;

    char recv_buf[4096];

    bool server_confirmed = false;

    while (true)
     {

        int n = SSL_read(
            ssl1,
            recv_buf,
            sizeof(recv_buf) - 1
        );

        if (n > 0) {

            recv_buf[n] = '\0';

            response.append(
                recv_buf,
                n
            );

            cerr << "[UPLOAD] "
                 << "server response: ["
                 << string(recv_buf, n)
                 << "]"
                 << endl;

            size_t pos;

            while ((pos = response.find('\n'))
                   != string::npos) {

                string line =
                    response.substr(0, pos);

                response.erase(
                    0,
                    pos + 1
                );

                if (!line.empty() &&
                    line.back() == '\r') {

                    line.pop_back();
                }

                cerr << "[UPLOAD] "
                     << "server line=["
                     << line
                     << "]"
                     << endl;

                string expected =
                    "UPLOAD_COMPLETE " + file_id;

                if (line == expected) {

                    server_confirmed = true;

                    cerr << "[UPLOAD] "
                         << "服务器确认文件上传完成"
                         << endl;

                    break;
                }
            }

            if (server_confirmed)
            {
                break;
            }
            continue;
        }

        int ssl_err =
            SSL_get_error(ssl1, n);

        if (ssl_err == SSL_ERROR_ZERO_RETURN) {

            cerr << "[UPLOAD] "
                 << "服务器关闭了 TLS 连接"
                 << endl;

            break;
        }

        if (ssl_err == SSL_ERROR_WANT_READ ||
            ssl_err == SSL_ERROR_WANT_WRITE) {

            continue;
        }

        cerr << "[UPLOAD] "
             << "等待服务器确认时 SSL_read 失败, error="
             << ssl_err
             << endl;

        ERR_print_errors_fp(stderr);

        break;
    }

    if (server_confirmed) {

        cout << "文件上传成功，总偏移量: "
             << offset
             << endl;
              {
                    lock_guard<mutex> lock(upload_mtu);
                    is_upload=false;
                }
                send_menu();

    } 

    SSL_shutdown(ssl1);
    SSL_free(ssl1);
    close(file_sock);
}

void start_download(const string& file_id, const string& filepath) {
    bool success = true;
    size_t local_size = 0;

    ifstream local_file(filepath, ios::binary | ios::ate);
    if (local_file.is_open()) {
        local_size = static_cast<size_t>(local_file.tellg());
        local_file.close();
        if (local_size > 0) {
            cout << "本地已有 " << local_size << " 字节，将从该位置续传" << endl;
        }
    } else {
        cout << "本地无文件，从头开始下载" << endl;
    }

    int file_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (file_sock < 0) 
    {
        perror("socket");
        return;
    }

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8889);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        cerr << "服务器地址错误" << endl;
        close(file_sock);
        return;
    }
    if (connect(file_sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("连接文件服务器失败");
        close(file_sock);
        return;
    }

    SSL* ssl2 = SSL_new(ctx);
    if (!ssl2) {
        ERR_print_errors_fp(stderr);
        close(file_sock);
        return;
    }
    SSL_set_fd(ssl2, file_sock);

    if (SSL_connect(ssl2) != 1) {
        cerr << "TLS 文件下载握手失败" << endl;
        ERR_print_errors_fp(stderr);
        SSL_free(ssl2);
        close(file_sock);
        return;
    }

    const uint32_t body_len = 1 + 16 + 8;
    uint32_t net_len = htonl(body_len);
    if (!SSL_write1(ssl2, &net_len, sizeof(net_len))) {
        cerr << "发送下载请求长度失败" << endl;
        SSL_shutdown(ssl2);
        SSL_free(ssl2);
        close(file_sock);
        return;
    }

    vector<char> packet(body_len);
    packet[0] = 0x03;
    char file_id_buf[16];
    memset(file_id_buf, ' ', sizeof(file_id_buf));
    memcpy(file_id_buf, file_id.data(), min(file_id.size(), sizeof(file_id_buf)));
    memcpy(packet.data() + 1, file_id_buf, sizeof(file_id_buf));

    uint64_t net_offset = htobe64(local_size);
    memcpy(packet.data() + 1 + 16, &net_offset, sizeof(net_offset));

    if (!SSL_write1(ssl2, packet.data(), static_cast<int>(packet.size()))) {
        cerr << "发送下载请求失败" << endl;
        SSL_shutdown(ssl2);
        SSL_free(ssl2);
        close(file_sock);
        return;
    }

    int fd = open(filepath.c_str(), O_APPEND | O_CREAT | O_WRONLY, 0644);
    if (fd < 0) {
        perror("open");
        SSL_shutdown(ssl2);
        SSL_free(ssl2);
        close(file_sock);
        return;
    }

    while (true) {
        uint32_t net_total_len = 0;
        if (!SSL_read_all(ssl2, &net_total_len, sizeof(net_total_len))) {
            cerr << "DOWNLOAD: SSL_read_all for length returned false, maybe EOF or error" << endl;
            break;
        }

        uint32_t total_len = ntohl(net_total_len);
        if (total_len < 1 + 16 + 8 || total_len > 512 * 1024 + 1 + 16 + 8) {
            cerr << "收到非法文件包长度: " << total_len << endl;
            success = false;
            break;
        }

        vector<char> body(total_len);
        if (!SSL_read_all(ssl2, body.data(), body.size())) {
            success = false;
            break;
        }

        uint8_t cmd = static_cast<uint8_t>(body[0]);
        if (cmd != 0x83) {
            cerr << "收到未知文件下载命令: " << static_cast<int>(cmd) << endl;
            success = false;
            break;
        }

        uint64_t packet_offset_net = 0;
        memcpy(&packet_offset_net, body.data() + 1 + 16, sizeof(packet_offset_net));
        uint64_t packet_offset = be64toh(packet_offset_net);

        if (packet_offset != local_size) {
            cerr << "下载偏移不匹配: server=" << packet_offset
                 << ", local=" << local_size << endl;
            success = false;
            break;
        }

        const char* data = body.data() + 1 + 16 + 8;
        size_t data_len = total_len - 1 - 16 - 8;
        size_t written_total = 0;
        while (written_total < data_len) {
            ssize_t w = write(fd, data + written_total, data_len - written_total);
            if (w > 0) {
                written_total += static_cast<size_t>(w);
            } else if (w < 0 && errno == EINTR) {
                continue;
            } else {
                perror("write");
                success = false;
                break;
            }
        }
        if (!success) break;

        local_size += data_len;
    }

    close(fd);
    SSL_shutdown(ssl2);
    SSL_free(ssl2);
    close(file_sock);

    if (success) {
     cerr << "文件下载完成，大小=" << local_size << " 字节" << endl;
cerr.flush();
    } else {
        cerr << "文件下载中断" << endl;
    }
}

void recv_thread_func() {
    char buffer[4096];
    std::string leftover;

    while (true) {

        ssize_t n = SSL_read(
            ssl,
            buffer,
            sizeof(buffer) - 1
        );

        if (n > 0) {
            buffer[n] = '\0';
            leftover.append(buffer, n);

            size_t pos;

            while ((pos = leftover.find('\n')) != std::string::npos) {

                std::string line =
                    leftover.substr(0, pos);

                leftover.erase(0, pos + 1);
              
                if (!line.empty() && line.back() == '\r') {
                    line.pop_back();
                }

                if (line.rfind("LOGIN_OK", 0) == 0) {

                    std::string user = line.substr(9);

                    if (!user.empty() && user.back() == '\r') {
                        user.pop_back();
                    }

                    {
                        lock_guard<mutex> lock(state_mtu);
                        username = user;
                        logged_in = true;
                    }
                     {
        lock_guard<mutex> lock(error_mtu);
        send_error_occurred = false;  
    }
                    std::cout << "登录成功\n";
                    
                 
                }
                else if (line == "退出登录成功") {
    lock_guard<mutex> lock(state_mtu);
    logged_in = false;
    username.clear();
    cout << "已退出登录，您可以重新登录其他账号" << endl;
       cerr<<"目录\n"<<
    "/1;发送验证码\n"<<
    "/2;验证码注册\n"<<
    "/3;验证码登录\n"<<
    "/31;密码登录\n"<<
    "/35;普通注册\n"
    "/4;//忘记密码\n"<<
    "/33;//退出\n"
    "/34;//注销\n"<<
    "====================请输入你的命令===================\n";
  
}
                else if(line.find("history:")==0)
                {
                     string msg = line.substr(8); 
    size_t colon = msg.find(':');
    if (colon != string::npos) {
        string sender = msg.substr(0, colon);
        string content = msg.substr(colon + 1);
        lock_guard<mutex> lock(state_mtu); 
        if (sender == username) {
            
            cout  << right << setw(60) << msg << endl; 
        } else {
            
            cout<< left << setw(60) << msg << endl;
        }
    }
                }
                else if(line.find("不能私聊")!=string::npos)
                 {        
    cout << line << "\n";
    {
        lock_guard<mutex> lock(error_mtu);
        send_error_occurred = true;
    }
}
                else if(line.find("不能群聊")!=string::npos)
                 {        
    cout << line << "\n";
    {
        lock_guard<mutex> lock(error_mtu);
        send_error_occurred = true;
    }
}
                else if(line.find("解除屏蔽成功")!=string::npos)
                 {
                   
    cout << line << "\n";
    {
        lock_guard<mutex> lock(error_mtu);
        send_error_occurred =false;
    }
}
                else if(line=="命令完成"&&logged_in==true)
                {
                   bool print=false;
                   {
                    lock_guard<mutex> lock(upload_mtu);
                    if(!is_upload)
                    {
                    {
                        lock_guard<mutex> lock(menu_lock);
                        print=menu;
                    }}
                }
                    if(print)
                    {
                        send_menu();
                    }
                    }
                else if(line=="命令完成"&&!logged_in==false)
                {
                    cerr<<"目录\n"<<
    "/1;发送验证码\n"<<
    "/2;验证码注册\n"<<
    "/3;验证码登录\n"<<
    "/31;密码登录\n"<<
    "/35;普通注册\n"
    "/4;//忘记密码\n"<<
    "/33;//退出\n"
    "/34;//注销\n"<<
    "====================请输入你的命令===================\n";
                }
                else if (line == "该用户已被注销" || line.rfind("注销成功",0)==0) {
                    {
            lock_guard<mutex> lock(close_mtu);
           should_close=true;;
                    }
}
                else if (line.rfind("UPLOAD_READY", 0) == 0) {

                    cerr << "DEBUG: Received UPLOAD_READY line: ["
                         << line << "]" << endl;

                    size_t p = line.find(':');

                    if (p != string::npos) {

                        pending_file_id = line.substr(p + 1);

                        pending_file_id.erase(
                            pending_file_id.find_last_not_of("\r\n") + 1
                        );

                        thread upload_thread(
                            start_upload,
                            pending_file_id,
                            pending_file_path,
                            0
                        );

                        upload_thread.detach();
                    }
                }
                else if (line.rfind("PROGRESS", 0) == 0) {

                    stringstream ss(line);

                    string cmd;
                    string file_id;
                    string offset_str;

                    ss >> cmd >> file_id >> offset_str;

                    if (!file_id.empty() &&
                        !offset_str.empty()) {

                        size_t offset = stoull(offset_str);

                        thread upload_thread(
                            start_upload,
                            file_id,
                            pending_file_path,
                            offset
                        );

                        upload_thread.detach();
                    }
                }
                else if(line.find("FILE_INFO")==0)
                {
                     stringstream ss(line);
    string cmd, filename, filesize_str, file_id;
    ss >> cmd >> filename >> filesize_str >> file_id;
    // 可忽略 filename 和 filesize
    cout << "服务器允许下载，开始下载..." << endl;
    // 启动下载线程，需要知道保存路径（可以在 /27 时设置 pending_file_path）
    thread download_thread(start_download, file_id, pending_file_path);
    download_thread.detach();
                }
                else if (line.rfind("FILE_NOTIFY", 0) == 0) {

                    stringstream ss(line);

                    string cmd;
                    string sender;
                    string filename;
                    string file_id;
                    string type;

                    ss >> cmd
                       >> sender
                       >> filename
                       >> file_id
                       >> type;

                    cout << "文件通知: "
                         << sender
                         << " 发送了 "
                         << filename
                         << " (file_id: "
                         << file_id
                         << ", 类型: "
                         << type
                         << ")" << endl;

                    cout << "使用 /27 "
                         << file_id
                         << " <保存路径> 下载"
                         << endl;
                }
                else if (line.rfind("PONG", 0) == 0) 
                {  }
                else {
                    cout << line << "\n";
                }
            }

            fflush(stdout);
            continue;
        }

        int err = SSL_get_error(ssl, n);

        if (err == SSL_ERROR_WANT_READ ||
            err == SSL_ERROR_WANT_WRITE) {

            this_thread::yield();
            continue;
        }

        if (err == SSL_ERROR_ZERO_RETURN) {

            cout << "\n服务器正常关闭 TLS 连接。"
                 << endl;

            break;
        }

        cerr << "\nSSL_read failed, error="
             << err
             << endl;

        ERR_print_errors_fp(stderr);

        break;
    }
}
bool get_args(string&u)
{
    int n=0;
     while(u.empty())
     {
                    cout<<"输入不能为空\n";
                    getline(cin,u);
                    n++;
                    if(n==5)
                    {
                        cout<<"输入过多错误命令，程序退出\n";
                        close(sockfd);
                        return false;
                        
                    }
                }
      return true;
}

int main(int argc, char* argv[]) 
{
    cerr << "======= CLIENT VERSION WITH /list DEBUG ========" << endl;
     cerr<<"目录\n"<<
    "/1;发送验证码\n"<<
    "/2;验证码注册\n"<<
    "/3;验证码登录\n"<<
    "/31;密码登录\n"<<
    "/35;普通注册\n"
    "/4;//忘记密码\n"<<
    "/33;//退出\n"
    "/34;//注销\n"<<
    "====================请输入你的命令===================\n";
    if (argc != 3) {
        cerr << "Usage: ./chat_client <server_ip> <port>" << endl;
        return 1;
    }
     ip = argv[1];
    int port = atoi(argv[2]);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    if (connect(sockfd, (sockaddr*)&addr, sizeof(addr)) < 0)
     {
        perror("connect");
        return 1;
    }
   SSL_library_init();
   OpenSSL_add_all_algorithms();
   SSL_load_error_strings();
   ERR_load_crypto_strings();
   ctx=SSL_CTX_new(TLS_client_method());
   SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,NULL);
   ssl=SSL_new(ctx);
   SSL_set_fd(ssl,sockfd);
   int n=SSL_connect(ssl);
   if(n!=1)
   {
    cerr<<"tls握手失败"<<SSL_get_error(ssl,n)<<"\n";
    return -1;
   }
    thread recv_thread(recv_thread_func);
    recv_thread.detach();
    thread heartbeat([&]()
    {
        while (true) 
        {
            
            this_thread::sleep_for(chrono::seconds(30));
              bool is_logged_in;
        {
            lock_guard<mutex> lock(state_mtu);
            is_logged_in = logged_in;
        }
            if (is_logged_in) 
            {
            
                string msg = "心跳\n";
               SSL_write1(ssl,msg.c_str(),msg.size());
            }
        }
    });
    heartbeat.detach();

    string line;
    while (getline(cin, line)) 
    {
            {
        lock_guard<mutex> lock(close_mtu);
        if (should_close) {
            cout << "收到退出信号，程序正常退出...\n";
          break;
        }
    }
        if (line.empty()) 
        {
            continue;
        }
        if(wrong==5)
        {
            cout<<"输入错误命令过多，退出程序"<<endl;
            string msg="退出\n";
            SSL_write1(ssl,msg.c_str(),msg.size());
            close(sockfd);
            return 0;
        }
         if (line[0] == '/') 
        {
            string cmd = line.substr(1);
            size_t space_pos = cmd.find(' ');
            string cmd_name = (space_pos == string::npos) ? cmd : cmd.substr(0, space_pos);
            string args = (space_pos == string::npos) ? "" : cmd.substr(space_pos + 1);
            if(cmd_name=="37")
            {
                send_menu();
            }
            if(!logged_in)
         {  
            if (cmd_name== "33") 
        {
            wrong=0;
            string msg = "退出\n";
            SSL_write1(ssl, msg.c_str(), msg.size());
            cerr<<"退出程序"<<endl;
         break;
        }
            else if (cmd_name == "2") 
            {
                wrong=0;
                 string u,w,r,p;
                cout<<"命令：验证码注册,name:\n";
                getline(cin,u);
                int n=0;
                while(u.empty())
                {
                    cout<<"输入不能为空\n";
                    getline(cin,u);
                    n++;
                    if(n==5)
                    {
                        cout<<"输入过多错误命令，程序退出\n";
                        close(sockfd);
                        return 0;
                    }
                }
                n=0;
                cout<<"password:\n";
                p=get_password();
                while(p.empty())
                {
                    n++;
                    p=get_password();
                    if(n==5)
                    {
                        cout<<"输入错误命令过多，退出程序\n";
                        return 0;
                    }
                }
                n=0;
                cout<<"email:\n";
                getline(cin,w);
                 while(w.empty())
                {
                    cout<<"输入不能为空\n";
                    getline(cin,w);
                    n++;
                    if(n==5)
                    {
                        cout<<"输入过多错误命令，程序退出\n";
                        close(sockfd);
                        return 0;
                        
                    }
                }
                if(w.find("@163.com")==string::npos)
                {
                    cout<<"请用@163.com邮箱,注册失败\n";
                    continue;
                }
                n=0;
                cout<<"code:\n";
                getline(cin,r);
                if(!get_args(r))
               {
                return 0;
               }
                string password=SHA256(SALT+p);
                string msg = "验证码注册 " + u + " "+p+" "+w+" "+r+"\n";
               SSL_write1(ssl, msg.c_str(), msg.size());
                send_menu();
            }
            else if(cmd_name=="1")
            {
                 wrong=0;
               string u;
               cout<<"发送验证码，email:\n";
               getline(cin,u);
               if(!get_args(u))
               {
                return 0;
               }
                string msg = "发送验证码 " + u + "\n";
               SSL_write1(ssl, msg.c_str(), msg.size());
            }
            else if (cmd_name == "3") 
            {
                 wrong=0;
                string u, p,w,r;
                cout<<"验证码登录,name:\n";
                getline(cin,u);
                
               if(!get_args(u))
               {
                return 0;
               }
                cout<<"email:\n";
                getline(cin,w);
                if(!get_args(w))
               {
                return 0;
               }
                cout<<"code:\n";
                getline(cin,r);
                if(!get_args(r))
               {
                return 0;
               }
                string msg = "验证码登录 " + u  + " "+w+" "+r+"\n";
                SSL_write1(ssl, msg.c_str(), msg.size());
            }
            else if(cmd_name=="34")
            {
                 wrong=0;
                string u, p;
               cout<<"注销,name:\n";
               getline(cin,u);
               if(!get_args(u))
               {
                return 0;
               }
               cout<<"password:\n";
              p=get_password();
                int n=0;
                while(p.empty())
                {
                    n++;
                    p=get_password();
                    if(n==5)
                    {
                        cout<<"输入错误命令过多，退出程序\n";
                        return 0;
                    }
                }
                n=0;
                string pwd_md5 = SHA256(SALT+p);
                string msg = "注销 " + u + " " + pwd_md5+"\n";
                SSL_write1(ssl, msg.c_str(), msg.size());
            }
            else if (cmd_name == "31") 
            {
                 wrong=0;
                string u, p;
                cout<<"密码登录,name:\n";
                getline(cin,u);
                if(!get_args(u))
               {
                return 0;
               }
                cout<<"password:\n";
                p=get_password();
                int n=0;
                while(p.empty())
                {
                    n++;
                    p=get_password();
                    if(n==5)
                    {
                        cout<<"输入错误命令过多，退出程序\n";
                        return 0;
                    }
                }
                n=0;
                string pwd_md5 = SHA256(SALT+p);
                string msg = "密码登录 " + u + " " + pwd_md5+"\n";
                SSL_write1(ssl, msg.c_str(), msg.size());
            }
            else if(cmd_name=="4")
            {
                wrong=0;
                string u, p,w,r;
                cout<<"忘记密码，name:\n";
                getline(cin,u);
                if(!get_args(u))
               {
                return 0;
               }
                cout<<"password:\n";
                 p=get_password();
                int n=0;
                while(p.empty())
                {
                    n++;
                    p=get_password();
                    if(n==5)
                    {
                        cout<<"输入错误命令过多，退出程序\n";
                        return 0;
                    }
                }
                n=0;
                cout<<"email:\n";
                getline(cin,w);
                if(!get_args(w))
               {
                return 0;
               }
                cout<<"code:\n";
                getline(cin,r);
                if(!get_args(r))
               {
                return 0;
               }
                string pwd_md5 = SHA256(SALT+p);
                string msg = "忘记密码 " + u + " " + pwd_md5 + " "+w+" "+r+"\n";
                SSL_write1(ssl, msg.c_str(), msg.size());
            }
            else if(cmd_name=="35")
            {
                 wrong=0;
                string u, p,w;
               cout<<"普通注册，name:\n";
               getline(cin,u);
               if(!get_args(u))
               {
                return 0;
               }
               cout<<"password:\n";
                p=get_password();
                int n=0;
                while(p.empty())
                {
                    n++;
                    p=get_password();
                    if(n==5)
                    {
                        cout<<"输入错误命令过多，退出程序\n";
                        return 0;
                    }
                }
                n=0;
               cout<<"email:\n";
               getline(cin,w);
               if(!get_args(w))
               {
                return 0;
               }
               if(w.find("@163.com")==string::npos)
               {
                cout<<"请使用@163.com邮箱，注册失败\n";
                continue;
               }
                string pwd_md5 = SHA256(SALT+p);
                string msg = "普通注册 " + u + " " + pwd_md5 + " "+w+"\n";
               SSL_write1(ssl, msg.c_str(), msg.size());
            } 
            else
           {
            wrong++;
            cout<<"unknow command\n";
            continue;
           }
        }
            else 
            {
               
            if (cmd_name == "5") 
            {
                 wrong=0;
               string u;
               cout<<"添加好友,name:\n";
               getline(cin,u);
               if(!get_args(u))
               {
                return 0;
               }
                string msg = "添加好友 " + u + "\n";
                SSL_write1(ssl, msg.c_str(), msg.size());
            }
            else if(cmd_name=="11")
            {
                 wrong=0;
                string u;
               cout<<"屏蔽好友,name:\n";
               getline(cin,u);
               if(!get_args(u))
               {
                return 0;
               }
                string msg = "屏蔽 " + u + "\n";
                SSL_write1(ssl, msg.c_str(), msg.size());
            }
            else if(cmd_name=="12")
            {
                 wrong=0;
                string u;
               cout<<"解除屏蔽好友,name:\n";
               getline(cin,u);
               if(!get_args(u))
               {
                return 0;
               }
                
                string msg = "解除屏蔽 " + u + "\n";
                SSL_write1(ssl, msg.c_str(), msg.size());
            }
            else if (cmd_name=="6")
            {
                 wrong=0;
                string msg="列出好友申请\n";
                SSL_write1(ssl,msg.c_str(),msg.size());
            }
            else if(cmd_name=="7")
            {
                 wrong=0;
               string u;
               cout<<"同意添加好友,name:\n";
               getline(cin,u);
                if(!get_args(u))
               {
                return 0;
               }
                string msg = "同意添加好友 " + u + "\n";
                SSL_write1(ssl, msg.c_str(), msg.size());
            }
            else if(cmd_name=="8")
            {
                 wrong=0;
               string u;
               cout<<"拒绝添加好友,name:\n";
               getline(cin,u);
               if(!get_args(u))
               {
                return 0;
               }
                string msg = "拒绝添加好友 " +u + "\n";
                SSL_write1(ssl, msg.c_str(), msg.size());
            }
            
            else if (cmd_name == "29")
             {
                 wrong=0;
              string u;
               cout<<"删除好友,name:\n";
               getline(cin,u);
               if(!get_args(u))
               {
                return 0;
               }
                string msg = "删除好友 " +u + "\n";
                SSL_write1(ssl, msg.c_str(), msg.size());
            }
            else if (cmd_name == "9") {
                 wrong=0;
    string msg = "好友列表\n";
    if (!SSL_write1(ssl, msg.c_str(), msg.size())) {
    cerr << "发送 list 命令失败" << endl;
}
}
            else if(cmd_name=="32")
{      wrong=0;
  string u;
               cout<<"读取未读消息，name:\n";
               getline(cin,u);
             if(!get_args(u))
               {
                return 0;
               }
    string msg="读取未读消息 "+u+'\n';
    SSL_write1(ssl,msg.c_str(),msg.size());
  
}
            else if (cmd_name == "10") 
{ 
    wrong=0;
    string target, content;
    cout << "私聊目标用户名: ";
    getline(cin, target);
    if (!get_args(target))
     return 0;

    cout << "请输入消息内容，每行一条，输入 finish 结束：\n";
    string msg1= "私聊 " + target + " " + "begin" + "\n";
     SSL_write1(ssl, msg1.c_str(), msg1.size());
    int blank_count = 0;  
    {
        lock_guard<mutex> lock(menu_lock);
        menu=false;
    }
    while (true) {
       {
    lock_guard<mutex> lock(error_mtu);
    if(send_error_occurred)
    {
        cerr << "[DEBUG] Error detected, sending finish" << endl;
        string msg = "私聊 " + target + " " + "finish" + "\n";
        SSL_write1(ssl, msg.c_str(), msg.size());
        send_error_occurred = false; 
        cerr << "[DEBUG] Error flag reset, calling send_menu" << endl;
        fflush(stdout); fflush(stderr);
        break;
    }
}
     
    getline(cin,content);
    cout << "\033[1A\033[2K\r";
    if (content != "finish") {
        cout << right << setw(60) <<  content<< endl;
    }
    if (content == "finish") {
            {
        lock_guard<mutex> lock(menu_lock);
        menu=true;
        string msg = "私聊 " + target + " " + content + "\n";
        SSL_write1(ssl, msg.c_str(), msg.size());
    }
            break;
        }
        if (content.empty()) {
            blank_count++;
            if (blank_count >= 5) {
                cerr << "连续输入空白过多，是否继续？(y/n): ";
                string choice;
                getline(cin, choice);
                if (choice != "y") break;
                blank_count = 0;
            }
            continue;
        }
        blank_count = 0;  
        string msg = "私聊 " + target + " " + content + "\n";
        SSL_write1(ssl, msg.c_str(), msg.size());
         {
        lock_guard<mutex> lock(error_mtu);
        if (send_error_occurred) {
            {
                send_error_occurred=false;
            } 
            {
        lock_guard<mutex> lock(menu_lock);
        menu=true;}
            break;
        }
    }
    }
    cout << "消息发送结束。\n";
    {
        {
        lock_guard<mutex> lock(menu_lock);
        menu=true;}
    }
}
            else if (cmd_name == "16") 
            { wrong=0;
                string u;
                cout<<"传建群聊,groupname:";
                getline(cin,u);
                if(!get_args(u))
               {
                return 0;
               }
                string msg = "创建群聊 " + u + "\n";
               SSL_write1(ssl, msg.c_str(), msg.size());
            }
            else if (cmd_name == "13")
             { wrong=0;
                 string u;
                cout<<"加入群聊,groupname:";
                getline(cin,u);
                if(!get_args(u))
               {
                return 0;
               }
                string msg = "加入群聊 " + u+ "\n";
                SSL_write1(ssl, msg.c_str(), msg.size());
            }
            else if(cmd_name=="19")
            { wrong=0;
                string u;
                cout<<"查看群聊申请,groupname:";
                getline(cin,u);
                if(!get_args(u))
               {
                return 0;
               }
                string msg = "查看群聊申请列表 " + u + "\n";
                SSL_write1(ssl, msg.c_str(), msg.size());
            }
            else if(cmd_name=="20")
            { wrong=0;
               string target,content;
               cout<<"同意加入群聊，groupname:\n";
               getline(cin,target);
               if(!get_args(target))
               {
                return 0;
               }
               cout<<"membername:\n";
               getline(cin,content);
               if(!get_args(content))
               {
                return 0;
               }
                string msg = "同意加入群聊 " + target + " " + content + "\n";
                 SSL_write1(ssl, msg.c_str(), msg.size());
            }
            else if(cmd=="21")
            {
                 wrong=0;
                 string target,content;
               cout<<"拒绝加入群聊，groupname:\n";
               getline(cin,target);
               if(!get_args(target))
               {
                return 0;
               }
               cout<<"membername:\n";
               getline(cin,content);
               if(!get_args(content))
               {
                return 0;
               }
                string msg = "拒绝加入群聊 " + target + " " + content + "\n";
                 SSL_write1(ssl, msg.c_str(), msg.size());
            }
            else if (cmd_name == "15") 
            {  wrong=0;
    string target, content;
    cout << "群聊,groupname: ";
    getline(cin, target);
    if (!get_args(target)) return 0;
     string msg = "群聊 " + target + " " + "begin" + "\n";
      SSL_write1(ssl, msg.c_str(), msg.size());
    cout << "请输入消息内容，每行一条，输入 finish 结束：\n";
    int blank_count = 0;  
    {
        lock_guard<mutex> lock(menu_lock);
        menu=false;
    }
    while (true) {
        {
            lock_guard<mutex> lock(error_mtu);
            if(send_error_occurred)
            {
                 string content = "finish";
            {
        lock_guard<mutex> lock(menu_lock);
        menu=true;
      }
     string msg = "群聊 " + target + " " + content + "\n";
     SSL_write1(ssl, msg.c_str(), msg.size());
     send_error_occurred=false;
            break;
        }
        }

           fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(STDIN_FILENO, &read_fds);
    struct timeval tv = {0, 100000}; 
    int ret=select(STDIN_FILENO+1,&read_fds,nullptr,nullptr,&tv);
    if(ret<0)
    {
        {
        lock_guard<mutex> lock(menu_lock);
        menu=true;}
        break;
         perror("select");
    }
    else if(ret==0)
{
    continue;
}
getline(cin,content);
cout << "\033[1A\033[2K\r";
    if (content != "finish") {
        cout << right << setw(60) <<  content<< endl;
    }
        if (content == "finish") {
            {
        lock_guard<mutex> lock(menu_lock);
        menu=true;
    }
     string msg = "群聊 " + target + " " + content + "\n";
     SSL_write1(ssl, msg.c_str(), msg.size());
            break;
        }
        if (content.empty()) {
            blank_count++;
            if (blank_count >= 5) {
                cerr << "连续输入空白过多，是否继续？(y/n): ";
                string choice;
                getline(cin, choice);
                if (choice != "y") break;
                blank_count = 0;
            }
            continue;
        }
        blank_count = 0;  
        string msg = "群聊 " + target + " " + content + "\n";
        SSL_write1(ssl, msg.c_str(), msg.size());
    }
    cout << "消息发送结束。\n";
            }
            else if (cmd_name == "17") 
            { wrong=0;
                string u;
               cout<<"查看群聊成员,groupname:\n";
               getline(cin,u);
               if(!get_args(u))
               {
                return 0;
               }
                string msg = "查看群成员 " +u + "\n";
               SSL_write1(ssl, msg.c_str(), msg.size());
            }
            else if(cmd_name=="22")
            { wrong=0;
               string group,content;
               cout<<"移除成员，groupname:\n";
               getline(cin,group);
               if(!get_args(group))
               {
                return 0;
               }
               cout<<"membername:\n";
               getline(cin,content);
               if(!get_args(content))
               {
                return 0;
               }
                string msg = "移除成员 " + group + " " + content + "\n";
             SSL_write1(ssl, msg.c_str(), msg.size());
            }
            else if (cmd_name == "18") 
            {    wrong=0;
                string msg = "查看群聊列表\n";
               SSL_write1(ssl, msg.c_str(), msg.size());
            }
            else if(cmd_name =="14")
            { wrong=0;
                string u;
                cout<<"退出群聊，groupname\n";
                getline(cin,u);
                if(!get_args(u))
               {
                return 0;
               }
                string msg="退出群聊 "+u+"\n";
               SSL_write1(ssl, msg.c_str(), msg.size());
            }
            else if(cmd_name =="25")
            { wrong=0;
                 string u;
                cout<<"解散群聊，groupname\n";
                getline(cin,u);
                if(!get_args(u))
               {
                return 0;
               }
                string msg="解散群聊 "+u+'\n';
                SSL_write1(ssl, msg.c_str(), msg.size());
            }
            else if(cmd_name=="23")
            { wrong=0;
               string u,m;
               cout<<"设置管理员,groupname:\n";
               getline(cin,u);
               if(!get_args(u))
               {
                return 0;
               }
               cout<<"name:\n";
               getline(cin,m);
               if(!get_args(m))
               {
                return 0;
               }
                string msg="设置管理员 "+u+" "+m+'\n';
               SSL_write1(ssl, msg.c_str(), msg.size());
            }
            else if(cmd_name=="24")
            { wrong=0;
                
                string u,m;
               cout<<"删除管理员,groupname:\n";
               getline(cin,u);
               if(!get_args(u))
               {
                return 0;
               }
               cout<<"name:\n";
               getline(cin,m);
               if(!get_args(m))
               {
                return 0;
               }
                string msg="删除管理员 "+u+" "+m+'\n';
              SSL_write1(ssl, msg.c_str(), msg.size());
            }
            else if(cmd_name=="28")
            { wrong=0;
              string u;
              cout<<"查看聊天记录,name:\n";
              getline(cin,u);
              if(!get_args(u))
               {
                return 0;
               }
                string msg="查看聊天记录 "+u+"\n";
                
                 SSL_write1(ssl, msg.c_str(), msg.size());
            }
            else if (cmd_name == "26") 
            {
                {
                    lock_guard<mutex> lock(upload_mtu);
                    is_upload=true;
                }
                
                wrong=0;
             
    string target ,filepath;
    cout<<"上传文件,targetname:\n";
    getline(cin,target);
    if(!get_args(target))
               {
                return 0;
               }
    cout<<"filepath\n";
    getline(cin,filepath); 
if(!get_args(filepath))
               {
                return 0;
               }
   size_t start = filepath.find_first_not_of(" \t\r\n");
    if (start == string::npos) {
        cout<<"name不能为空\n";
         cout << "用法: /26 <目标> <文件路径>\n";
         send_menu();
        continue;
    }
   size_t end = filepath.find_last_not_of(" \t\r\n");
    filepath = filepath.substr(start, end - start + 1);
    filepath=simplifyPath(filepath);
    if (filepath.empty()) {
        cout<<"filepath不能为空\n";
         cout << "用法: /26 <目标> <文件路径>\n";
         send_menu();
        continue;
    }
    cerr<<"filepath:"<<filepath<<endl;
    ifstream file(filepath, ios::binary | ios::ate);
    if (!file.is_open()) {
        cout<<"file打不开"<<endl;
        send_menu();
        continue;
    }
    size_t filesize = file.tellg();
    file.close();
    if (filesize == 0) {
         cout << "文件为空\n";
         send_menu();
        continue;
    }

    size_t sep_pos = filepath.find_last_of("/\\");
    string filename = (sep_pos != string::npos) ? filepath.substr(sep_pos + 1) : filepath;

    pending_file_path = filepath;
    pending_file_path = filepath;
cerr << "DEBUG: pending_file_path set to [" << pending_file_path << "]" << endl;
cerr << "DEBUG: hex: ";
for (char c : pending_file_path) cerr << hex << (int)(unsigned char)c << " ";
cerr << dec << endl;
  
    string cmd = "UPLOAD_FILE " + target + " " + filename + " " + to_string(filesize) + "\n";
  SSL_write1(ssl, cmd.c_str(),cmd.size());

    cout << "文件上传请求已发送，等待服务端响应...\n";
}
            else if (cmd_name == "30") {
                 wrong=0;
              
    string filepath;
    cout<<"续传，filepath:\n";
    getline(cin,filepath);
if(!get_args(filepath))
               {
                return 0;
               }
    ifstream file(filepath, ios::binary | ios::ate);
    if (!file.is_open()) {
        cout << "无法打开文件，请检查路径和权限\n";
        continue;
    }
    file.close();  
    filepath=simplifyPath(filepath);
    size_t sep_pos = filepath.find_last_of("/\\");
    string filename = (sep_pos != string::npos) ? filepath.substr(sep_pos + 1) : filepath;
    pending_file_path = filepath;
    
    string cmd = "RESUME_UPLOAD " + filename + "\n";
    SSL_write1(ssl, cmd.c_str(), cmd.size());
    cout << "续传请求已发送，等待服务端响应...\n";
}
            else if(cmd_name=="27")
            {
                  wrong=0;
             
    string file_id,filepath;
    cout<<"下载文件,file_id:\n";
    getline(cin,file_id);
    if(!get_args(file_id))
               {
                return 0;
               }
    cout<<"filepath:\n";
    getline(cin,filepath);
    if(!get_args(filepath))
               {
                return 0;
               }
    if (filepath.empty()) 
    {
           cout<<"filepath不能为空\n";
       cout << "用法: /27 <file_id> <文件路径>\n";
        continue;
    }
    pending_file_path = filepath;
    string msg="DOWNLOAD_FILE "+file_id+" "+filepath+'\n';
   SSL_write1(ssl,msg.c_str(),msg.size());
    } 
            else if(cmd_name=="38")
            {
                wrong=0;
                string msg="查看可下载文件\n";
                 SSL_write1(ssl, msg.c_str(), msg.size());
            }
            else if (cmd_name== "36") 
        {
            wrong=0;
            string msg = "退出登录\n";
            SSL_write1(ssl, msg.c_str(), msg.size());
            cerr<<"退出登录"<<endl;
        }
            else {
                wrong++;
                cout << "Unknown command" << endl;
            }
        }
         
    }
         else
        {
             cout << "Unknown command" << endl;
              wrong++;
            
        }
    }
   close(sockfd);
SSL_free(ssl);
SSL_CTX_free(ctx);
    return 0;
}