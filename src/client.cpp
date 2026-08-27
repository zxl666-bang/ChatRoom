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
#include <byteswap.h>
#include <endian.h>
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
#include "chat.pb.h"
#include "chat_utils.h" 
#define DEBUG_UPLOAD
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
mutex menu1;
mutex upload_mtu;
size_t wrong=0;
bool serverdisconnect=false;
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
    {lock_guard<mutex> lock(menu_lock);
    cerr << "send_menu called" << endl;
    cerr << "=============================================\n";
    cerr<<"================好友操作=============================\n";
    cerr << left << setw(20) << "/5 添加好友"
         << setw(20) << "/6 列出好友申请" << "\n";
    cerr << left << setw(20) << "/7 同意好友申请"
         << setw(20) << "/8 拒绝好友申请" << "\n";
    cerr << left << setw(20) << "/9 好友列表"
         << setw(20) << "/10 私聊" << "\n";
    cerr << left << setw(20) << "/11 屏蔽好友"
         << setw(20) << "/12 解除屏蔽" << "\n";
    cerr << left << setw(20) << "/29 删除好友"
     << setw(20) << "/28 查看历史记录" << "\n";
     cerr<<"================群聊操作=============================\n";
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
    cerr <<"/40 查看群聊天记录\n";
    cerr  << "/25 解散群聊\n";
    cerr<<"================文件操作=============================\n";
    cerr << "/38 列出文件"
    << setw(20) << "/30 手动续传" << "\n";
    cerr << left << setw(20) << "/27 下载文件"
    << setw(20) << "/26 发送文件" << "\n";
    cerr<<"/41 发送群文件\n";
    cerr<<"================其他操作=============================\n";
    cerr << left << setw(20) << "/32 读取未读消息"
         << setw(20) << "/36 退出登录" << "\n";
    cerr << "/37 列出命令目录\n";
    cerr << "=============================================\n";}
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
    
    chat::ChatPacket packet;
    packet.set_type(chat::ChatPacket::TEXT);
    string text(static_cast<const char*>(buf), static_cast<size_t>(num));
    packet.set_text(text);
    packet.set_payload(text);
    
    string body;
    if (!packet.SerializeToString(&body) || body.size() > UINT32_MAX) {
        cerr << "[SSL_write1] Serialize failed" << endl;
        return false;
    }
    
    // 发送长度头
    uint32_t net_len = htonl(static_cast<uint32_t>(body.size()));
    if (SSL_write(s, &net_len, sizeof(net_len)) != sizeof(net_len)) {
        serverdisconnect = true;
        return false;
    }
    
    // 发送数据体
    size_t sent = 0;
    while (sent < body.size()) {
        int n = SSL_write(s, body.data() + sent, static_cast<int>(body.size() - sent));
        if (n > 0) {
            sent += static_cast<size_t>(n);
        } else {
            int err = SSL_get_error(s, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                this_thread::yield();
                continue;
            }
            serverdisconnect = true;
            ERR_print_errors_fp(stderr);
            return false;
        }
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
        serverdisconnect=true;
        {
            lock_guard<mutex> lock(menu_lock);
            cerr<<"serverdisconnect=true;"<<endl;
             cerr << "SSL_read error: " << err << endl;
        }
        
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}
void start_upload(const string& file_id, const string& filepath, size_t offset)
{
    {
        lock_guard<mutex> lock(menu_lock);
        cerr << "start_upload: filepath=[" << filepath
             << "], offset=" << offset << endl;
    }

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

    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        {
            lock_guard<mutex> lock(menu_lock);
            cerr << "服务器地址错误" << endl;
        }

        SSL_free(ssl1);
        close(file_sock);
        return;
    }

    int sndbuf = 4 * 1024 * 1024;
    int rcvbuf = 4 * 1024 * 1024;

    if (setsockopt(file_sock,
                   SOL_SOCKET,
                   SO_SNDBUF,
                   &sndbuf,
                   sizeof(sndbuf)) < 0) {
        perror("setsockopt SO_SNDBUF");
    }

    if (setsockopt(file_sock,
                   SOL_SOCKET,
                   SO_RCVBUF,
                   &rcvbuf,
                   sizeof(rcvbuf)) < 0) {
        perror("setsockopt SO_RCVBUF");
    }

    if (connect(file_sock,
                reinterpret_cast<sockaddr*>(&addr),
                sizeof(addr)) < 0) {

        perror("连接文件服务器失败");

        SSL_free(ssl1);
        close(file_sock);
        return;
    }

    {
        lock_guard<mutex> lock(menu_lock);
        cerr << "[UPLOAD] TCP connected to 8889" << endl;
    }

    if (SSL_connect(ssl1) != 1) {
        {
            lock_guard<mutex> lock(menu_lock);
            cerr << "TLS 文件上传握手失败" << endl;
        }

        ERR_print_errors_fp(stderr);

        SSL_free(ssl1);
        close(file_sock);
        return;
    }

    {
        lock_guard<mutex> lock(menu_lock);
        cerr << "[UPLOAD] TLS handshake success" << endl;
    }

    ifstream file(filepath, ios::binary);

    if (!file) {
        {
            lock_guard<mutex> lock(menu_lock);
            cerr << "无法重新打开文件: " << filepath << endl;
        }

        SSL_shutdown(ssl1);
        SSL_free(ssl1);
        close(file_sock);
        return;
    }

    // 定位到断点续传位置
    file.seekg(static_cast<streamoff>(offset));

    if (!file) {
        {
            lock_guard<mutex> lock(menu_lock);
            cerr << "定位文件偏移失败，offset="
                 << offset << endl;
        }

        file.close();
        SSL_shutdown(ssl1);
        SSL_free(ssl1);
        close(file_sock);
        return;
    }

    /*
     * 每个 protobuf FILE 数据包最多携带 4MB。
     */
    constexpr size_t CHUNK_SIZE = 4 * 1024 * 1024;

    vector<char> buffer(CHUNK_SIZE);

    bool success = true;

    while (file.good()) {

        file.read(
            buffer.data(),
            static_cast<streamsize>(buffer.size())
        );

        streamsize got = file.gcount();

        if (got <= 0) {
            break;
        }

        size_t read_len = static_cast<size_t>(got);

        /*
         * =====================================================
         * 构造 Protobuf 文件数据包
         *
         * 不再使用：
         *
         *   1 byte command
         *   16 byte file_id
         *   8 byte offset
         *   file data
         *
         * 直接使用 ChatPacket。
         * =====================================================
         */
        chat::ChatPacket packet;

        packet.set_type(chat::ChatPacket::FILE);

        packet.set_file_id(file_id);

        packet.set_offset(
            static_cast<uint64_t>(offset)
        );

        packet.set_payload(
            buffer.data(),
            read_len
        );

        /*
         * protobuf 序列化
         */
        string body;

        if (!packet.SerializeToString(&body)) {
            {
                lock_guard<mutex> lock(menu_lock);
                cerr << "[UPLOAD] protobuf 序列化失败" << endl;
            }

            success = false;
            break;
        }

        if (body.size() > UINT32_MAX) {
            {
                lock_guard<mutex> lock(menu_lock);
                cerr << "[UPLOAD] protobuf 数据包过大" << endl;
            }

            success = false;
            break;
        }

        /*
         * =====================================================
         * 外层 framing：
         *
         *   4 byte protobuf body length
         *   +
         *   protobuf body
         *
         * 注意：
         *
         * 这里绝对不能调用 SSL_write1()
         *
         * 因为 SSL_write1() 会再次把数据包装成 TEXT。
         * =====================================================
         */

        uint32_t net_len =
            htonl(static_cast<uint32_t>(body.size()));

        /*
         * 发送 4 字节长度
         */
        size_t header_sent = 0;

        while (header_sent < sizeof(net_len)) {

            int n = SSL_write(
                ssl1,
                reinterpret_cast<const char*>(&net_len)
                    + header_sent,
                static_cast<int>(
                    sizeof(net_len) - header_sent
                )
            );

            if (n > 0) {
                header_sent += static_cast<size_t>(n);
                continue;
            }

            int err = SSL_get_error(ssl1, n);

            if (err == SSL_ERROR_WANT_READ ||
                err == SSL_ERROR_WANT_WRITE) {

                this_thread::yield();
                continue;
            }

            {
                lock_guard<mutex> lock(menu_lock);
                cerr << "[UPLOAD] 发送 protobuf 长度失败"
                     << endl;
            }

            ERR_print_errors_fp(stderr);

            success = false;
            break;
        }

        if (!success) {
            break;
        }

        /*
         * 发送 protobuf body
         */
        size_t sent = 0;

        while (sent < body.size()) {

            int n = SSL_write(
                ssl1,
                body.data() + sent,
                static_cast<int>(body.size() - sent)
            );

            if (n > 0) {
                sent += static_cast<size_t>(n);
                continue;
            }

            int err = SSL_get_error(ssl1, n);

            if (err == SSL_ERROR_WANT_READ ||
                err == SSL_ERROR_WANT_WRITE) {

                this_thread::yield();
                continue;
            }

            {
                lock_guard<mutex> lock(menu_lock);
                cerr << "[UPLOAD] 发送 protobuf 文件数据失败"
                     << endl;
            }

            ERR_print_errors_fp(stderr);

            success = false;
            break;
        }

        if (!success) {
            break;
        }

        /*
         * 当前 chunk 成功发送。
         */
        offset += read_len;
    }

    file.close();

    if (!success) {

        {
            lock_guard<mutex> lock(menu_lock);
            cerr << "[UPLOAD] 文件发送失败" << endl;
        }

        SSL_shutdown(ssl1);
        SSL_free(ssl1);
        close(file_sock);
        return;
    }

    /*
     * =====================================================
     * 文件数据全部发送完成。
     *
     * 发送一个 FILE 包作为结束标志：
     *
     * payload 为空
     * offset = 最终文件大小
     *
     * =====================================================
     */
    chat::ChatPacket finish_packet;

    finish_packet.set_type(chat::ChatPacket::FILE);

    finish_packet.set_file_id(file_id);

    finish_packet.set_offset(
        static_cast<uint64_t>(offset)
    );

    /*
     * payload 为空，表示文件发送结束。
     */
    finish_packet.clear_payload();

    string finish_body;

    if (!finish_packet.SerializeToString(&finish_body)) {

        {
            lock_guard<mutex> lock(menu_lock);
            cerr << "[UPLOAD] FILE_FINISH protobuf 序列化失败"
                 << endl;
        }

        SSL_shutdown(ssl1);
        SSL_free(ssl1);
        close(file_sock);
        return;
    }

    if (finish_body.size() > UINT32_MAX) {

        {
            lock_guard<mutex> lock(menu_lock);
            cerr << "[UPLOAD] FILE_FINISH 数据包过大"
                 << endl;
        }

        SSL_shutdown(ssl1);
        SSL_free(ssl1);
        close(file_sock);
        return;
    }

    uint32_t finish_len =
        htonl(static_cast<uint32_t>(finish_body.size()));

    /*
     * 发送 FILE_FINISH 的 protobuf 长度
     */
    size_t finish_header_sent = 0;

    while (finish_header_sent < sizeof(finish_len)) {

        int n = SSL_write(
            ssl1,
            reinterpret_cast<const char*>(&finish_len)
                + finish_header_sent,
            static_cast<int>(
                sizeof(finish_len) - finish_header_sent
            )
        );

        if (n > 0) {
            finish_header_sent += static_cast<size_t>(n);
            continue;
        }

        int err = SSL_get_error(ssl1, n);

        if (err == SSL_ERROR_WANT_READ ||
            err == SSL_ERROR_WANT_WRITE) {

            this_thread::yield();
            continue;
        }

        {
            lock_guard<mutex> lock(menu_lock);
            cerr << "[UPLOAD] 发送 FILE_FINISH 长度失败"
                 << endl;
        }

        ERR_print_errors_fp(stderr);

        SSL_shutdown(ssl1);
        SSL_free(ssl1);
        close(file_sock);
        return;
    }

    /*
     * 发送 FILE_FINISH protobuf body
     */
    size_t finish_sent = 0;

    while (finish_sent < finish_body.size()) {

        int n = SSL_write(
            ssl1,
            finish_body.data() + finish_sent,
            static_cast<int>(
                finish_body.size() - finish_sent
            )
        );

        if (n > 0) {
            finish_sent += static_cast<size_t>(n);
            continue;
        }

        int err = SSL_get_error(ssl1, n);

        if (err == SSL_ERROR_WANT_READ ||
            err == SSL_ERROR_WANT_WRITE) {

            this_thread::yield();
            continue;
        }

        {
            lock_guard<mutex> lock(menu_lock);
            cerr << "[UPLOAD] 发送 FILE_FINISH 失败"
                 << endl;
        }

        ERR_print_errors_fp(stderr);

        SSL_shutdown(ssl1);
        SSL_free(ssl1);
        close(file_sock);
        return;
    }

    {
        lock_guard<mutex> lock(menu_lock);
        cerr << "[UPLOAD] 所有文件数据已经发送，"
             << "等待服务器 UPLOAD_COMPLETE..."
             << endl;
    }

    /*
     * =====================================================
     * 等待服务器返回 protobuf。
     * =====================================================
     */
    string recv_buffer;
    bool server_confirmed = false;
string response;
    while (!server_confirmed) {

        char recv_buf[64 * 1024];

        int n = SSL_read(
            ssl1,
            recv_buf,
            sizeof(recv_buf)
        );

        if (n > 0) {

            recv_buffer.append(
                recv_buf,
                static_cast<size_t>(n)
            );

            /*
             * 一个 SSL_read 可能收到：
             *
             *   半个 protobuf
             *
             * 或：
             *
             *   多个 protobuf
             *
             * 所以这里循环拆包。
             */
            while (recv_buffer.size() >= 4) {

                uint32_t net_len = 0;

                memcpy(
                    &net_len,
                    recv_buffer.data(),
                    sizeof(net_len)
                );

                uint32_t body_len = ntohl(net_len);

                /*
                 * 防止错误长度导致异常。
                 */
                if (body_len > 16 * 1024 * 1024) {

                    {
                        lock_guard<mutex> lock(menu_lock);
                        cerr << "[UPLOAD] 服务端 protobuf 包过大: "
                             << body_len
                             << endl;
                    }

                    server_confirmed = false;
                    break;
                }

                /*
                 * 半包。
                 */
                if (recv_buffer.size() <
                    4 + static_cast<size_t>(body_len)) {

                    break;
                }

                /*
                 * 提取 protobuf body。
                 */
                string body =
                    recv_buffer.substr(
                        4,
                        body_len
                    );

                /*
                 * 删除已经处理的数据。
                 */
                recv_buffer.erase(
                    0,
                    4 + static_cast<size_t>(body_len)
                );

                chat::ChatPacket response_packet;

                if (!response_packet.ParseFromString(body)) {

                    {
                        lock_guard<mutex> lock(menu_lock);
                        cerr << "[UPLOAD] 服务端 protobuf 解析失败"
                             << endl;
                    }

                    continue;
                }

                /*
                 * 当前服务端 send_message()
                 * 使用 TEXT 类型返回：
                 *
                 *     UPLOAD_COMPLETE xxx
                 *
                 * 所以这里继续兼容你的现有服务器。
                 */
                string line = response_packet.text();

if (line.empty()) {
    line = response_packet.payload();
}

if (line == "UPLOAD_COMPLETE " + file_id) {

    {
        lock_guard<mutex> lock(menu_lock);
        cerr << "[UPLOAD] server confirmed: "
             << line << endl;
    }

    server_confirmed = true;
    break;
}
                if (server_confirmed) {
                    break;
                }
            }

            continue;
        }

        int err = SSL_get_error(ssl1, n);

        if (err == SSL_ERROR_WANT_READ ||
            err == SSL_ERROR_WANT_WRITE) {

            this_thread::yield();
            continue;
        }

        if (err == SSL_ERROR_ZERO_RETURN) {

            {
                lock_guard<mutex> lock(menu_lock);
                cerr << "[UPLOAD] 服务端关闭了文件连接"
                     << endl;
            }

            break;
        }

        {
            lock_guard<mutex> lock(menu_lock);
            cerr << "[UPLOAD] 等待服务器确认时 SSL_read 失败，"
                 << "error=" << err
                 << endl;
        }

        ERR_print_errors_fp(stderr);

        break;
    }

    if (server_confirmed) {

        {
            lock_guard<mutex> lock(menu_lock);
            cout << "文件上传成功，总大小="
                 << offset
                 << " 字节"
                 << endl;
        }

        {
            lock_guard<mutex> lock(upload_mtu);
            is_upload = false;
        }

        send_menu();

    } else {

        {
            lock_guard<mutex> lock(menu_lock);
            cerr << "[UPLOAD] 文件传送失败："
                 << "服务器没有返回 UPLOAD_COMPLETE"
                 << endl;
        }

        {
            lock_guard<mutex> lock(upload_mtu);
            is_upload = false;
        }
    }

    SSL_shutdown(ssl1);
    SSL_free(ssl1);
    close(file_sock);
}
void start_download(const string& file_id, const string& filepath)
{
    bool success = true;
    size_t local_size = 0;

    /*
     * ============================================================
     * 1. 检查本地文件
     * ============================================================
     */
    ifstream local_file(filepath, ios::binary | ios::ate);

    if (local_file.is_open()) {

        local_size = static_cast<size_t>(
            local_file.tellg()
        );

        local_file.close();

        /*
         * 你原来的逻辑：
         * 如果文件已经存在，不允许直接覆盖。
         */
        if (local_size > 0) {

            {
                lock_guard<mutex> lock(menu_lock);

                cout << "本地已有同名文件,"
                     << "请更改文件名后重新下载"
                     << endl;
            }

            return;
        }
    }
    else {

        {
            lock_guard<mutex> lock(menu_lock);

            cout << "本地无文件，从头开始下载"
                 << endl;
        }
    }

    /*
     * ============================================================
     * 2. 创建 TCP socket
     * ============================================================
     */
    int file_sock = socket(AF_INET, SOCK_STREAM, 0);

    if (file_sock < 0) {
        perror("socket");
        return;
    }

    /*
     * 设置 socket 缓冲区
     */
    int sndbuf = 4 * 1024 * 1024;
    int rcvbuf = 4 * 1024 * 1024;

    if (setsockopt(
            file_sock,
            SOL_SOCKET,
            SO_SNDBUF,
            &sndbuf,
            sizeof(sndbuf)) < 0) {

        perror("setsockopt SO_SNDBUF");
    }

    if (setsockopt(
            file_sock,
            SOL_SOCKET,
            SO_RCVBUF,
            &rcvbuf,
            sizeof(rcvbuf)) < 0) {

        perror("setsockopt SO_RCVBUF");
    }

    /*
     * ============================================================
     * 3. 连接 8889 文件服务器
     * ============================================================
     */
    sockaddr_in addr{};

    addr.sin_family = AF_INET;
    addr.sin_port = htons(8889);

    if (inet_pton(
            AF_INET,
            ip,
            &addr.sin_addr) != 1) {

        {
            lock_guard<mutex> lock(menu_lock);

            cerr << "服务器地址错误" << endl;
        }

        close(file_sock);
        return;
    }

    if (connect(
            file_sock,
            reinterpret_cast<sockaddr*>(&addr),
            sizeof(addr)) < 0) {

        perror("连接文件服务器失败");

        close(file_sock);
        return;
    }

    {
        lock_guard<mutex> lock(menu_lock);

        cerr << "[DOWNLOAD] TCP connected to 8889"
             << endl;
    }

    /*
     * ============================================================
     * 4. TLS
     * ============================================================
     */
    SSL* ssl2 = SSL_new(ctx);

    if (!ssl2) {

        ERR_print_errors_fp(stderr);

        close(file_sock);
        return;
    }

    SSL_set_fd(ssl2, file_sock);

    if (SSL_connect(ssl2) != 1) {

        {
            lock_guard<mutex> lock(menu_lock);

            cerr << "TLS 文件下载握手失败"
                 << endl;
        }

        ERR_print_errors_fp(stderr);

        SSL_free(ssl2);
        close(file_sock);

        return;
    }

    {
        lock_guard<mutex> lock(menu_lock);

        cerr << "[DOWNLOAD] TLS handshake success"
             << endl;
    }

    /*
     * ============================================================
     * 5. 发送 Protobuf 下载请求
     * ============================================================
     *
     * 现在不再发送：
     *
     *     03
     *     file_id[16]
     *     offset[8]
     *
     * 而是：
     *
     *     ChatPacket {
     *         type    = FILE
     *         file_id = xxx
     *         offset  = 本地文件大小
     *         payload = 空
     *     }
     *
     * payload 为空表示这是一个下载请求。
     *
     * 后续服务器发送 FILE 时：
     *
     *     payload != 空
     *
     * 表示真正的文件数据。
     * ============================================================
     */

    chat::ChatPacket request_packet;

    request_packet.set_type(
        chat::ChatPacket::FILE
    );

    request_packet.set_file_id(
        file_id
    );

    request_packet.set_offset(
        static_cast<uint64_t>(local_size)
    );

    request_packet.clear_payload();

    string request_body;

    if (!request_packet.SerializeToString(
            &request_body)) {

        {
            lock_guard<mutex> lock(menu_lock);

            cerr << "[DOWNLOAD] Protobuf 下载请求序列化失败"
                 << endl;
        }

        SSL_shutdown(ssl2);
        SSL_free(ssl2);
        close(file_sock);

        return;
    }

    if (request_body.size() > UINT32_MAX) {

        {
            lock_guard<mutex> lock(menu_lock);

            cerr << "[DOWNLOAD] Protobuf 请求过大"
                 << endl;
        }

        SSL_shutdown(ssl2);
        SSL_free(ssl2);
        close(file_sock);

        return;
    }

    /*
     * ============================================================
     * 6. 发送 Protobuf frame
     *
     *     [4字节网络序长度]
     *     [protobuf body]
     *
     * 注意：
     *
     * 这里不能调用 SSL_write1()
     *
     * 因为 SSL_write1() 会再次包装 ChatPacket。
     * ============================================================
     */

    uint32_t request_len =
        htonl(
            static_cast<uint32_t>(
                request_body.size()
            )
        );

    /*
     * 发送长度
     */
    size_t header_sent = 0;

    while (header_sent < sizeof(request_len)) {

        int n = SSL_write(
            ssl2,
            reinterpret_cast<const char*>(&request_len)
                + header_sent,
            static_cast<int>(
                sizeof(request_len) - header_sent
            )
        );

        if (n > 0) {

            header_sent += static_cast<size_t>(n);
            continue;
        }

        int err = SSL_get_error(ssl2, n);

        if (err == SSL_ERROR_WANT_READ ||
            err == SSL_ERROR_WANT_WRITE) {

            this_thread::yield();
            continue;
        }

        {
            lock_guard<mutex> lock(menu_lock);

            cerr << "[DOWNLOAD] 发送 Protobuf 请求长度失败"
                 << endl;
        }

        ERR_print_errors_fp(stderr);

        success = false;
        break;
    }

    if (!success) {

        SSL_shutdown(ssl2);
        SSL_free(ssl2);
        close(file_sock);

        return;
    }

    /*
     * 发送 protobuf body
     */
    size_t request_sent = 0;

    while (request_sent < request_body.size()) {

        int n = SSL_write(
            ssl2,
            request_body.data() + request_sent,
            static_cast<int>(
                request_body.size() - request_sent
            )
        );

        if (n > 0) {

            request_sent += static_cast<size_t>(n);
            continue;
        }

        int err = SSL_get_error(ssl2, n);

        if (err == SSL_ERROR_WANT_READ ||
            err == SSL_ERROR_WANT_WRITE) {

            this_thread::yield();
            continue;
        }

        {
            lock_guard<mutex> lock(menu_lock);

            cerr << "[DOWNLOAD] 发送 Protobuf 下载请求失败"
                 << endl;
        }

        ERR_print_errors_fp(stderr);

        success = false;
        break;
    }

    if (!success) {

        SSL_shutdown(ssl2);
        SSL_free(ssl2);
        close(file_sock);

        return;
    }

    {
        lock_guard<mutex> lock(menu_lock);

        cerr << "[DOWNLOAD] Protobuf 下载请求发送成功，"
             << "file_id=" << file_id
             << ", offset=" << local_size
             << endl;
    }

    /*
     * ============================================================
     * 7. 打开目标文件
     * ============================================================
     *
     * O_APPEND 与服务器返回的 offset 配合。
     */
    int fd = open(
        filepath.c_str(),
        O_APPEND | O_CREAT | O_WRONLY,
        0644
    );

    if (fd < 0) {

        perror("open");

        SSL_shutdown(ssl2);
        SSL_free(ssl2);
        close(file_sock);

        return;
    }

    /*
     * ============================================================
     * 8. 接收服务器 Protobuf 文件数据
     * ============================================================
     *
     * 使用：
     *
     *     4字节长度
     *     +
     *     protobuf
     *
     * 一个 SSL_read 可能：
     *
     *     收到半个包
     *
     * 也可能：
     *
     *     收到多个包
     *
     * 所以自己维护 recv_buffer。
     * ============================================================
     */

    string recv_buffer;

    bool download_complete = false;

    while (!download_complete) {

        char buffer[256 * 1024];

        int n = SSL_read(
            ssl2,
            buffer,
            sizeof(buffer)
        );

        if (n > 0) {

            recv_buffer.append(
                buffer,
                static_cast<size_t>(n)
            );

            /*
             * 一次 SSL_read 可能包含多个 protobuf。
             */
            while (true) {

                /*
                 * 至少要有 4 字节长度。
                 */
                if (recv_buffer.size() < 4) {
                    break;
                }

                uint32_t net_body_len = 0;

                memcpy(
                    &net_body_len,
                    recv_buffer.data(),
                    sizeof(net_body_len)
                );

                uint32_t body_len =
                    ntohl(net_body_len);

                /*
                 * 防止异常包。
                 */
                if (body_len > 16 * 1024 * 1024) {

                    {
                        lock_guard<mutex> lock(menu_lock);

                        cerr << "[DOWNLOAD] 收到非法 protobuf 包长度: "
                             << body_len
                             << endl;
                    }

                    success = false;
                    download_complete = true;

                    break;
                }

                /*
                 * 当前包还没有接收完整。
                 */
                if (recv_buffer.size() <
                    4 + static_cast<size_t>(body_len)) {

                    break;
                }

                /*
                 * 提取 protobuf body。
                 */
                string body =
                    recv_buffer.substr(
                        4,
                        body_len
                    );

                /*
                 * 从缓存删除已经处理的数据。
                 */
                recv_buffer.erase(
                    0,
                    4 + static_cast<size_t>(body_len)
                );

                /*
                 * =================================================
                 * 解析 ChatPacket
                 * =================================================
                 */
                chat::ChatPacket packet;

                if (!packet.ParseFromString(body)) {

                    {
                        lock_guard<mutex> lock(menu_lock);

                        cerr << "[DOWNLOAD] "
                             << "Protobuf 文件包解析失败"
                             << endl;
                    }

                    success = false;
                    download_complete = true;

                    break;
                }

                /*
                 * =================================================
                 * 检查 packet 类型
                 * =================================================
                 */
                if (packet.type() !=
                    chat::ChatPacket::FILE) {

                    {
                        lock_guard<mutex> lock(menu_lock);

                        cerr << "[DOWNLOAD] 收到未知 packet type: "
                             << packet.type()
                             << endl;
                    }

                    continue;
                }

                /*
                 * 如果服务器返回的 file_id 不为空，
                 * 校验 file_id。
                 */
                if (!packet.file_id().empty() &&
                    packet.file_id() != file_id) {

                    {
                        lock_guard<mutex> lock(menu_lock);

                        cerr << "[DOWNLOAD] file_id 不匹配: "
                             << packet.file_id()
                             << " != "
                             << file_id
                             << endl;
                    }

                    success = false;
                    download_complete = true;

                    break;
                }

                uint64_t packet_offset =
                    packet.offset();

                const string& data =
                    packet.payload();

                /*
                 * =================================================
                 * 判断结束包
                 * =================================================
                 *
                 * 这里约定：
                 *
                 *     FILE
                 *     payload为空
                 *     offset = 最终文件大小
                 *
                 * 表示服务器已经发送完文件。
                 * =================================================
                 */
                if (data.empty()) {

                    if (packet_offset >= local_size) {

                        local_size =
                            static_cast<size_t>(
                                packet_offset
                            );

                        download_complete = true;

                        {
                            lock_guard<mutex> lock(menu_lock);

                            cerr << "[DOWNLOAD] "
                                 << "服务器通知文件发送完成，"
                                 << "size="
                                 << local_size
                                 << endl;
                        }

                        break;
                    }

                    /*
                     * 空数据但是 offset 不合理。
                     */
                    {
                        lock_guard<mutex> lock(menu_lock);

                        cerr << "[DOWNLOAD] "
                             << "收到非法空文件包，offset="
                             << packet_offset
                             << ", local="
                             << local_size
                             << endl;
                    }

                    success = false;
                    download_complete = true;

                    break;
                }

                /*
                 * =================================================
                 * 检查 offset
                 * =================================================
                 */
                if (packet_offset != local_size) {

                    {
                        lock_guard<mutex> lock(menu_lock);

                        cerr << "[DOWNLOAD] 下载偏移不匹配: "
                             << "server="
                             << packet_offset
                             << ", local="
                             << local_size
                             << endl;
                    }

                    success = false;
                    download_complete = true;

                    break;
                }

                /*
                 * =================================================
                 * 写文件
                 * =================================================
                 */
                size_t written_total = 0;

                while (written_total < data.size()) {

                    ssize_t w = write(
                        fd,
                        data.data() + written_total,
                        data.size() - written_total
                    );

                    if (w > 0) {

                        written_total +=
                            static_cast<size_t>(w);

                        continue;
                    }

                    if (w < 0 && errno == EINTR) {
                        continue;
                    }

                    perror("write");

                    success = false;
                    download_complete = true;

                    break;
                }

                if (!success) {
                    break;
                }

                /*
                 * 更新本地 offset。
                 */
                local_size += data.size();

                {
                    lock_guard<mutex> lock(menu_lock);

                    cerr << "[DOWNLOAD] received "
                         << data.size()
                         << " bytes, total="
                         << local_size
                         << endl;
                }
            }

            continue;
        }

        /*
         * ========================================================
         * SSL_read 返回 <= 0
         * ========================================================
         */
        int err = SSL_get_error(ssl2, n);

        if (err == SSL_ERROR_WANT_READ ||
            err == SSL_ERROR_WANT_WRITE) {

            this_thread::yield();
            continue;
        }

        if (err == SSL_ERROR_ZERO_RETURN) {

            /*
             * TLS 正常关闭。
             */
            if (success && download_complete) {
                break;
            }

            {
                lock_guard<mutex> lock(menu_lock);

                cerr << "[DOWNLOAD] "
                     << "服务器关闭 TLS 连接"
                     << endl;
            }

            break;
        }

        {
            lock_guard<mutex> lock(menu_lock);

            cerr << "[DOWNLOAD] SSL_read 失败，error="
                 << err
                 << endl;
        }

        ERR_print_errors_fp(stderr);

        success = false;
        break;
    }

    /*
     * ============================================================
     * 9. 清理
     * ============================================================
     */
    close(fd);

    SSL_shutdown(ssl2);
    SSL_free(ssl2);
    close(file_sock);

    /*
     * ============================================================
     * 10. 最终结果
     * ============================================================
     */
    if (success && download_complete) {

        {
            lock_guard<mutex> lock(menu_lock);

            cerr << "文件下载完成，大小="
                 << local_size
                 << " 字节"
                 << endl;

            cerr.flush();
        }

    } else {

        {
            lock_guard<mutex> lock(menu_lock);

            cerr << "文件下载中断，当前大小="
                 << local_size
                 << " 字节"
                 << endl;

            cerr.flush();
        }
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
            leftover.append(buffer, n);
            std::vector<chat::ChatPacket> packets;
            if (!chat::ExtractPackets(leftover, packets)) {
                cerr << "[PROTO] invalid server frame" << endl;
                serverdisconnect = true;
                break;
            }
            for (const auto& packet : packets) {
                if (packet.type() != chat::ChatPacket::TEXT && packet.type() != chat::ChatPacket::HEARTBEAT) continue;
                std::string line = packet.text();
                if (line.empty() && !packet.payload().empty()) line = packet.payload();
                if (!line.empty() && line.back() == '\r') line.pop_back();

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
    
    // 添加这行：登录成功后显示菜单
    send_menu();  // ← 添加这行
}
                else if (line.find("退出登录成功")!=string::npos) {
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
                else if(line.find("注销成功")!=string::npos||line.find("已被注销")!=string::npos)
                {
                     lock_guard<mutex> lock(state_mtu);
                      logged_in = false;
                       username.clear();
                    cerr<<line<<endl;
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
        size_t pos = 0;
        while((pos = content.find("\\n", pos)) != string::npos) {
            content.replace(pos, 2, "\n");
            pos += 1;
        }
        
        lock_guard<mutex> lock(state_mtu);
        bool is_self = (sender == username);
        string indent;
        if (is_self) {
            indent = string(60, ' ');
        } else {
            indent = "";
        }
        vector<string> lines;
        stringstream ss(content);
        string line;
        while (getline(ss, line, '\n')) {
            lines.push_back(line);
        }
        if (lines.empty()) lines.push_back("");
        for (size_t i = 0; i < lines.size(); ++i) {
            string output;
            if (i == 0) {
                output = sender + ":" + lines[i];
            } else {
                output = lines[i];
            }
            if (!indent.empty()) {
                cout << indent.substr(0, indent.length() - output.length()) << output << endl;
            } else {
                cout << output << endl;
            }
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
                   if(line.find("你")==string::npos)cout << line << "\n";
    {
        lock_guard<mutex> lock(error_mtu);
        send_error_occurred =false;
    }
    {
        lock_guard<mutex> lock(menu_lock);
        menu=true;
    }
}
                else if(line.find("命令完成") != string::npos&&logged_in==true)
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
                else if(line.find("命令完成") != string::npos&&!logged_in==false)
                {             
    bool print=false;
    {
        lock_guard<mutex> lock(upload_mtu);
        if(!is_upload)
        {
            {
                lock_guard<mutex> lock(menu_lock);
                print=menu;
            }
        }
    }
    if(print)
    {
        send_menu();
    }
}
                else if (line.find( "该用户已被注销" )!=string::npos|| line.rfind("注销成功",0)==0) {
                    {
            lock_guard<mutex> lock(close_mtu);
           should_close=true;
                    }
                    {
                        lock_guard<mutex> lock(state_mtu);
                        logged_in=false;
                    }
}
                else if(line.find("你不是群成员")!=string::npos||line.find("不是好友")!=string::npos)
                {
                    send_menu();
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
    cout << "服务器允许下载，开始下载..." << endl;
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
                else if (line.rfind("PONG", 0) == 0||line.rfind("[UPLOAD]",0)==0) 
                {  
                    continue;
                }
                else 
                {
                     size_t pos = 0;
    while((pos = line.find("\\n", pos)) != string::npos)
    {
        line.replace(pos, 2, "\n");
        pos += 1;  
    }
               
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
                 serverdisconnect=true;
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
        if (serverdisconnect) {
        cout << "服务器已断开，自动退出登录。" << endl;
        close(sockfd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    return 0;
    }
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
                /*if(w.find("@163.com")==string::npos)
                {
                    cout<<"请用@163.com邮箱,注册失败\n";
                    continue;
                }*/
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
              /* if(w.find("@163.com")==string::npos)
               {
                cout<<"请使用@163.com邮箱，注册失败\n";
                continue;
               }*/
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
    bool long_send=false;
    string long_buferr;
    wrong=0;
    string target, content;
    cout << "私聊目标用户名: ";
    getline(cin, target);
    if (!get_args(target))
     return 0;

    cout << "请输入消息内容，每行一条，输入 finish 结束,输入/long开启长文本：\n";
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
    send_menu();
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
    if(content=="/long")
        {
            long_send=true;
            long_buferr.clear();
            cerr<<"发长文本，发送/end表示本段结束"<<endl;
            continue;
        }
        if(long_send)
        {
             if(content=="/end")
             {
                long_send=false;
                string result;
                if(!long_buferr.empty())
                {
        for(size_t i=0;i<long_buferr.size();i++)
        {
            if(long_buferr[i]=='\n')
            {
                result+="\\n";
            }
            else
            {
                result+=long_buferr[i];
            }
        }
                    string msg = "私聊 " + target + " " +result + "\n";
                    SSL_write1(ssl,msg.c_str(),msg.size());
                }
                long_buferr.clear();
                cerr<<"长文本发送结束\n";
                continue;
             }
             else
             {
              long_buferr+=content+"\n";
             }
             continue;
        }
        string msg = "私聊 " + target + " " + content + "\n";
        SSL_write1(ssl, msg.c_str(), msg.size());}
        {
        lock_guard<mutex> lock(error_mtu);
        if (send_error_occurred) {
            {
                send_error_occurred=false;
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
               string n;
               cout<<"拉入群聊name:";
               getline(cin,n);
               string msg = "创建群聊 " + u +n+ "\n";
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
    cout << "请输入消息内容，每行一条，输入 finish 结束,/long为长文本模式：\n";
    int blank_count = 0;  
    {
        lock_guard<mutex> lock(menu_lock);
        menu=false;
    }
     bool long_send=false;
     string long_buffer;
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
    if (content != "finish") 
    {
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
        if(content=="/long")
        {
            long_send=true;
            continue;
        }
        if(long_send)
        {
            if(content=="/end")
            {
                long_send=false;
                if(!long_buffer.empty())
                {
                    string result;
                    for(char ch:long_buffer)
                    {
                        if(ch=='\n')
                        {
                            result+="\\n";
                        }
                        else
                        {
                            result+=ch;
                        }
                    }
                     string msg = "群聊 " + target + " " + result + "\n";
                    SSL_write1(ssl, msg.c_str(), msg.size());
                }
                long_buffer.clear();
                cerr<<"长文本发送结束"<<endl;
                continue;
            }
            else
            {
                long_buffer+=content+"\n";
                continue;
            }
        }
        else
        {
            string msg = "群聊 " + target + " " + content + "\n";
        SSL_write1(ssl, msg.c_str(), msg.size());}
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
            else if(cmd_name=="40")
            {
                wrong=0;
              string u;
              cout<<"查看群聊天记录,name:\n";
              getline(cin,u);
              if(!get_args(u))
               {
                return 0;
               }
                string msg="查看群聊天记录 "+u+"\n";
                
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
            else if (cmd_name == "41") 
            {
                {
                    lock_guard<mutex> lock(upload_mtu);
                    is_upload=true;
                }
                
                wrong=0;
             
    string target ,filepath;
    cout<<"上传群文件,targetname:\n";
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
  
    string cmd = "UPLOAD_GROUP_FILE " + target + " " + filename + " " + to_string(filesize) + "\n";
  SSL_write1(ssl, cmd.c_str(),cmd.size());

    cout << "文件上传请求已发送，等待服务端响应...\n";
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