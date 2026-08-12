#ifndef FILE_TRANSFER_H
#define FILE_TRANSFER_H

#include <string>
#include <vector>
#include <map>
#include <hiredis/hiredis.h>
#include <leveldb/db.h>
using namespace std;

// file_transfer.h
enum ParseState {
    PARSE_HEADER,   // 正在读取长度头（4字节）
    PARSE_BODY      // 正在读取包体
};
enum DownloadState { DOWNLOAD_IDLE, DOWNLOAD_SENDING };
struct FILETRANSFER {
    string file_id;           // 当前正在传输的文件ID
    string tmp_path;          // 临时文件路径
    int tmp_fd;               // 临时文件描述符

    // 状态机字段
    ParseState state;         // 当前解析状态
    uint32_t header_bytes;    // 已读取的头部字节数 (0-4)
    uint32_t total_len;       // 包总长度（从头部解析得到）
    vector<char> buffer;      // 存储已读数据（包括头部+部分包体）
     DownloadState download_state;   // IDLE 或 SENDING
    int download_file_fd;           // 正在发送的文件描述符
    uint64_t download_offset;       // 起始偏移（保留，用于后续可能的重试）
    size_t total_sent;              // 已发送总字节数
    vector<char> download_chunk;    // 当前分片数据
    size_t chunk_sent;              // 当前分片已发送字节数
};
extern std::map<std::string, std::string> filename_to_file_id;
extern map<int,FILETRANSFER> file_contexts;
// 获得原始文件名
string get_filename_meta(const string& file_id, redisContext* redis);
// 检查权限（接收者或群成员）
bool is_target(int fd, redisContext* redis, const string& file_id, const string& name);
// 获取文件大小
long long get_file_size(const string& file_id, redisContext* redis);

// 通知接收方文件准备完成
void notify_reciver(redisContext* redis, const string& file_id);
// 初始化文件传输模块（创建目录、加载待通知等）
void init_file_transfer(redisContext* redis);
// 处理文件传输命令
void handle_file_command(redisContext* redis, int fd, const string& sender, const string& target, const string& filename, size_t Size);
// 处理文件传输端口（8889）的二进制数据
void on_file_data(int fd, redisContext* redis);
// 文件传输连接的建立和关闭回调（由 epoll 事件循环调用）
void on_file_connection(int fd, bool connected);
// 清理资源（可选）
void cleanup_file_transfer(redisContext* redis);
// 断点续传
void Resend_file(int fd, const string& sender, const string& filename, redisContext* redis);
// 下载文件
void download_file(int fd, const string& file_id, const string& filepath);

#endif