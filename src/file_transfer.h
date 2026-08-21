#ifndef FILE_TRANSFER_H
#define FILE_TRANSFER_H

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <cstdint>
#include <hiredis/hiredis.h>
#include <leveldb/db.h>
using namespace std;

enum ParseState {
    PARSE_HEADER,
    PARSE_BODY
};

enum DownloadState {
    DOWNLOAD_IDLE,
    DOWNLOAD_SENDING
};

struct FILETRANSFER {
    string file_id;
    string tmp_path;
    int tmp_fd = -1;
    uint64_t  upload_offset=0;
    ParseState state = PARSE_HEADER;
    uint32_t header_bytes = 0;
    uint32_t total_len = 0;
    vector<char> buffer;
    DownloadState download_state = DOWNLOAD_IDLE;
    int download_file_fd = -1;
    uint64_t download_offset = 0;
    size_t total_sent = 0;
    vector<char> download_chunk;
    size_t chunk_sent = 0;
    bool file_read_done=false;
    uint64_t filesize=0;
    string status;
};

extern std::map<std::string, std::string> filename_to_file_id;
extern map<int,FILETRANSFER> file_contexts;
extern std::recursive_mutex file_mutex;

string get_filename_meta(const string& file_id, redisContext* redis);
bool is_target(int fd, redisContext* redis, const string& file_id, const string& name);
long long get_file_size(const string& file_id, redisContext* redis);
void notify_reciver(redisContext* redis, const string& file_id);
void init_file_transfer(redisContext* redis);
void handle_file_command(redisContext* redis, int fd, const string& sender, const string& target, const string& filename, size_t Size);
void on_file_data(int fd, redisContext* redis);
void on_file_connection(int fd, bool connected);
void cleanup_file_transfer(redisContext* redis);
void Resend_file(int fd, const string& sender, const string& filename, redisContext* redis);
void download_file(int fd, const string& file_id, const string& filepath);

#endif
