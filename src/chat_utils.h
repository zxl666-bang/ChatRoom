// chat_utils.h
#ifndef CHAT_UTILS_H
#define CHAT_UTILS_H
#include <openssl/ssl.h> 
#include <string>
#include <vector>
#include "chat.pb.h"

namespace chat {
    // 读取一个完整的 ChatPacket
    bool ReadPacket(SSL* ssl, ChatPacket& packet);
    
    // 从缓冲区提取所有完整的 ChatPacket
    bool ExtractPackets(std::string& buffer, std::vector<ChatPacket>& packets, size_t max_size = 8 * 1024 * 1024);
    
    // 发送 ChatPacket
    bool SendPacket(int fd, const ChatPacket& packet);
}

#endif // CHAT_UTILS_H