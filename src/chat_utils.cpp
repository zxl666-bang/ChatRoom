// chat_utils.cpp
#include "chat_utils.h"
#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <unistd.h>  
#include <iostream>

namespace chat {

bool ReadPacket(SSL* ssl, ChatPacket& packet) {
    // 读取长度头 (4字节)
    uint32_t net_len;
    int bytes_read = 0;
    while (bytes_read < 4) {
        int n = SSL_read(ssl, reinterpret_cast<char*>(&net_len) + bytes_read, 4 - bytes_read);
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                return false;  // 需要等待更多数据
            }
            return false;  // 错误
        }
        bytes_read += n;
    }
    
    uint32_t len = ntohl(net_len);
    if (len > 100 * 1024 * 1024) {  // 最大100MB
        std::cerr << "Packet too large: " << len << std::endl;
        return false;
    }
    
    // 读取数据体
    std::string data;
    data.resize(len);
    bytes_read = 0;
    while (bytes_read < static_cast<int>(len)) {
        int n = SSL_read(ssl, &data[bytes_read], len - bytes_read);
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                return false;
            }
            return false;
        }
        bytes_read += n;
    }
    
    // 解析 protobuf
    return packet.ParseFromString(data);
}

bool ExtractPackets(std::string& buffer, std::vector<ChatPacket>& packets, size_t max_size) {
    while (buffer.size() >= 4) {
        uint32_t net_len;
        memcpy(&net_len, buffer.data(), 4);
        uint32_t len = ntohl(net_len);
        
        if (len > max_size || len > 100 * 1024 * 1024) {
            std::cerr << "[ExtractPackets] packet too large: " << len << std::endl;
            return false;
        }
        
        if (buffer.size() < 4 + len) {
            break;  // 数据不完整
        }
        
        ChatPacket packet;
        if (packet.ParseFromArray(buffer.data() + 4, len)) {
            packets.push_back(std::move(packet));
            buffer.erase(0, 4 + len);
        } else {
            std::cerr << "[ExtractPackets] parse failed" << std::endl;
            return false;
        }
    }
    return true;
}

bool SendPacket(int fd, const ChatPacket& packet) {
    std::string data;
    if (!packet.SerializeToString(&data)) {
        std::cerr << "Serialize packet failed" << std::endl;
        return false;
    }
    
    uint32_t net_len = htonl(static_cast<uint32_t>(data.size()));
    
    // 发送长度头
    if (write(fd, &net_len, 4) != 4) {
        return false;
    }
    
    // 发送数据
    size_t sent = 0;
    while (sent < data.size()) {
        ssize_t n = write(fd, data.data() + sent, data.size() - sent);
        if (n <= 0) {
            return false;
        }
        sent += n;
    }
    
    return true;
}

} // namespace chat