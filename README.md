# 基于C++与TLS的IM即时通讯聊天室

## 项目简介
这是一个基于C++17的终端IM（即时通讯）系统，支持**TLS加密通信**、**好友/群组管理**、**文件传输（支持断点续传）**、**离线消息**与**历史记录查询**。

## 主要功能

### 用户与安全
- **注册/登录**：支持密码登录和邮箱验证码登录。
- **安全通信**：全链路使用OpenSSL进行TLS加密。
- **数据安全**：用户密码使用SHA256+盐值哈希存储。

### 社交功能
- **好友管理**：添加、删除、屏蔽、解除屏蔽好友，好友申请审批。
- **群组管理**：创建、解散、加入（需审批）、退出群聊；支持设置/删除管理员。

### 通信功能
- **私聊**：支持与在线或离线好友进行一对一私聊，支持长文本发送。
- **群聊**：支持多人群聊，群成员均可收发消息。
- **历史记录**：私聊和群聊记录持久化到LevelDB，可随时查询最近200条。

### 文件传输
- **发送文件**：支持向好友或群发送文件。
- **下载文件**：收到文件通知后，可随时下载。
- **断点续传**：支持上传和下载过程中的断点续传。

## 快速开始

### 依赖安装（Ubuntu）
```bash
OpenSSL	TLS加密	sudo apt install libssl-dev
hiredis	Redis客户端	sudo apt install libhiredis-dev
leveldb	历史记录存储	sudo apt install librocksdb-dev 或 sudo apt install libleveldb-dev
MySQL Client	用户数据存储	sudo apt install libmysqlclient-dev
libcurl	发送邮件验证码	sudo apt install libcurl4-openssl-dev
MySQL Server	数据库服务	sudo apt install mysql-server
Redis Server	缓存服务	sudo apt install redis-server
```
## 配置数据库

### MySQL：创建数据库chat_db和用户chat_user。
```bash
sql
CREATE DATABASE chat_db;
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    password_hash VARCHAR(128) NOT NULL,
    email VARCHAR(128) UNIQUE NOT NULL
);
```
### Redis：安装并启动redis-server。

### LevelDB：程序启动时会自动创建history_db目录

## 生成SSL证书
```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
```

## 编译
``` bash
# 编译服务端
g++ -std=c++17 -pthread -o chat_server server.cpp file_transfer.cpp send_email.cpp -lssl -lcrypto -lhiredis -lleveldb -lmysqlclient -lcurl
# 编译客户端
g++ -std=c++17 -pthread -o chat_client client.cpp -lssl -lcrypto

# 启动服务端
./chat_server

# 启动客户端（连接服务器IP）
./chat_client 127.0.0.1 8888
```

## 命令
```bash
==========登陆前============
/1;发送验证码
/2;验证码注册(需要先发送/1发送验证码后操作）
/3;验证码登录(需要先发送/1发送验证码后操作）
/31;密码登录
/35;普通注册
/4;//忘记密码
/33;//退出
/34;//注销
==========登陆后============
================好友操作=============================
/5 添加好友     /6 列出好友申请
/7 同意好友申请/8 拒绝好友申请
/9 好友列表     /10 私聊          
/11 屏蔽好友    /12 解除屏蔽    
/29 删除好友    /28 查看历史记录
================群聊操作=============================
/13 申请加入群聊/14 退出群聊    
/15 群聊          /16 创建群聊    
/17 查看群成员 /18 查看自己的群聊
/19 查看群申请 /20 同意加群申请
/21 拒绝加群申请/22 删除群成员 
/23 设置管理员 /24 删除管理员 
/40 查看群聊天记录
/25 解散群聊
================文件操作=============================
/38 列出文件/30 手动续传    
/27 下载文件    /26 发送文件    
/41 发送群文件
================其他操作=============================
/32 读取未读消息/36 退出登录    
/37 列出命令目录
====================================================
```
## 项目架构
### 服务端：Reactor模式（epoll）+ 线程池处理业务。

### 客户端：主线程处理输入，子线程接收消息。

### 加密：OpenSSL提供的TLS 1.3/1.2。

### 存储：

Redis：缓存在线状态、离线消息、关系链。

MySQL：用户账号数据。

LevelDB：聊天历史记录。
