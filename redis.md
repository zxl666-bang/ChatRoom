# REDIS
## 作用:
- 用于数据存储，实现数据的长时间存储和快速读取
## 数据结构
1. HASH（哈希表）
* 是什么：类似 C++ 里的 std::unordered_map<string, string>，是一个键值对集合。

* 如何存储：一个 key（如 user:alice）对应多个 field-value 对。

示例：
```
HSET user:alice password "e10adc..."

HSET user:alice nickname "Alice"
```
常用命令：
```cpp
HSET key field value：设置一个字段

HGET key field：获取一个字段

HGETALL key：获取所有字段和值
```
* 在聊天室项目中的用途：存储用户的多个属性（密码、昵称、邮箱等），避免创建多个单独的 key。

2. EX（过期时间）
* 是什么：EX 是 Redis 中 SET 命令的一个选项，用于设置 key 的过期时间（秒）。

示例：
```
SET online:alice 1 EX 60
```
* 表示 key online:alice 将在 60 秒后自动被删除。

* 在聊天室中的用途：实现自动离线。客户端定时发送心跳，服务器刷新过期时间；若客户端不发送心跳，60 秒后 key 消失，表示用户离线。

相关命令：
```
TTL key：查看剩余生存时间（秒）

PERSIST key：移除过期时间
```
3. SET（集合）
* 是什么：无序的、不重复的字符串集合。类似于 C++ 的 std::unordered_set<string>。

* 特点：支持快速的添加、删除、判断是否存在、求交集、并集等。

常用命令：
```
SADD key member：添加元素

SREM key member：删除元素

SMEMBERS key：返回所有元素

SISMEMBER key member：判断是否存在
```
* 在聊天室项目中的用途：

* 存储好友列表：friends:alice 包含 bob, charlie

* 存储群组成员：group:123:members 包含用户列表

4. LIST（列表）
* 是什么：有序的字符串列表，允许重复元素。类似 C++ 的 std::list<string>。

* 特点：可以在头部或尾部添加/弹出元素，非常适合做消息队列。

常用命令：
```
RPUSH key value：在列表尾部添加元素

LPOP key：移除并返回头部元素

LRANGE key start stop：返回指定范围内的元素
```
* 在聊天室项目中的用途：

* 离线消息暂存：当用户不在线时，将消息 RPUSH 进 offline:接收者 列表；用户上线后 LPOP 或 LRANGE 取出所有消息。

* 历史消息（最近几条）：可用 LPUSH + LTRIM 限制长度。

## 流程
1. 确定存储对象
2. 根据存储对象确定数据结构
* 用户账号：一个用户有多个属性（密码、昵称、邮箱），用 Hash 最合适。

* 在线状态：只是一个标志（1/0）加上过期时间，用 String 带 EX 秒数。

* 好友关系：无序、不重复、支持快速增删查，用 Set。

* 离线消息：按时间顺序存储，之后依次取出，用 List。
3. 设计key的命名逻辑
* 对象类型：唯一标识
```cpp
user:alice;
online:alice;
friends:alice;
offline:alice;
```
这样就可以在redis_cil里用
```
KEY user:*
```
查看用户
4. 定义每个key下的具体内容
* 通用：
```cpp
KEYS pattern:查看所有符合给定模式的key;
DEL key:删除key；
EXISTS key:查看key是否存在;只支持上传一个%s
EXPIRE key seconds:设置有效期限;
TTL key:查看剩余有效期限;
```
* String:
```cpp
SET key value;设置一个键值对
GET key：获取key的value;
INCR key：将key的value+1；
MSET key1 value1[key2 value2......]：批量设置;
```
* Hash:
```cpp
HSET key field value:设置哈希表中的某个字段
HGET key field:获取哈希表中的某个字段
HGETALL key：获取key后的所有field和value
```
* List
```cpp
LPUSH key value [value...]	:将一个或多个值插入到列表头部	
RPUSH key value [value...]	:将一个或多个值插入到列表尾部	
LRANGE key start stop	:获取列表中指定范围的元素	
LPOP / RPOP key:	移除并返回列表的头/尾元素	
```
* Set
```cpp
SADD key member [member...];	向集合中添加元素	
SREM key member [member...];	从集合中删除元素	
SISMEMBER key member;	判断元素是否在集合中	
SMEMBERS key;	获取集合中的所有元素	
```
## 代码
1. CMakeLists.txt:
```cpp
find_library(HIREDIS_LIB hiredis REQUIRED)
target_link_libraries(chat_server ${HIREDIS_LIB} pthread)
```
2. 建立连接：
```
redisContext*redisConnect(const char*ip,int port);
```
* ip:redis所在服务器ip，默认“127.0.1"
* port:redis所在端口,默认6379
* 返回值：redisContext指针，连接上下文，后续命令要链接他
3. 初始化
```cpp
redisContext*redis_conn=nullprt;
redis_conn=redisConnect("127.0.1",6379);
redis_conn == nullptr：内存分配失败（极少数情况）。

redis_conn->err：连接建立时发生网络错误（比如 Redis 没启动、IP/端口错误）。

调用 redisFree 清理失败的连接，避免资源泄漏
```
4. 发送命令并接收回复
```cpp
//以登陆为例
bool void(const string&username,const string&password)
{
      string key="user:"+username;
      redisReply*reply=redisCommand(redis_conn,"HGET %s password",key.c_str());
      if(reply==nullprt)
      return false;
      if(reply->type!=REDIS_REPLY_STRING)
      {
        freeRelpyObject(reply);
        return false;
      }
      string pass=reply->str;
      return password==pass;
}
```
5. 释放连接
```cpp
if (redis_conn) {
    redisFree(redis_conn);
    redis_conn = nullptr;
}
```
## reply的返回类型

| 常量名 | 数值 | 含义 | 典型命令示例 |
| :--- | :--- | :--- | :--- |
| `REDIS_REPLY_STRING` | 1 | 字符串值 | `GET`, `HGET` |
| `REDIS_REPLY_ARRAY` | 2 | 数组（多元素） | `SMEMBERS`, `LRANGE`, `HGETALL` |
| `REDIS_REPLY_INTEGER` | 3 | 整数（长整型） | `EXISTS`, `SADD`, `INCR`, `SISMEMBER` |
| `REDIS_REPLY_NIL` | 4 | 空值（null） | `GET` 不存在的键 |
| `REDIS_REPLY_STATUS` | 5 | 状态字符串（如 "OK"） | `SET`, `HSET`, `AUTH` |
| `REDIS_REPLY_ERROR` | 6 | 错误信息 | 语法错误、类型错误 |
| `REDIS_REPLY_DOUBLE` | 7 | 双精度浮点数（RESP3） | `ZSCORE`（特定场景） |
| `REDIS_REPLY_BOOL` | 8 | 布尔值（RESP3） | 需显式启用 RESP3 |
| `REDIS_REPLY_MAP` | 9 | 键值对集合（RESP3） | `HGETALL`（RESP3 模式） |
| `REDIS_REPLY_SET` | 10 | 无序集合（RESP3） | `SMEMBERS`（RESP3 模式） |
| `REDIS_REPLY_ATTR` | 11 | 属性数据（RESP3） | 较少见 |
| `REDIS_REPLY_PUSH` | 12 | 推送消息（Pub/Sub） | `SUBSCRIBE` 收到的消息 |
| `REDIS_REPLY_BIGNUM` | 13 | 大整数（RESP3） | `GET` 超大数值 |
| `REDIS_REPLY_VERB` | 14 | 格式化字符串（RESP3） | 较少见 |