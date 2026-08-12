MySQL 在聊天室项目中的完整操作指南
本指南涵盖从安装、启动、用户管理、数据库/表创建到远程连接配置的完整流程，适用于 Ubuntu/Debian 系统。

1. 安装 MySQL
```
sudo apt update
sudo apt install mysql-server -y
```
检查是否安装成功：

```
mysql --version
which mysql   # 通常输出 /usr/bin/mysql
```
1. MySQL 服务管理
```
操作	命令
启动服务	sudo systemctl start mysql
停止服务	sudo systemctl stop mysql
重启服务	sudo systemctl restart mysql
查看状态	sudo systemctl status mysql
开机自启	sudo systemctl enable mysql
禁止自启	sudo systemctl disable mysql
```
1. 登录 MySQL
3.1 使用 root 用户
```
sudo mysql -u root -p
```
输入 root 密码后进入 MySQL 命令行。

3.2 使用自定义用户（如 chat_user）
```
mysql -u chat_user -p -h 127.0.0.1 chat_db
```
-h 指定主机，127.0.0.1 为本地。
chat_db 为默认数据库（可选），登录后自动切换。

1. 创建数据库
4.1 创建数据库（推荐字符集）
```
CREATE DATABASE 数据库名 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```
参数说明：

参数	含义
CHARACTER SET utf8mb4	支持全部 Unicode 字符（含 Emoji）
COLLATE utf8mb4_unicode_ci	排序规则：不区分大小写，按 Unicode 标准排序
4.2 查看所有数据库
sql
SHOW DATABASES;
4.3 切换数据库
sql
USE 数据库名;
1. 创建表（以用户表为例）
```
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    password_hash VARCHAR(64) NOT NULL,
    email VARCHAR(128) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```
字段说明：

字段	类型	约束	说明
id	INT	AUTO_INCREMENT, PRIMARY KEY	自增主键
username	VARCHAR(64)	UNIQUE, NOT NULL	用户名，唯一
password_hash	VARCHAR(64)	NOT NULL	SHA256 哈希值（64字符）
email	VARCHAR(128)	UNIQUE, NOT NULL	邮箱，唯一
created_at	TIMESTAMP	DEFAULT CURRENT_TIMESTAMP	注册时间，自动填充
5.1 查看表结构
sql
DESCRIBE 表名;
5.2 查看所有表
sql
SHOW TABLES;
1. 用户管理与授权
6.1 创建用户
sql
CREATE USER '用户名'@'主机' IDENTIFIED BY '密码';
主机值常用示例：

主机值	含义
'localhost'	仅允许本机连接
'%'	允许任意主机连接（不推荐生产环境）
'192.168.1.%'	允许 192.168.1.x 网段
'192.168.1.100'	只允许特定 IP
6.2 授予权限
sql
GRANT ALL PRIVILEGES ON 数据库名.* TO '用户名'@'主机';
ALL PRIVILEGES 可替换为 SELECT, INSERT, UPDATE 等细粒度权限。

数据库名.* 表示该数据库下的所有表。

6.3 刷新权限
sql
FLUSH PRIVILEGES;
6.4 查看现有用户
sql
SELECT user, host FROM mysql.user;
6.5 修改用户密码
sql
ALTER USER '用户名'@'主机' IDENTIFIED BY '新密码';
6.6 删除用户
sql
DROP USER '用户名'@'主机';
7. 远程连接配置（若需要）
如果 MySQL 与应用程序（聊天室服务端）不在同一台机器，需允许远程连接。

7.1 创建支持远程的用户
sql
CREATE USER 'chat_user'@'%' IDENTIFIED BY '强密码';
GRANT ALL PRIVILEGES ON chat_db.* TO 'chat_user'@'%';
FLUSH PRIVILEGES;
7.2 修改 MySQL 配置文件
编辑 /etc/mysql/mysql.conf.d/mysqld.cnf，将 bind-address 改为：

ini
bind-address = 0.0.0.0
重启服务：

bash
sudo systemctl restart mysql
7.3 防火墙放行端口
bash
sudo ufw allow 3306
若使用云服务商，还需在安全组规则中开放 3306 端口。

7.4 在 C++ 中连接远程 MySQL
cpp
mysql_real_connect(mysql_conn, "远程IP", "chat_user", "密码", "chat_db", 3306, nullptr, 0);
8. 常用命令速查表
操作	SQL 命令
创建数据库	CREATE DATABASE db_name CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
删除数据库	DROP DATABASE db_name;
切换数据库	USE db_name;
创建表	CREATE TABLE table_name (...);
删除表	DROP TABLE table_name;
查看表结构	DESCRIBE table_name;
查看所有表	SHOW TABLES;
查看所有数据库	SHOW DATABASES;
创建用户	CREATE USER 'user'@'host' IDENTIFIED BY 'password';
授予权限	GRANT ALL ON db.* TO 'user'@'host';
刷新权限	FLUSH PRIVILEGES;
退出 MySQL	EXIT;
9. 常见错误排查
错误现象	可能原因	解决方法
Access denied	用户名/密码错误	检查凭据，或用 root 重置密码
Can't connect to MySQL server	服务未启动/防火墙/绑定地址	启动服务，检查 bind-address，开放端口
Unknown database	数据库不存在	先用 CREATE DATABASE 创建
ERROR 1045	认证失败	确认用户主机值匹配（如 'localhost' vs '%'）
mysql: command not found	MySQL 未安装	执行 sudo apt install mysql-server
10. 您的聊天室项目当前配置
数据库：chat_db

用户：chat_user@localhost（密码 chat123456）

表：users（含 username, password_hash, email）

连接参数（C++）：

cpp
mysql_real_connect(mysql_conn, "127.0.0.1", "chat_user", "chat123456", "chat_db", 3306, nullptr, 0);
11. 后续步骤
在 C++ 中修改用户相关函数（user_exists, regiser_user, authenticate, is_email, findpassword）改用 MySQL。

其他功能（好友、群组、申请）仍保留 Redis，无需迁移。

如需部署到其他机器，按“远程连接配置”设置。

