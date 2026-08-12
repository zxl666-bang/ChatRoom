**磁盘存储**
**写多读少**
全局变量
```
leveidb::DB*history_db=nullptr;
```
结构体Option
## LevelDB `Options` 结构体成员变量

| 成员变量 | 类型 | 默认值 | 作用 |
|----------|------|--------|------|
| `create_if_missing` | `bool` | `false` | 数据库目录不存在时是否自动创建 |
| `error_if_exists` | `bool` | `false` | 数据库已存在时是否报错 |
| `write_buffer_size` | `size_t` | `4MB` | 内存写入缓冲区大小，越大写入性能越好 |
| `max_open_files` | `int` | `1000` | 最大打开文件数，限制资源占用 |
| `block_cache` | `Cache*` | `nullptr` | 数据块缓存（提升读取性能） |
| `block_size` | `size_t` | `4096` | 数据块大小（影响读写粒度） |
| `compression` | `CompressionType` | `kSnappyCompression` | 压缩算法（`kNoCompression` 或 `kSnappyCompression`） |
| `filter_policy` | `const FilterPolicy*` | `nullptr` | 布隆过滤器（加速 `Get` 查询） |
| `paranoid_checks` | `bool` | `false` | 每次读取时校验数据完整性 |
| `log_level` | `LogLevel` | `kInfoLogLevel` | 日志级别 |
| `info_log` | `Logger*` | `nullptr` | 日志输出目标（默认 `stderr`） |
| `env` | `Env*` | `nullptr` | 操作系统环境接口（用于文件 I/O） |