Golang 版本的探针客户端

## 项目介绍
云探针 是一款服务器状态监控工具，本项目是其 Golang 版本的客户端，支持普通服务器。相比原版 Python 客户端，该版本无需依赖 Python 运行环境，使得部署更加轻量、高效。

## 使用教程

普通服务器的使用方法与原版 Python 脚本基本一致，只是由脚本换成了本项目的可执行文件。

```bash
./serverstatus-client -server 12.1.1.1 -user s01
```

更多详情请参考 [ServerStatus](https://github.com/cppla/ServerStatus) 项目。

