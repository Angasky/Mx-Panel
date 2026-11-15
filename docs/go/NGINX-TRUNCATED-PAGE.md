# 页面一直加载：Nginx 截断响应

## 原因

2026-11-15 的实际故障并非账号验证过慢。Go 源站返回完整 660598 字节 HTML，公网只收到约 459 KB，主脚本缺少尾部，启动和超时逻辑都无法执行。Nginx 错误日志出现代理临时目录 `Permission denied`；目录属主 nobody，系统服务工作进程使用 www-data。该机还有其他 Nginx 实例，可能重复初始化共享的编译默认目录。

## v0.3.3 发布包处理

新安装和 `mx-p` 升级都会运行检测。不要求服务器必须安装 Nginx；内置 HTTPS 网关不涉及此故障。

仅在系统 nginx.service 运行、有效配置代理到本面板 127.0.0.1:62578、编译临时路径为 /var/lib/nginx/proxy、没有显式自定义 proxy_temp_path，且系统服务实际非 root 工作进程 UID/GID 唯一时，修复该目录属主。拒绝符号链接及非预期真实路径。不递归修改子目录，不更改权限位，不重启 Nginx。

无法识别的自定义配置会提示人工检查，不能保证所有 Nginx/OpenResty/容器部署都自动修复。其他实例以后仍可能重设共享目录，因此配置示例同时增加 `proxy_max_temp_file_size 0;`。

## 其他用户恢复

1. SSH 执行 `mx-p`，更新到 v0.3.3 或更新版本。即使网页不能打开，终端更新仍可用。
2. 在 Nginx 中代理本面板的每个 `location` 中加入：

```nginx
proxy_max_temp_file_size 0;
```

该项禁用代理响应写入临时磁盘，保留内存缓冲与客户端背压。不要配置成 `proxy_max_temp_file_size` 的其他正数来尝试修权限。

3. 执行 `nginx -t`，成功后 `systemctl reload nginx`。自定义容器或多实例须使用对应配置和重载命令。
4. 刷新页面；检查错误日志没有新增 Permission denied，并从公网确认 HTML 有完整的 `</html>` 尾部和可运行的登录页。只测试源站 healthz 或 HEAD 不足以发现截断。

不要盲目 chmod 777 或递归 chown 整个 Nginx 数据目录。

当前站点已修复属主，并仅在面板反代 location 加入不落盘配置。公网 HTML（剔除 Cloudflare 注入的验证脚本）与源文件一致，两份字体逐字节一致，真实 Chromium 经公网进入登录页且无页面脚本错误。

隔离真实 Nginx 故障复现：将临时目录改为 worker 不可访问，限速响应仅收到 1690 字节且 curl 返回 18；设置 proxy_max_temp_file_size 0 后，在临时目录依然不可访问时完整收到 660598 字节，与源文件一致。未对生产目录注入故障。
