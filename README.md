# LDN Relay Web UI

为 dogty/ldn_mitm 的免电脑 UDP 中继添加中文管理页面。Python **3.8+**，仅使用标准库，无须 pip 或 Node.js。

功能：密码登录、游戏房间列表、房主与成员名称、当前主机数/主机上限、已加入主机数、在线客户端、真实流量图、事件日志、可选 IP/CIDR 白名单。房间从 LANDiscovery 广播解析，绝不以中继在线数冒充房间人数。协议数据只能说明房主广播的成员快照，不能证明实际游戏已顺利运行。

游戏通信标识（LCID）不保证等于 Title ID；首次显示“未知游戏”，管理员可在房间卡片点“标注游戏”保存名称，下次同标识自动使用该名称。自定义游戏房间名不做猜测。人数是联网主机/节点数，含房主，不是同机玩家数。房间超过 30 秒无广播即从列表移除（网页下次刷新生效）。客户端 60 秒无流量后从列表移除。

统计、房间快照、日志、登录会话在内存中，重启清零。只有游戏名称映射持久保存。网页不提供修改监听端口、客户端白名单或重启服务；这些仍通过环境变量及 systemd/Docker 管理。

### 转发与页面解析分离

中继先处理并转发数据包，再把广播交给独立解析线程。转发线程不解压、不重组房间分片，也不等待页面名称文件写入。普通 IPv4 游戏流量通过端口头快速过滤；分片在后台检查。观察队列最多 128 包，满时只丢弃统计观察副本，排队超过 5 秒的样本也丢弃，不丢弃原中继包。

解析异常仅增加 `room_observer.errors`，不会终止转发。`/api/status` 的 `room_observer` 包含队列长度和丢弃计数。若解析器正忙，页面使用上一份房间快照，下次刷新重试。线程仍共享同一 Python 进程和 CPU/GIL，不承诺零额外耗时；没有做过公网实机延迟基准。

## 快速启动

```bash
git clone https://github.com/VegetableManII/ldn_mitm_webui.git
cd ldn_mitm_webui
python3 --version
read -rsp '管理密码（至少12位）: ' ADMIN_PASSWORD; echo
export ADMIN_PASSWORD
export RELAY_PORT=11544
python3 -u app.py
```

管理页面默认监听 `0.0.0.0:8080`，可用服务器公网 IP 访问。需要在云安全组放行 **TCP 8080**（建议只允许管理者 IP）；游戏中继另行放行 **UDP 11544**。网页仍需管理密码，长期使用建议配置 HTTPS。

如果希望管理页面只走 SSH 隧道，将 `WEB_BIND=127.0.0.1`，然后在你自己的电脑开隧道（保持窗口运行）：

```bash
ssh -N -L 8080:127.0.0.1:8080 你的SSH用户名@服务器公网IP
```

然后在电脑浏览器访问 http://localhost:8080，用刚设置的密码登录。无需开放管理页面的公网端口。

### 在手机或公网访问页面

使用 Nginx/Caddy 为 `127.0.0.1:8080` 配置 HTTPS 反向代理，设置 `COOKIE_SECURE=1` 后重启应用。不要将明文 HTTP 登录页直接暴露到互联网。反向代理需保留浏览器原始 Host，应用不信任任意客户端提供的 X-Forwarded-* 头。限制请求体大小、连接数和登录请求速率。登录失败限制基于直连地址，因此反代下不同用户会共享同一个限制。

## Switch 设置

两台 Switch 都使用兼容其 Atmosphere 的免电脑 ldn 分支。将以下行加入 `config/ldn_mitm/relay.cfg`：

```text
my-server 服务器公网IPv4:11544
```

选择此服务器，开启 Enabled / Broadcast relay / Internet relay；IP 与 DNS 自动，MTU 1500。协议内部发现端口 11452 不要修改。两台跨网络测试，游戏版本保持一致。此网页项目不会解决插件与 AMS 的兼容问题。

## 防止别人使用服务器

**改变端口和管理页密码都不是 UDP 中继认证。** 原协议没有密码。可在云安全组只允许你们双方公网 IP，或使用应用白名单：

```bash
export ALLOWED_CLIENTS="你家公网IP/32,她家公网IP/32"
```

支持 IPv4 CIDR；空值允许所有客户端。家用公网 IP 变化后需要更新并重启。不要填 Switch 的局域网 IP 或中继虚拟 IP。使用移动网络时也可能有共享或变化的出口 IP。页面显示因应用白名单拒绝的包数，云防火墙在应用前丢弃的包不会计入。

## 配置

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `ADMIN_PASSWORD` | 无 | 必填，至少 12 位，管理页面密码 |
| `RELAY_PORT` | `11544` | 公网 UDP 中继端口 |
| `WEB_BIND` | `0.0.0.0` | 管理页面绑定地址；仅 SSH 隧道访问时设为 `127.0.0.1` |
| `WEB_PORT` | `8080` | 管理页面 TCP 端口 |
| `ALLOWED_CLIENTS` | 空 | 允许使用中继的公网 IP/CIDR，逗号分隔 |
| `COOKIE_SECURE` | `0` | HTTPS 反代访问设 `1`，SSH 隧道 HTTP 保持 `0` |
| `GAME_NAMES_FILE` | `data/game_names.json` | 管理员标注的游戏名称映射文件；服务账户需拥有目录写权限 |

程序不会自动读取 `.env`；systemd 通过 EnvironmentFile 加载，Docker Compose 会读取项目 `.env`。

## Ubuntu/Debian 开机自启

需要 Python 3.8+（例如 Ubuntu 20.04/22.04/24.04）。在 `/opt/ldn-relay-admin` 放置完整项目。

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin ldn-relay
sudo install -m 600 .env.example /etc/ldn-relay-admin.env
sudo nano /etc/ldn-relay-admin.env
# 填写强密码和可选白名单
sudo install -m 644 deploy/ldn-relay-admin.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ldn-relay-admin
sudo systemctl status ldn-relay-admin
sudo journalctl -u ldn-relay-admin -f
```

项目文件需要允许 ldn-relay 用户读取。如果用户名已存在，不再执行 useradd。使用 UFW 的服务器可执行 `sudo ufw allow 11544/udp`；同时配置云平台安全组。不要在尚未放行 SSH 时直接开启 UFW。

### 从旧版本更新

旧 systemd 服务启用了只读文件系统保护，需要一并更新 service 文件，以便名称映射保存到 `/var/lib/ldn-relay-admin/game_names.json`。管理密码配置不受影响：

```bash
sudo git -C /opt/ldn-relay-admin pull --ff-only
sudo cp /opt/ldn-relay-admin/deploy/ldn-relay-admin.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl restart ldn-relay-admin
```

Docker 更新：`docker compose up -d --build`。游戏名称保存在 relay-data 数据卷，更新不会丢失；不要使用 `docker compose down -v` 删除该卷。

### 房间没有显示

确认使用免电脑分支并在当前服务器创建本地联机房间；仅连接 Wi-Fi 或中继不等于开房。该分支房主约每 5 秒广播一次，成员变化也会发送 SyncNetwork。页面应显示已解析广播条数。支持原始 IPv4、该分支的 IPv4 包装分片和零字节游程压缩，未知协议忽略，不影响原有转发。

目前用源码布局构造的协议样本及实际本机 UDP→API 链路做了测试，仍需要用你两台实机验证网站二进制与该源码的布局完全一致。若只有在线客户端没有房间，不要先换系统，先查看游戏是否进入正确模式及插件日志。

## Docker

```bash
cp .env.example .env
# 编辑 .env 设置密码与白名单，然后：
docker compose up -d --build
docker compose logs -f
```

Compose 网页端口默认映射到宿主机所有接口，可在 .env 设置 `WEB_BIND=127.0.0.1` 改为仅 SSH 隧道访问。Docker 可能绕过主机 UFW 的常规规则，请同时用云安全组或 ALLOWED_CLIENTS 限制访问。

## 检查与限制

```bash
python3 -m unittest discover -s tests -v
```

`/healthz` 只返回中继是否监听成功，不返回客户端信息；`/api/status` 必须登录。页面每两秒刷新。不支持通过公网 IP 访问浏览器后直接发现游戏；需要 Switch 真的进入游戏的本地联机界面。所有工具页面仅供小范围私人使用，不是经压力测试的公共中继平台。

底层中继退出时页面显示错误，健康检查返回 503；服务需通过 systemd/Docker 重启。内存数据随进程重启清空。

## 来源与许可证

基于 [dogty/ldn_mitm 的 beta/bsd-broadcast-relay 分支](https://github.com/dogty/ldn_mitm/tree/beta/bsd-broadcast-relay)。`vendor/relay_server.py` 来自用户提供的该分支 ZIP，转发逻辑保留，仅将 `main()` 改为接受参数列表以便集成。上游脚本哈希与来源见 THIRD_PARTY.md。管理页面和包装层同样以 GPL-2.0 发布，完整许可证见 LICENSE。
