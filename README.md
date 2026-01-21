# SecScripts
## 等保检测脚本
只是按等保二、三级大纲检测linux然后导出Markdown文件，不能自动判断。
- sudodbcp2md.sh 第一版，没有使用函数
- dbcp2md.sh 第二版，使用函数
## SSH 脚本
- modify_sshd_config.sh 有选择修改如下12项服务端配置
```shell
Protocol 2 # 仅支持 SSH v2（v1 存在设计缺陷，已被淘汰）
Port 23456 # 自定义端口
PermitEmptyPasswords no # 不允许空密码账号登录（默认no不允许，需确认）
PermitRootLogin no # 不允许root远程登录
UsePAM yes # 启用PAM
PubkeyAuthentication yes # 启用密钥认证
PasswordAuthentication yes # 启用密码认证
MaxAuthTries 3  # 最多允许3次密码/密钥尝试(不含密钥passphrase，因为是客户端侧认证)，超过则断开连接
# 如启用PAM，PAM的deny值应大于等于此值，避免PAM层提前阻断（小于的话当达到deny值即使输入正确密码仍会提示"Permission denied"）
# 客户端侧的 NumberOfPasswordPrompts 也会限制密钥passphrase/密码尝试次数，默认各3次
LoginGraceTime 30  # 认证超时秒数（默认 2 分钟），单位可填s和m，最终会转为秒
ClientAliveInterval 300 # 客户端存活检测间隔秒数，需与ClientAliveCountMax同时使用，用于避免无响应客户端占用资源，设置0禁用检测。
ClientAliveCountMax 3 # 客户端存活检测最大次数，需与ClientAliveInterval同时使用，用于避免无响应客户端占用资源，设置0禁用检测。
TCPKeepAlive no # 设置no禁用TCP层的keepalive（避免与ClientAlive 2个检测冲突），可改用客户端的keepalive。
```
