#!/bin/bash
#2026年1月20日更新
#作者：https://github.com/ETime-Github
#--------------------
#     root权限与备份
#--------------------
# 脚本完整路径
SCRIPT_PATH=$(readlink -f "$0")

if [ "$(id -u)" -ne 0 ]; then
    printf "请使用 sudo bash %s 或 root 用户运行此脚本\n" "$SCRIPT_PATH" >&2
    exit 1
fi

# 获取主机名
HOSTNAME=$(hostname)

if hostname -I >/dev/null 2>&1; then
    # 优先尝试 hostname -I
    IP=$(hostname -I | cut -d ' ' -f1)
fi

# 如果 IP 仍然为空（比如命令不存在或返回空），则进入兼容性判断
if [ -z "$IP" ]; then
    if command -v ip >/dev/null 2>&1; then
        IP=$(ip addr show | grep -v "127.0.0.1" | grep "inet " | head -n 1 | awk '{print $2}' | cut -d/ -f1)
    elif command -v ifconfig >/dev/null 2>&1; then
        IP=$(ifconfig | grep -v "127.0.0.1" | grep "inet " | head -n 1 | awk '{print $2}' | sed 's/addr://')
    else
        IP="unknown"
    fi
fi

# 清理变量中的空格或换行，确保文件名合法
IP=$(printf "%s" "$IP" | tr -d '[:space:]')
HOSTNAME=$(printf "%s" "$HOSTNAME" | tr -d '[:space:]')
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

MD_FILE="/tmp/${HOSTNAME}_${IP}.md"
BACKUP_FILE="${MD_FILE}.${TIMESTAMP}.bak"

backup_config() {
    # 仅在文件存在且大小不为 0 时备份
    if [ -s "$MD_FILE" ]; then
        if cp "$MD_FILE" "$BACKUP_FILE" 2>/dev/null; then
            printf "[INFO] 发现已有同名文件，已备份至: %s\n" "$BACKUP_FILE"
            > "$MD_FILE" # 彻底清空文件
            printf "[INFO] 已重置记录文件: %s\n" "$MD_FILE"
        else
            printf "[ERROR] 备份失败，请检查权限或路径: %s\n" "$MD_FILE" >&2
            return 1
        fi
    else
        # 文件不存在或为空，直接初始化
        touch "$MD_FILE"
        printf "[INFO] 已初始化记录文件: %s\n" "$MD_FILE"
    fi
}

# 执行备份逻辑
backup_config || exit 1

#--------------------
#     通用函数
#--------------------

# 通过 PAM 识别 Linux 发行版系列
detect_by_pam() {
    if [ -f /etc/pam.d/system-auth ] || [ -f /etc/pam.d/password-auth ]; then
        printf "redhat"
    elif [ -f /etc/pam.d/common-auth ] || [ -f /etc/pam.d/common-password ]; then
        printf "debian"
    else
        printf "unknown"
    fi
}
family=$(detect_by_pam)

# 用户列表、家目录
users=$(getent passwd | grep -vE 'nologin$|false$|sync$|shutdown$|halt$' | cut -d: -f1)
homes=$(getent passwd | grep -vE 'nologin$|false$|sync$|shutdown$|halt$' | cut -d: -f6)

check_global_config() {
    local keyword="$1"
    
    printf "\n\`\`\`shell\n" >> "$MD_FILE"
    
    # 检查 /etc/profile
    if [ -f "/etc/profile" ]; then
        printf "#-----/etc/profile-----\n" >> "$MD_FILE"
        grep -E -v '^$|^#' /etc/profile | grep -C 5 --color=never "$keyword" >> "$MD_FILE" 2>&1
    fi

    # 检查 /etc/profile.d/ 目录
    if [ -d "/etc/profile.d" ]; then
        printf "\n#-----/etc/profile.d/*-----\n" >> "$MD_FILE"
        grep -E -v '^$|^#' -r /etc/profile.d/ 2>/dev/null | grep -C 5 --color=never "$keyword" >> "$MD_FILE" 2>&1
    fi

    # 根据系统系列检查不同的 bashrc
    if [ "$family" = "redhat" ]; then
        if [ -f "/etc/bashrc" ]; then
            printf "\n#-----/etc/bashrc-----\n" >> "$MD_FILE"
            grep -E -v '^$|^#' /etc/bashrc | grep -C 5 --color=never "$keyword" >> "$MD_FILE" 2>&1
        fi
    elif [ "$family" = "debian" ]; then
        if [ -f "/etc/bash.bashrc" ]; then
            printf "\n#-----/etc/bash.bashrc-----\n" >> "$MD_FILE"
            grep -E -v '^$|^#' /etc/bash.bashrc | grep -C 5 --color=never "$keyword" >> "$MD_FILE" 2>&1
        fi
    fi
    
    printf "\`\`\`\n" >> "$MD_FILE"
}

check_user_config() {
    local keyword="$1"
    
    # 将字符串转为数组，方便索引对应
    local user_arr=($users)
    local home_arr=($homes)
    
    printf "\n\`\`\`shell\n" >> "$MD_FILE"
    
    for i in "${!user_arr[@]}"; do
        local user="${user_arr[$i]}"
        local user_home="${home_arr[$i]}"
        
        # 检查 .bash_profile
        if [ -f "$user_home/.bash_profile" ]; then
            printf "#-----%s/.bash_profile-----\n" "$user_home" >> "$MD_FILE"
            grep -E -v '^$|^#' "$user_home/.bash_profile" | grep -C 5 --color=never "$keyword" >> "$MD_FILE" 2>&1
        fi

        # 检查 .profile
        if [ -f "$user_home/.profile" ]; then
            printf "#-----%s/.profile-----\n" "$user_home" >> "$MD_FILE"
            grep -E -v '^$|^#' "$user_home/.profile" | grep -C 5 --color=never "$keyword" >> "$MD_FILE" 2>&1
        fi
        # 检查 .bashrc
        if [ -f "$user_home/.bashrc" ]; then
            printf "#-----%s/.bashrc-----\n" "$user_home" >> "$MD_FILE"
            grep -E -v '^$|^#' "$user_home/.bashrc" | grep -C 5 --color=never "$keyword" >> "$MD_FILE" 2>&1
        fi
        
        printf "\n" >> "$MD_FILE"
    done
    
    printf "\`\`\`\n" >> "$MD_FILE"
}

# 查生效配置
check_real_config() {
    local keyword="$1"
    local has_dollar=0
    
    # 判断参数是否以 $ 开头
    case "$keyword" in
        \$*) has_dollar=1 ;;
    esac
    
    printf "\n\`\`\`shell\n" >> ""$MD_FILE""
    
    local user_list=($users)
    local home_list=($homes)
    for i in "${!user_list[@]}"; do
        local user="${user_list[$i]}"
        local user_home="${home_list[$i]}"
        
        printf "#----------%s----------\n" "$user" >> ""$MD_FILE""
        
        # --- 测试登录 Shell (Login Shell) ---
        if [ $has_dollar -eq 1 ]; then
            # 变量检查：使用 printf 处理输出，确保格式统一
            res_login=$(su -l "$user" -c '
                if command -v shopt >/dev/null 2>&1; then
                    printf "确保是Login Shell（login_shell on）："
                    shopt login_shell 2>&1
                else
                    printf "确保是Login Shell（有减号-）：%s\n" "$0"
                fi
                val=$(printf "%s" '"$keyword"')
                if [ -z "$val" ]; then printf "生效值：无/获取失败/默认值\n"; else printf "生效值：%s\n" "$val"; fi
            ' 2>/dev/null)
        else
            # 命令检查：使用 printf 配合变量捕获结果
            res_login=$(su -l "$user" -c '
                if command -v shopt >/dev/null 2>&1; then
                    printf "确保是Login Shell（login_shell on）："
                    shopt login_shell 2>&1
                else
                    printf "确保是Login Shell（有减号-）：%s\n" "$0"
                fi
                cmd_out=$('"$keyword"' 2>/dev/null)
                if [ -z "$cmd_out" ]; then printf "生效值：无/获取失败/默认值\n"; else printf "生效值：%s\n" "$cmd_out"; fi
            ' 2>/dev/null)
        fi
        
        printf "#-----登录Shell 非交互生效值 (su -l)-----\n" >> ""$MD_FILE""
        printf "%s\n" "$res_login" >> ""$MD_FILE""

        # --- 测试非登录 Shell (Non-login Shell) ---
        if [ $has_dollar -eq 1 ]; then
            res_nonlogin=$(su "$user" -c '
                [ -f "'"$user_home"'/.bashrc" ] && . "'"$user_home"'/.bashrc"
                if command -v shopt >/dev/null 2>&1; then
                    printf "确保是Non-login Shell（login_shell off）："
                    shopt login_shell 2>&1
                else
                    printf "确保是Non-login Shell（无减号-）：%s\n" "$0"
                fi
                val=$(printf "%s" '"$keyword"')
                if [ -z "$val" ]; then printf "生效值：无/获取失败/默认值\n"; else printf "生效值：%s\n" "$val"; fi
            ' 2>/dev/null)
        else
            res_nonlogin=$(su "$user" -c '
                [ -f "'"$user_home"'/.bashrc" ] && . "'"$user_home"'/.bashrc"
                if command -v shopt >/dev/null 2>&1; then
                    printf "确保是Non-login Shell（login_shell off）："
                    shopt login_shell 2>&1
                else
                    printf "确保是Non-login Shell（无减号-）：%s\n" "$0"
                fi
                cmd_out=$('"$keyword"' 2>/dev/null)
                if [ -z "$cmd_out" ]; then printf "生效值：无/获取失败/默认值\n"; else printf "生效值：%s\n" "$cmd_out"; fi
            ' 2>/dev/null)
        fi
        
        printf "#-----非登录Shell 非交互生效值 (su)-----\n" >> ""$MD_FILE""
        printf "%s\n" "$res_nonlogin" >> ""$MD_FILE""
        
        printf "\n" >> ""$MD_FILE""
    done
    printf "\`\`\`\n" >> ""$MD_FILE""
}

append_text_to_md() {
    local text_a="$1"
    local text_b="$2"
    local text_c="$3"
    
    if [ -n "$text_a" ]; then
        printf "\n%b\n" "$text_a" >> "$MD_FILE"
    fi
    
    if [ -n "$text_b" ]; then
        printf "\n%b\n" "$text_b" >> "$MD_FILE"
    fi
    
    if [ -n "$text_c" ]; then
        printf "\n%b\n" "$text_c" >> "$MD_FILE"
    fi
}

append_code_to_md() {
    # 参数顺序：注释1, 代码1, 注释2, 代码2, 注释3, 代码3
    local note_a="$1"
    local code_a="$2"
    local note_b="$3"
    local code_b="$4"
    local note_c="$5"
    local code_c="$6"

    # 只有当至少有一个参数不为空时才开始写入
    if [ -n "$note_a" ] || [ -n "$code_a" ] || [ -n "$note_b" ] || [ -n "$code_b" ] || [ -n "$note_c" ] || [ -n "$code_c" ]; then
        
        printf "\n\`\`\`shell\n" >> "$MD_FILE"

        # 处理第一组
        [ -n "$note_a" ] && printf "#%s\n" "$note_a" >> "$MD_FILE"
        [ -n "$code_a" ] && eval "$code_a" >> "$MD_FILE" 2>&1

        # 处理第二组
        [ -n "$note_b" ] && printf "#%s\n" "$note_b" >> "$MD_FILE"
        [ -n "$code_b" ] && eval "$code_b" >> "$MD_FILE" 2>&1

        # 处理第三组
        [ -n "$note_c" ] && printf "#%s\n" "$note_c" >> "$MD_FILE"
        [ -n "$code_c" ] && eval "$code_c" >> "$MD_FILE" 2>&1

        printf "\`\`\`\n" >> "$MD_FILE"
    fi
}

#--------------------
#     基本信息
#--------------------
printf "[INFO] 开始收集\n"
append_text_to_md "# 基本信息" "1. 机器名、[系统、内核]"
printf "\n\`\`\`shell\n" >> "$MD_FILE"
if command -v hostnamectl > /dev/null 2>&1; then
    hostnamectl >> "$MD_FILE" 2>&1
elif command -v hostname > /dev/null 2>&1; then
    hostname >> "$MD_FILE" 2>&1
fi
printf "\`\`\`\n" >> "$MD_FILE"

append_text_to_md "2. ip信息"
printf "\n\`\`\`shell\n" >> "$MD_FILE"
if command -v ip > /dev/null 2>&1; then
    ip a s up >> "$MD_FILE" 2>&1
elif command -v ifconfig > /dev/null 2>&1; then
    ifconfig >> "$MD_FILE" 2>&1
fi
printf "\`\`\`\n" >> "$MD_FILE"

append_text_to_md "3. Bash Shellshock（破壳）漏洞（CVE-2014-6271）测试"
append_code_to_md "" "env x='() { :;}; echo 有漏洞' bash -c 'echo 无漏洞'"

#--------------------
#     1/6身份鉴别
#--------------------
append_text_to_md "# 身份鉴别" "## 1. 应对登录的用户进行身份标识和鉴别，身份标识具有唯一性，身份鉴别信息具有复杂度要求并定期更换。" "> \`grep -v '^#' /etc/login.defs | grep PASS\` #密码最长使用小于等于90天符合，最短使用大于等于1天符合，长度大于等于8位符合。天数只对新账号有效，旧账号查看下方过期账号测评项。长度pam配置优先。"
append_code_to_md "" "grep -v '^#' /etc/login.defs | grep PASS"

append_text_to_md "> \`grep -v '^#' /etc/pam.d/passwd | grep -E 'pam_cracklib|pam_pwquality|include|substack'\` #先看这个文件include或substack哪个文件，再看下方相应文件有无使用相关模块。或者直接配置在这个文件也行。下次修改密码生效。"
append_code_to_md "" "grep -v '^#' /etc/pam.d/passwd | grep -E 'pam_cracklib|pam_pwquality|include|substack'"

if [ "$family" = "redhat" ]; then
    append_text_to_md "> \`grep -E 'pam_cracklib|pam_pwquality' /etc/pam.d/*-auth\` #RedHat系查看是否使用密码复杂度模块？密码长度大于等于8位，每种符号至少1个(值-1)符合。"
    append_code_to_md "" "grep -E 'pam_cracklib|pam_pwquality' /etc/pam.d/*-auth"
elif [ "$family" = "debian" ]; then
    append_text_to_md "> \`grep -E 'pam_cracklib|pam_pwquality' /etc/pam.d/common-*\` #Debian系查看是否使用密码复杂度模块？密码长度大于等于8位，每种符号至少1个(值-1)符合。"
    append_code_to_md "" "grep -E 'pam_cracklib|pam_pwquality' /etc/pam.d/common-*"
else
    printf "[ERROR] pam识别出Linux为%s系列，无法检查密码复杂度要求，请手动检查。\n" "$family"
fi

if [ -f "/etc/security/pwquality.conf" ]; then
    append_text_to_md "> \`grep -E -v '^$|^#' /etc/security/pwquality.conf\` #pam_pwquality.so模块默认配置文件，pam未配置参数都取这里的值。"
    append_code_to_md "" "grep -E -v '^$|^#' /etc/security/pwquality.conf"
fi
if [ -f "/etc/deepin/dde.conf" ]; then
    append_text_to_md "> \`grep -E -v '^$|^#' /etc/deepin/dde.conf\` #UOS统信系统密码复杂度配置文件。"
    append_code_to_md "" "grep -E -v '^$|^#' /etc/deepin/dde.conf"
fi

#--------------------
append_text_to_md "## 2. 应具有登录失败处理功能，应配置并启用结束会话、限制非法登录次数和当登录连接超时自动退出等相关措施。" "> \`grep -v '^#' /etc/pam.d/login | grep -E 'pam_tally2|pam_faillock|include|substack'\` #**本地终端登录失败**处理，先看这个文件include或substack哪个文件，再看下方相应文件有无使用相关模块。或者直接配置在这个文件也行。"
append_code_to_md "" "grep -v '^#' /etc/pam.d/login | grep -E 'pam_tally2|pam_faillock|include|substack'"

append_text_to_md "> \`grep -v '^#' /etc/pam.d/sshd | grep -E 'pam_tally2|pam_faillock|include|substack'\` #**远程登录失败**处理，先看这个文件include或substack哪个文件，再看下方相应文件有无使用相关模块。或者直接配置在这个文件也行。"
append_code_to_md "" "grep -v '^#' /etc/pam.d/sshd | grep -E 'pam_tally2|pam_faillock|include|substack'"

if [ -f "/etc/pam.d/lightdm" ]; then
    append_text_to_md "> \`grep -v '^#' /etc/pam.d/lightdm | grep -E 'pam_tally2|pam_faillock|include|substack'\` #**图形登录失败**处理，先看这个文件include或substack哪个文件，再看下方相应文件有无使用相关模块。或者直接配置在这个文件也行。"
    append_code_to_md "" "grep -v '^#' /etc/pam.d/lightdm | grep -E 'pam_tally2|pam_faillock|include|substack'"
elif [ -f "/etc/pam.d/gdm" ]; then
    append_text_to_md "> \`grep -v '^#' /etc/pam.d/gdm | grep -E 'pam_tally2|pam_faillock|include|substack'\` #**图形登录失败**处理，先看这个文件include或substack哪个文件，再看下方相应文件有无使用相关模块。或者直接配置在这个文件也行。"
    append_code_to_md "" "grep -v '^#' /etc/pam.d/gdm | grep -E 'pam_tally2|pam_faillock|include|substack'"
else
    printf "[ERROR] 不是使用lightdm或gdm桌面环境，无法检查【图形登录失败】处理，请手动检查。\n"
fi

if [ "$family" = "redhat" ]; then
    append_text_to_md "> \`grep -E 'pam_tally2|pam_faillock' /etc/pam.d/*-auth\` #RedHat系查看是否使用登录失败处理模块？登录失败小于等于10次，锁定大于等于5分钟（值大于等于300）符合。"
    append_code_to_md "" "grep -E 'pam_tally2|pam_faillock' /etc/pam.d/*-auth"
elif [ "$family" = "debian" ]; then
    append_text_to_md "> \`grep -E 'pam_tally2|pam_faillock' /etc/pam.d/common-*\` #Debian系查看是否使用登录失败处理模块？登录失败小于等于10次，锁定大于等于5分钟（值大于等于300）符合。"
    append_code_to_md "" "grep -E 'pam_tally2|pam_faillock' /etc/pam.d/common-*"
else
    printf "> [ERROR] pam识别出Linux为%s系列，无法检查【登录失败】处理，请手动检查。\n" "$family"
fi

append_text_to_md "> \`grep -E -v '^$|^#' /etc/profile /etc/profile.d/* /etc/bashrc /etc/bash.bashrc | grep -C 5 TMOUT\` #全局配置，要有export才生效。登录超时自动退出非监控或投屏建议小于等于10分钟（值小于等于600）符合。"
check_global_config 'TMOUT'

append_text_to_md "> \`grep -E -v '^$|^#' ~/.bash_profile ~/.profile ~/.bashrc | grep -C 5 TMOUT\` #用户配置，要有export才生效。"
check_user_config 'TMOUT'

append_text_to_md "> **后加载的配置覆盖先加载，除非有变量、参数、脚本内容控制**\n> 登录shell：\`ssh远程登录\`，\`本地终端登录\`，\`bash -l / bash --login\`，\`su - / su -l /su --login\`，\`sudo -i / sudo --login\`\n> 加载顺序：1. ==/etc/profile== (会遍历调用 ==/etc/profile.d/\*.sh== ) → 2.按顺序加载第一个存在的( ==~/.bash_profile== → ==~/.bash_login== → ==~/.profile== ) → 3.调用 ==~/.bashrc== → 4.调用 ==/etc/bashrc== (RedHat系)或 ==/etc/bash.bashrc== (Debian系)\n>\n> 非登录shell：\`图形界面终端\`，\`bash\`，\`su\`，\`sudo -s / sudo --shell\`\n> 加载顺序：1. ==~/.bashrc== → 2. ==/etc/bashrc== (RedHat系)或 ==/etc/bash.bashrc==(Debian系)\n>\n> ***以下是生效配置（可能与实际交互有区别）仅供参考***"
check_real_config '$TMOUT'

printf "[WARN] 注意！！！【图形登录超时】自动退出请手动检查系统首选项的电源选项或屏幕保护选项，或者直接看公用配置文件也可以。\n" 

#--------------------
append_text_to_md "## 3. 当进行远程管理时，应采取必要措施防止鉴别信息在网络传输过程中被窃听。" "> 使用ssh或其他远程开加密符合，使用telnet或其他远程不开加密不符合。以下只检查ssh和telnet。"
printf "\n\`\`\`shell\n" >> "$MD_FILE"
printf "#-----ssh-----\n" >> "$MD_FILE"
if command -v systemctl > /dev/null 2>&1; then
    # 尝试 sshd，如果失败则尝试 ssh
    systemctl status sshd >> "$MD_FILE" 2>&1 || systemctl status ssh >> "$MD_FILE" 2>&1
elif command -v service > /dev/null 2>&1; then
    service sshd status >> "$MD_FILE" 2>&1 || service ssh status >> "$MD_FILE" 2>&1
fi
printf "#-----telnet-----\n" >> "$MD_FILE"
if command -v systemctl > /dev/null 2>&1; then
    # 尝试 telnet.socket，如果失败则尝试 telnetd.socket
    systemctl status telnet.socket >> "$MD_FILE" 2>&1 || systemctl status telnetd.socket >> "$MD_FILE" 2>&1
elif command -v service > /dev/null 2>&1; then
    service telnet status >> "$MD_FILE" 2>&1 || service telnetd status >> "$MD_FILE" 2>&1
fi
printf "\`\`\`\n" >> "$MD_FILE"

#--------------------
append_text_to_md "## 4. (三级)应采用口令、密码技术、生物技术等两种或两种以上组合的鉴别技术对用户进行身份鉴别，且其中一种鉴别技术至少应使用密码技术来实现。" "> 除密码以外有OTP、证书、USBkey、指纹、声纹、虹膜等其他鉴别技术符合。"
printf "[INFO] 1/6身份鉴别部分收集完成。\n"

#--------------------
#     2/6访问控制
#--------------------
append_text_to_md "# 访问控制" "## 1. 应对登录的用户分配账户和权限。" "> \`grep -E -v 'nologin$|false$|sync$|shutdown$|halt$' /etc/passwd\` #查看非/sbin/nologin、非/bin/false、非shutdown、sync、halt账户，询问这些账户的作用和使用人。理论上一人一个账户才符合。"
append_code_to_md "" "grep -E -v 'nologin$|false$|sync$|shutdown$|halt$' /etc/passwd"

#--------------------
append_text_to_md "## 2. 应重命名或删除默认账户，修改默认账户的默认口令。" "> 重命名或删除有风险可以禁用。以下检查是否禁用root。" "> \`grep -E -A10 '^[^#].*!' -r /etc/sudoers /etc/sudoers.d/\` #是否禁止其他用户以root身份使用shell命令？添加到所有允许命令后才有效，这个必须有再加下面2选1都有才符合。3条有其中1条部分符合。"
append_code_to_md "-----/etc/sudoers-----" "grep -E '^[^#].*!' -r /etc/sudoers" "-----/etc/sudoers.d/-----" "grep -E '^[^#].*!' -r /etc/sudoers.d/ 2>/dev/null"

append_text_to_md "> \`cat /etc/passwd | grep root\` #是否禁用root登录shell？没有root用户，shell字段为nologin或false则符合。2选1。\n> \`passwd -S root\` #是否锁定root密码？L或LK则符合。2选1。"
append_code_to_md "" "cat /etc/passwd | grep root" "-----" "passwd -S root"

append_text_to_md "> \`sshd -T | grep root\` #是否允许root远程登录？以上都没有，至少要不允许远程登录，但是测评项仍然不符合。这个配置优先级：DenyUsers > PermitRootLogin > AllowUsers > DenyGroups > AllowGroups。"
append_code_to_md "" "sshd -T | grep root"

#--------------------
append_text_to_md "## 3. 应及时删除或停用多余的、过期的账户，避免共享账户的存在。" "> \`chage -l 用户名\` #查看账户是否过期？过期账户锁定则符合。最近90天是否修改密码？修改则符合。是否要求90天修改密码？有要求则符合。\n> \`passwd -S 用户名\` #查看账户密码是否锁定？过期账户锁定L/LK则则符合。"
printf "\n\`\`\`shell\n" >> "$MD_FILE"
for user in $users; do
    chage_output=$(chage -l $user)
    passwd_output=$(passwd -S $user)
    printf "#-----%s-----\n" "$user">> "$MD_FILE" 2>&1
    printf "%s\n" "$chage_output" >> "$MD_FILE" 2>&1
    printf "\n" >> "$MD_FILE"
    printf "%s\n" "$passwd_output" >> "$MD_FILE" 2>&1
done
printf "\`\`\`\n" >> "$MD_FILE"

#--------------------
append_text_to_md "## 4. 应授予管理用户所需的最小权限，实现管理用户的权限分离。" "> \`grep -E -v '^$|^#' /etc/sudoers\` #查看用户权限划分是否配置三权分立？系统管理员、用户管理员、日志管理员，有则符合。"
append_code_to_md "" "grep -E -v '^$|^#' /etc/sudoers"

append_text_to_md "> \`id 用户名\` #查看非/sbin/nologin、非/bin/false、非shutdown、sync、halt账户所属组，询问各组作用。检查账户是否加入root、sudo、wheel等sudoers文件有root权限的组。"
printf "\n\`\`\`shell\n" >> "$MD_FILE"
for user in $users; do
    id_output=$(id $user)
    printf "#-----%s-----\n" "$user" >> "$MD_FILE"
    printf "%s\n" "$id_output" >> "$MD_FILE" 2>&1
done
printf "\`\`\`\n" >> "$MD_FILE"

append_text_to_md "> \`grep -E -v '^$|^#' /etc/profile /etc/profile.d/* /etc/bashrc /etc/bash.bashrc | grep -C 5 umask\` #全局配置，要有export才生效。默认情况下：文件最大权限为 666（rw-rw-rw-），目录为 777（rwxrwxrwx），实际权限 = 最大权限 - umask。\n> 二级系统 0022 符合，即所有者全部权限、所属组读写、其他人无。推荐 0027。\n> 三级系统 0027 符合，即所有者全部权限、所属组读写、其他人无。推荐 0077。\n> 四级系统 0077 符合，即所有者全部权限、所属组无、其他人无）。"
check_global_config 'umask'

append_text_to_md "> \`grep -E -v '^$|^#' ~/.bash_profile ~/.profile ~/.bashrc | grep -C 5 umask\` #用户配置，要有export才生效。"
check_user_config 'umask'

append_text_to_md "> **后加载的配置覆盖先加载，除非有变量、参数、脚本内容控制**\n> 登录shell：\`ssh远程登录\`，\`本地终端登录\`，\`bash -l / bash --login\`，\`su - / su -l /su --login\`，\`sudo -i / sudo --login\`\n> 加载顺序：1. ==/etc/profile== (会遍历调用 ==/etc/profile.d/\*.sh== ) → 2.按顺序加载第一个存在的( ==~/.bash_profile== → ==~/.bash_login== → ==~/.profile== ) → 3.调用 ==~/.bashrc== → 4.调用 ==/etc/bashrc== (RedHat系)或 ==/etc/bash.bashrc== (Debian系)\n>\n> 非登录shell：\`图形界面终端\`，\`bash\`，\`su\`，\`sudo -s / sudo --shell\`\n> 加载顺序：1. ==~/.bashrc== → 2. ==/etc/bashrc== (RedHat系)或 ==/etc/bash.bashrc==(Debian系)\n>\n> ***以下是生效配置（可能与实际交互有区别）仅供参考***"
check_real_config 'umask'

#--------------------
append_text_to_md "## 5. （三级）应由授权主体配置访问控制策略，访问控制策略规定主体对客体的访问规则。" "> 看上方sudoers文件有无配置到文件级别，有则符合。"

#--------------------
append_text_to_md "## 6. （三级）访问控制的粒度应达到主体为用户级或进程级，客体为文件、数据库表级。" "> \`stat -c '%a %F %n' /etc/passwd /etc/shadow /etc/group\` #查看权限是否小于等于644\n> \`stat -c '%a %F %n' /etc/*.conf | sort\` #查看权限是否小于等于644"
append_code_to_md "" "stat -c '%a %F %n' /etc/passwd /etc/shadow /etc/group" "-----" "stat -c '%a %F %n' /etc/*.conf | sort"


#--------------------
append_text_to_md "## 7. （三级）应对重要主体和客体设置安全标记，并控制主体对有安全标记信息资源的访问。" "> 询问有没有安装使用可信客户端或其他软硬件。"
printf "[INFO] 2/6访问控制部分收集完成。\n"

#--------------------
#     3/6安全审计
#--------------------
append_text_to_md "# 安全审计" "## 1. 应启用安全审计功能，审计覆盖到每个用户，对重要的用户行为和重要安全事件进行审计。" "> \`systemctl status rsyslog\` #查看服务是否启动，旧版命令service rsyslog status。\n> \`grep -E -v '^$|^#' /etc/rsyslog.conf\` #查看rsyslog配置文件的审计内容（auth、authpriv、cron、daemon、kern、lpr、mail、news、syslog、user、uucp、local0-7），有无指定日志服务器。"
printf "\n\`\`\`shell\n" >> "$MD_FILE"
if command -v systemctl > /dev/null 2>&1; then
    systemctl status rsyslog >> "$MD_FILE" 2>&1
elif command -v service > /dev/null 2>&1; then
    service rsyslog status >> "$MD_FILE" 2>&1
fi
printf "#-----/etc/rsyslog.conf-----\n" >> "$MD_FILE"
grep -E -v '^$|^#' /etc/rsyslog.conf >> "$MD_FILE" 2>&1
printf "\`\`\`\n" >> "$MD_FILE"

append_text_to_md "> \`systemctl status auditd\` #查看服务是否启动，旧版命令service auditd status。\n> \`grep -E -v '^$|^#' /etc/audit/audit.rules\` #查看是否配置审计规则。\n> \`auditctl -l\` #查看当前审计规则。"
printf "\n\`\`\`shell\n" >> "$MD_FILE"
if command -v systemctl > /dev/null 2>&1; then
    systemctl status auditd >> "$MD_FILE" 2>&1
elif command -v service > /dev/null 2>&1; then
    service auditd status >> "$MD_FILE" 2>&1
fi
printf "#-----/etc/audit/audit.rules-----\n" >> "$MD_FILE"
grep -E -v '^$|^#' /etc/audit/audit.rules >> "$MD_FILE" 2>&1
printf "#-----auditctl -l-----\n" >> "$MD_FILE"
auditctl -l >> "$MD_FILE" 2>&1
printf "\`\`\`\n" >> "$MD_FILE"

#--------------------
append_text_to_md "## 2. 审计记录应包括事件的日期和时间、用户、事件类型、事件是否成功及其他与审计相关的信息。" "> 查看上方rsyslog配置文件的审计级别，从少到多是emerg、alert、crit、err、warning、notice、info、debug。简单来说至少info级。复杂的话不同审计内容不同级别，至少notice级。"

#--------------------
append_text_to_md "## 3. 应对应审计记录进行保护，防止未授权的查看、修改和删除等。" "> 询问是否手动备份日志？上方日志配置有指向日志服务器符合。" "> \`grep -E '^(daily|weekly|monthly|yearly|rotate)' /etc/logrotate.conf\` #查看日志清除周期，大于等于6个月、24周、180天则符合。"
append_code_to_md "" "grep -E '^(daily|weekly|monthly|yearly|rotate)' /etc/logrotate.conf"

append_text_to_md "> \`stat -c '%a %F %n' /etc/rsyslog.conf\` #查看权限是否小于等于644？\n> \`stat -c '%a %F %n' /etc/audit/* | sort\` #查看权限是否小于等于644？\n> \`stat -c '%a %F %n' /var/log/*  | sort\` #查看权限是否小于等于644？"
append_code_to_md "-----/etc/rsyslog.conf-----" "stat -c '%a %F %n' /etc/rsyslog.conf" "-----/etc/audit/*-----" "stat -c '%a %F %n' /etc/audit/* | sort" "-----/var/log/*-----" "stat -c '%a %F %n' /var/log/*  | sort"

#--------------------
append_text_to_md "## 4. （三级）对审计进程进行保护，防止未经授权的中断。" "> 询问有没有安装使用可信客户端或其他软硬件。" ""
printf "[INFO] 3/6安全审计部分收集完成。\n"

#--------------------
#     4/6入侵防范
#--------------------
append_text_to_md "# 入侵防范" "## 1. 应遵循最小安装的原则，仅安装需要的组件和应用程序。"
printf "\n\`\`\`shell\n" >> "$MD_FILE"
if [ "$family" = "redhat" ]; then
    yum list installed >> "$MD_FILE" 2>&1
elif [ "$family" = "debian" ]; then
    apt list --installed >> "$MD_FILE" 2>&1
else
    printf "[ERROR] pam识别出Linux为%s系列，无法列出已安装组件和应用程序，请手动检查。" "$family"
fi
printf "\`\`\`\n" >> "$MD_FILE"

#--------------------
append_text_to_md "## 2. 应关闭不需要的系统服务、默认共享和高危端口。" "> \`ss -lnptu | column -t\` 或 \`netstat -tulnp\` #列出所有监听端口，询问相关端口是否需要使用，看是否有高危端口。"
printf "\n\`\`\`shell\n" >> "$MD_FILE"
if command -v ss > /dev/null 2>&1; then
    ss -lnptu | column -t >> "$MD_FILE" 2>&1
elif command -v netstat > /dev/null 2>&1; then
    netstat -tulnp >> "$MD_FILE" 2>&1
else
    printf "[ERROR] 没有ss或netstat命令，无法检查监听端口，请手动检查。\n"
fi
printf "\`\`\`\n" >> "$MD_FILE"

append_text_to_md "> \`systemctl list-unit-files --type service --state enabled\` 或 \`chkconfig --list | grep -E 'on|启用|开'\` #列出所有启用的系统服务，询问相关服务是否需要使用。"
printf "\n\`\`\`shell\n" >> "$MD_FILE"
if command -v systemctl > /dev/null 2>&1; then
    systemctl list-unit-files --type service --state enabled >> "$MD_FILE" 2>&1
elif command -v chkconfig > /dev/null 2>&1; then
    chkconfig --list | grep -E 'on|启用|开' >> "$MD_FILE" 2>&1
elif command -v update-rc.d > /dev/null 2>&1; then
    ls -l /etc/rc*.d/S* | awk '{print $9}' | sed 's/.*S[0-9]*//' | sort -u >> "$MD_FILE" 2>&1
else
    printf "[ERROR] 没有systemctl或chkconfig命令，无法检查系统服务状态，请手动检查。\n"
fi
printf "\`\`\`\n" >> "$MD_FILE"

#--------------------
append_text_to_md "## 3. 应通过设定终端接入方式或网络地址范围对通过网络进行管理的管理终端进行限制。" "> \`firewall-cmd --list-all\` 或 \`iptables -nvL\` #查看防火墙默认策略是否禁止或者在最后加禁止所有策略，使用远程运维是否配置允许范围。"
printf "\n\`\`\`shell\n" >> "$MD_FILE"
if command -v firewall-cmd > /dev/null 2>&1 && firewall-cmd --state > /dev/null 2>&1; then
    firewall-cmd --list-all >> "$MD_FILE" 2>&1
elif command -v iptables > /dev/null 2>&1; then
    iptables -nvL >> "$MD_FILE" 2>&1
else
    printf "[ERROR] 未发现运行中的 firewalld 或可用 iptables 命令，请手动检查防火墙。\n" >> "$MD_FILE"
    printf "[ERROR] 未发现运行中的 firewalld 或可用 iptables 命令，请手动检查防火墙。\n"
fi
printf "\`\`\`\n" >> "$MD_FILE"

append_text_to_md "> 查看hosts.allow和hosts.deny的准入配置，以及sshd_config中的准入配置。"
append_code_to_md "-----hosts.allow-----" "grep -E -v '^$|^#' /etc/hosts.allow" "-----hosts.deny-----" "grep -E -v '^$|^#' /etc/hosts.deny" "-----sshd_config-----" "grep -v '^#' /etc/ssh/sshd_config | grep -E 'DenyUsers|AllowUsers|DenyGroups|AllowGroups'"

#--------------------
append_text_to_md "## 4. 应能发现可能存在的已知漏洞，并在经过充分测试评估后，及时修补漏洞。" "> 检查上方软件列表，最近6个月是否更新。可以使用能以版本匹配漏洞的漏洞扫描器做漏扫。" "> \`uname -r\` #查看内核版本，是否使用已停止技术支持的版本？\n> \`cat /etc/*release\` #查看操作系统版本，是否使用已停止技术支持的版本？"
append_code_to_md "" "uname -r" "-----" "cat /etc/*release"

append_text_to_md "> \`grep -E -v '^$|^#' /etc/profile /etc/profile.d/* /etc/bashrc /etc/bash.bashrc | grep -C 5 HISTSIZE\` #全局配置，要有export才生效。建议小于等于10条。"
check_global_config 'HISTSIZE'

append_text_to_md "> \`grep -E -v '^$|^#' ~/.bash_profile ~/.profile ~/.bashrc | grep -C 5 HISTSIZE\` #用户配置，要有export才生效。"
check_user_config 'HISTSIZE'

append_text_to_md "> **后加载的配置覆盖先加载，除非有变量、参数、脚本内容控制**\n> 登录shell：\`ssh远程登录\`，\`本地终端登录\`，\`bash -l / bash --login\`，\`su - / su -l /su --login\`，\`sudo -i / sudo --login\`\n> 加载顺序：1. ==/etc/profile== (会遍历调用 ==/etc/profile.d/\*.sh== ) → 2.按顺序加载第一个存在的( ==~/.bash_profile== → ==~/.bash_login== → ==~/.profile== ) → 3.调用 ==~/.bashrc== → 4.调用 ==/etc/bashrc== (RedHat系)或 ==/etc/bash.bashrc== (Debian系)\n>\n> 非登录shell：\`图形界面终端\`，\`bash\`，\`su\`，\`sudo -s / sudo --shell\`\n> 加载顺序：1. ==~/.bashrc== → 2. ==/etc/bashrc== (RedHat系)或 ==/etc/bash.bashrc==(Debian系)\n>\n> ***以下是生效配置（可能与实际交互有区别）仅供参考***"
check_real_config '$HISTSIZE'

#--------------------
append_text_to_md "## 5. （三级）应能够检测到对重要节点进行入侵的行为，并在发生严重入侵事件时提供报警。" "> 询问是否有IDS，IPS等设备。"
printf "[INFO] 4/6入侵防范部分收集完成。\n"

#--------------------
#     5/6恶意代码
#--------------------
append_text_to_md "# 恶意代码" "## 1. 应安装防恶意代码软件或配置具有相应功能的软件，并定期进行升级和更新防恶意代码库。"

printf "\n\`\`\`shell\n" >> "$MD_FILE"
printf "#-----安天防病毒-----\n" >> "$MD_FILE"
if [ -f "/opt/LinuxKPC/ini/version" ]; then
    ps -ef | grep kis >> "$MD_FILE" 2>&1
    cat /opt/LinuxKPC/ini/version >> "$MD_FILE" 2>&1
else
    printf "未安装安天防病毒软件\n" >> "$MD_FILE"
fi
printf "#-----G01-----\n" >> "$MD_FILE"
if [ -f "/usr/local/gov_defence_agent" ]; then
    ps -ef | grep gov >> "$MD_FILE" 2>&1
else
    printf "未安装G01\n" >> "$MD_FILE"
fi
printf "#-----ClamAV-----\n" >> "$MD_FILE"
if command -v clamscan > /dev/null 2>&1; then
    ps -ef | grep clam >> "$MD_FILE" 2>&1
    clamscan --version >> "$MD_FILE" 2>&1
else
    printf "未安装ClamAV防病毒软件\n" >> "$MD_FILE"
fi
printf "\`\`\`\n" >> "$MD_FILE"

printf "[INFO] 5/6恶意代码部分收集完成。\n"

#--------------------
#     6/6可信验证
#--------------------
append_text_to_md "# 可信验证" "## 1. 可基于可信根对计算设备的系统引导程序、系统程序、重要配置参数和应用程序等进行可信验证，并在检测到其可信性受到破坏后进行报警，并将验证结果形成审计记录送至安全管理中心。" "> TPM国际，TCM国内。询问是否安装使用可信客户端或其他软硬件？"
append_code_to_md "" "dmesg | grep -i -E 'tpm|tcm|可信密码模块'"

printf "[INFO] 6/6可信验证部分收集完成。\n"

#--------------------
#     结束
#--------------------
printf "[INFO] 全部收集完成。\n"
printf "\n----------\n"

if command -v sz > /dev/null 2>&1; then
    read -p "[？] 检测到 sz 工具，是否尝试下载记录文件到本地? (y/n): " download_choice
    if [[ "$download_choice" == "y" || "$download_choice" == "Y" ]]; then
        printf "[！] 下载中……\n"
        sz "$MD_FILE"
        read -p "[？] 下载完成。是否删除生成的记录文件 ($MD_FILE)? (y/n): " rm_md_choice
        if [[ "$rm_md_choice" == "y" || "$rm_md_choice" == "Y" ]]; then
            rm -f "$MD_FILE"
            printf "[！] 记录文件已删除。\n"
        else
            printf "[INFO] 请手动删除记录文件 %s 。\n" "$MD_FILE"
        fi
    else
        printf "[INFO] 请手动下载记录文件 %s\n" "$MD_FILE"
        printf "[HINT] 可在本地电脑上打开 cmd 执行如下命令（可能需要重新指定IP和端口）\n"
        printf "scp -P 22 root@%s:%s  %s/Downloads\n" "$IP" "$MD_FILE" "%USERPROFILE%"
        printf "[HINT] 然后手动删除记录文件。"
    fi
else
    printf "[INFO] 请手动下载记录文件 %s\n" "$MD_FILE"
    printf "[HINT] 可在本地电脑上打开 cmd 执行如下命令（可能需要重新指定IP和端口）\n"
    printf "scp -P 22 root@%s:%s  %s/Downloads\n" "$IP" "$MD_FILE" "%USERPROFILE%"
    printf "[HINT] 然后手动删除记录文件。"
fi
printf "\n----------\n"
read -p "[？] 是否删除此脚本本身 ($SCRIPT_PATH)? (y/n): " rm_script_choice
if [[ "$rm_script_choice" == "y" || "$rm_script_choice" == "Y" ]]; then
    rm -f "$SCRIPT_PATH"
    printf "[！] 脚本已删除。\n"
else
    printf "[INFO] 请手动删除此脚本 %s\n" "$SCRIPT_PATH"
fi