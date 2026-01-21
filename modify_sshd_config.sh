#!/bin/sh
# 修改sshd_config部分安全配置

CONFIG_FILE="/etc/ssh/sshd_config"
BACKUP_FILE="/etc/ssh/sshd_config.$(date +%Y%m%d_%H%M%S).bak"

# ------------------------------
# 进度显示
# ------------------------------
total_items=12  # 总配置项数（固定值）
current_item=0   # 当前处理项数

# 显示分割线（含进度）
show_separator() {
    current_item=$((current_item + 1))
    echo
    echo "========================================"
    echo "🔧 配置项处理进度：$current_item/$total_items"
    echo "----------------------------------------"
}

# ------------------------------
# 重复项检测
# ------------------------------
check_duplicate() {
    local param="$1"
    # 关键修复：使用 \s+ 匹配参数后的空格，确保只匹配完整参数
    count=$(grep -E "^[[:space:]]*$param\s+" "$CONFIG_FILE" | grep -v '^#' | wc -l)
    if [ "$count" -gt 1 ]; then
        echo "⚠️  警告：$param 在配置文件中存在 $count 个未注释的重复项！"
        echo "⚠️  建议先手动清理重复项，否则修改可能不生效。"
        return 1
    fi
    return 0
}

# ------------------------------
# 当前值显示
# ------------------------------
get_current_value() {
    local param="$1"
    # 1. 获取未注释的有效配置
    active_val=$(grep -E "^[[:space:]]*$param\s+" "$CONFIG_FILE" | grep -v '^#' | tail -n1 | awk '{print $2}')
    if [ -n "$active_val" ]; then
        echo "当前值: $active_val"
        return 0
    fi
    # 2. 获取注释中的值（修复多#问题）
    comment_val=$(grep -E "^[#]+[[:space:]]*$param\s+" "$CONFIG_FILE" | tail -n1 | sed 's/^#//')
    if [ -n "$comment_val" ]; then
        echo "当前值: #$comment_val <注释状态>"
        return 0
    fi
    # 3. 未设置
    echo "当前值: <未设置>"
}

# ------------------------------
# 数值验证
# ------------------------------
is_number() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;; # 非数字
        *) return 0 ;;           # 数字
    esac
}

is_time() {
    case "$1" in
        ''|*[!0-9smSM]*) return 1 ;; # 非法字符
        *) return 0 ;;             # 合法
    esac
}

is_protocol() {
    case "$1" in
        1|2|2,1) return 0 ;; # 仅允许这三个值
        *) return 1 ;;
    esac
}

# ------------------------------
# 原文位置修改
# ------------------------------
modify_in_place() {
    local param="$1"
    local new_val="$2"
    # 1. 检查是否存在未注释的配置项
    if grep -qE "^[[:space:]]*$param\s+" "$CONFIG_FILE"; then
        # 存在未注释项：直接替换值
        sed -i "s/^\([[:space:]]*$param\s\+\).*/\1$new_val/" "$CONFIG_FILE"
        echo "[INFO] 已在原文位置修改: $param = $new_val"
    elif grep -qE "^[#]+[[:space:]]*$param\s+" "$CONFIG_FILE"; then
        # 存在注释项：取消注释并修改值
        sed -i "s/^[#]*\([[:space:]]*$param\s\+\).*/\1$new_val/" "$CONFIG_FILE"
        echo "[INFO] 已取消注释并修改: $param = $new_val"
    else
        # 不存在：添加到文件末尾（但保留原文顺序）
        echo "$param $new_val" >> "$CONFIG_FILE"
        echo "[INFO] 已添加新配置: $param = $new_val"
    fi
}

# ------------------------------
# 严格输入验证（只接受y/n/yes/no大小写）
# ------------------------------
confirm_modify() {
    local prompt="$1"
    while true; do
        read -p "$prompt (y/N): " choice
        case "$choice" in
            [Yy]|[Yy][Ee][Ss]) 
                echo "[INFO] 用户确认修改"
                return 0 ;;  # 确认修改
            [Nn]|[Nn][Oo]) 
                echo "[INFO] 用户选择跳过修改"
                return 1 ;;  # 跳过修改
            "") 
                # 回车默认跳过（安全行为）
                echo "[INFO] 未输入，默认跳过修改"
                return 1 ;;
            *) 
                # 乱输入重新询问
                echo "[ERROR] 输入无效，请输入y/yes/n/no" >&2
                continue ;;
        esac
    done
}

# ------------------------------
# 1. YES/NO参数修改
# ------------------------------
modify_yesno() {
    local param="$1"
    local desc="$2"  # 移除推荐值参数

    show_separator  # 显示进度分割线
    echo "参数: $param"
    get_current_value "$param"
    echo "说明: $desc"

    # 在修改前调用重复项检测
    check_duplicate "$param"

    # 严格输入验证
    if confirm_modify "是否修改?"; then
        while true; do
            read -p "输入新值 (yes/no): " new_val
            case "$new_val" in
                yes|no)
                    # 关键修复：原文位置修改
                    modify_in_place "$param" "$new_val"
                    break
                    ;;
                *)
                    echo "[ERROR] 无效值，请输入 yes 或 no" >&2
                    ;;
            esac
        done
    else
        echo "[INFO] 跳过修改"
    fi
}

# ------------------------------
# 其他辅助函数
# ------------------------------
backup_config() {
    if cp "$CONFIG_FILE" "$BACKUP_FILE"; then
        echo "[INFO] 备份已创建: $BACKUP_FILE"
        return 0
    else
        echo "[ERROR] 无法创建备份文件" >&2
        return 1
    fi
}

verify_config() {
    if sshd -t; then
        echo "[INFO] 配置语法检查通过"
        return 0
    else
        echo "[ERROR] 配置语法错误！正在恢复备份..." >&2
        cp "$BACKUP_FILE" "$CONFIG_FILE"
        exit 1
    fi
}

reload_sshd() {
    echo "[INFO] 重载SSH服务..."
    systemctl reload sshd 2>/dev/null || systemctl restart sshd 2>/dev/null || echo "[WARN] 请手动重载服务" >&2
}

# ------------------------------
# 2. 自定义值类型参数修改（包含重复项检测）
# ------------------------------
modify_custom() {
    local param="$1"
    local default="$2"
    local desc="$3"
    local validator="$4"

    show_separator  # 显示进度分割线
    echo "参数: $param"
    get_current_value "$param"
    echo "说明: $desc"
    echo "推荐值: $default"

    # 在修改前调用重复项检测
    check_duplicate "$param"

    # 严格输入验证
    if confirm_modify "是否修改?"; then
        while true; do
            read -p "输入新值（回车使用推荐值）: " input_val
            if [ -z "$input_val" ]; then
                new_val="$default"
                echo "[INFO] 使用推荐值: $new_val"
                break
            else
                # 调用验证函数
                if $validator "$input_val"; then
                    new_val="$input_val"
                    break
                else
                    echo "[ERROR] 无效值，请重新输入" >&2
                fi
            fi
        done

        modify_in_place "$param" "$new_val"
    else
        echo "[INFO] 跳过修改"
    fi
}

# ------------------------------
# 3. Port参数修改（单独处理，推荐值22222）
# ------------------------------
modify_port() {
    local param="Port"
    local default="22222"  # 核心修复：推荐值改为22222
    local desc="SSH监听端口（推荐10000-65535之间的端口）"

    show_separator  # 显示进度分割线
    echo "参数: $param"
    get_current_value "$param"
    echo "说明: $desc"
    echo "推荐值: $default"

    # 关在修改前调用重复项检测
    check_duplicate "$param"

    # 严格输入验证
    if confirm_modify "是否修改?"; then
        while true; do
            read -p "输入新端口（回车使用推荐值22222）: " input_port
            if [ -z "$input_port" ]; then
                new_port="$default"
                echo "[INFO] 使用推荐值: $new_port"
                break
            else
                # 核心修复：端口范围验证（10000-65535）
                if is_number "$input_port" && [ "$input_port" -ge 10000 ] && [ "$input_port" -le 65535 ]; then
                    new_port="$input_port"
                    break
                else
                    echo "[ERROR] 无效端口，请输入10000-65535之间的数字" >&2
                fi
            fi
        done

        modify_in_place "$param" "$new_port"
    else
        echo "[INFO] 跳过修改"
    fi
}

# ------------------------------
# 初始化检查
# ------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] 请以root用户执行" >&2
    exit 1
fi

if [ ! -f "$CONFIG_FILE" ]; then
    echo "[ERROR] 配置文件不存在" >&2
    exit 1
fi

echo "[INFO] 开始SSH配置修改..."
if ! backup_config; then
    exit 1
fi

# ------------------------------
# 参数修改流程（按指定顺序，共12项）
# ------------------------------
# 1. Protocol（自定义值）
modify_custom "Protocol" "2" "SSH协议版本（推荐使用v2，v1存在设计缺陷，可输入1/2/2,1）" is_protocol
# 2. Port（单独处理）
modify_port
# 3. PermitEmptyPasswords（YES/NO）
modify_yesno "PermitEmptyPasswords" "是否允许空密码账号登录，推荐no"
# 4. PermitRootLogin（YES/NO）
modify_yesno "PermitRootLogin" "是否允许root远程登录，推荐no"
# 5. UsePAM（YES/NO）
modify_yesno "UsePAM" "是否启用PAM认证，推荐yes"
# 6. PubkeyAuthentication（YES/NO）
modify_yesno "PubkeyAuthentication" "是否启用密钥认证，推荐yes"
# 7. PasswordAuthentication（YES/NO）
modify_yesno "PasswordAuthentication" "是否启用密码认证（确保密钥配置生效后再禁用），启用PAM可能强制要求密码认证"
# 8. MaxAuthTries（自定义值）
modify_custom "MaxAuthTries" "3" "最多允许几次密码/密钥尝试(不含密钥passphrase)。如启用PAM，PAM的deny值应大于等于此值，避免PAM层提前阻断" is_number
# 9. LoginGraceTime（自定义值）
modify_custom "LoginGraceTime" "30" "认证超时秒数，单位可填s或m，最终会转为秒" is_time
# 10. ClientAliveInterval（自定义值）
modify_custom "ClientAliveInterval" "300" "客户端存活检测间隔秒数，需与ClientAliveCountMax同时使用，用于避免无响应客户端占用资源，设置0禁用检测" is_number
# 11. ClientAliveCountMax（自定义值）
modify_custom "ClientAliveCountMax" "3" "客户端存活检测最大次数，需与ClientAliveInterval同时使用，用于避免无响应客户端占用资源，设置0禁用检测" is_number
# 12. TCPKeepAlive（YES/NO）
modify_yesno "TCPKeepAlive" "设置no禁用TCP层的keepalive（避免与ClientAlive 2个检测冲突），可改用客户端的keepalive"

# ------------------------------
# 配置生效
# ------------------------------
echo
echo "========================================"
echo "✅ 配置项处理完成：$current_item/$total_items"
echo "----------------------------------------"
read -p "是否验证配置并重载服务? (y/N): " apply_choice
case "$apply_choice" in
    [Yy]*)
        verify_config
        reload_sshd
        echo "[INFO] 配置已生效"
        ;;
    *)
        echo "[INFO] 配置已修改，请手动验证：sshd -t"
        ;;
esac

echo "[INFO] 脚本执行完毕，备份文件: $BACKUP_FILE"