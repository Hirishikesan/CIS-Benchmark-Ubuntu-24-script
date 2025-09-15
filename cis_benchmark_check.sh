#!/usr/bin/env bash

SUCCESS_LOG="success.log"
ERROR_LOG="error.log"

> "$SUCCESS_LOG"
> "$ERROR_LOG"

global counter=0
pass_counter=0
fail_counter=0
pass() {
    ((counter++))
    ((pass_counter++))
    echo "$counter.[PASS] $1"
    echo "$pass_counter. $1" >> "$SUCCESS_LOG"
    echo ""
}

fail() {
    ((counter++))
    ((fail_counter++))
    echo "$counter. [FAIL] $1"
    echo "$fail_counter. $1" >> "$ERROR_LOG"
    echo ""
}



#Ensure usb-storage kernel module is not available
path="/etc/modprobe.d/"
module="usb-storage"

install_found=0
blacklist_found=0

for entry in "$path"*.conf; do
    if [ -f "$entry" ]; then
        if grep -Pq "^[^#]*install\s$module\s/bin/false" "$entry" && grep -Pq "^[^#]*blacklist\s$module" "$entry"; then
            pass "install usb-storage /bin/false and  blacklist usb-storage has been configured in $entry"
        else
            fail "Configure both install usb-storage /bin/false and  blacklist usb-storage in $entry"
        fi
    fi
done




#Ensure the server has partitions
check_partition() {
    local mount_point=$1
    local setting_name=$2
    if [ -d "$mount_point" ]; then
        pass "$setting_name ($mount_point)"
    else
        fail "$setting_name ($mount_point)"
    fi
}

PARTITIONS=(
    "/tmp:Ensure /tmp is a seperate partition"
    "/home:Ensure /home is a seperate partition"
    "/var:Ensure /var is a seperate partition"
    "/var/tmp:Ensure /var/tmp is a seperate partition"
    "/var/log:Ensure /var/log is a sepearate partition"
)

for entry in "${PARTITIONS[@]}"; do
    mount_point="${entry%%:*}"
    setting_name="${entry#*:}"
    check_partition "$mount_point" "$setting_name"
done


#Ensure Apparmor has been installed
dpkg-query -s apparmor &>/dev/null && pass "Apparmor is installed" || fail "Apparmor is not installed"


#Ensure ufw has been installed
dpkg-query -s ufw &>/dev/null && pass "UFW firwall is installed" || fail "UFW firewall is not installed"


#Ensure display message for /etc/issue has been configured
grep -q "^[^#]*Authorized users only. All activity may be monitored and reported." /etc/issue && pass "Message has been displayed correctly on /etc/issue" || fail "Message not available /etc/issue - This setting is Non Compliant"


#Ensure display message for /etc/issue.net has been configured
grep -q "^[^#]*Authorized users only. All activity may be monitored and reported." /etc/issue.net && pass "Message has been displayed correctly on /etc/issue.net" || fail "Message not available /etc/issue - This setting is Non Compliant"


#Ensure GNOME/GDM screen locks settings is set
Screensaver_settings=(
    "[org/gnome/desktop/session]"
    #3 mins inactivity before the screen goes off
    "idle-delay=180"
    "[org/gnome/desktop/screensaver]"
    #10 seconds before locking the screen
    "lock-delay=10"
    # Lock desktop screensaver settings 
    "/org/gnome/desktop/session/idle-delay" 
    "/org/gnome/desktop/screensaver/lock-delay"
)
directory="/etc/dconf/db/local.d/"
file=$directory/00-screensaver
for entry in "${Screensaver_settings[@]}"; do
    if [ -f $directory ]; then
        grep -q "^[^#]*$entry" $file && pass "$entry is present, So it's found to be compliant" || pass "$entry is not present, So it's found to be Non-compliant"
    else
        fail "$directory is not present, So kindly create the file as per the standard document"
        break
    fi
done


#Ensure the services are not installed
Services=(
    "autofs"
    "avahi daemon"
    "isc-dhcp-server"
    "bind9"
    "vsftpd"
    "slapd"
    "dovecot-imapd"
    "dovecot-pop3d"
    "nfs-kernel-server"
    "cups"
    "rpcbind"
    "rsync"
    "samba"
    "snmpd"
    "tftp"
    "squid"
    "xinetd"
    "xserver-common"
    "nis"
    "rsh-client"
    "talk"
    "inetutils-telnet"
    "telnet"
    "ftp"
    "tnftp"
)
for entry in "${Services[@]}"; do
dpkg-query -s $entry &>/dev/null && fail "$entry is installed on the server, Kindly confirm that this service is needed or not" || pass "$entry is not installed on the server, so found to be compliant"
done


#Ensure crontab is restricted to authorized 
File=(
    "/etc/cron.allow"
    "/etc/cron.deny"
)
for entry in "${File[@]}"; do

if [ -f $entry ]; then
    permission=$(stat -c "%a" "$entry")
    owner=$(stat -c "%U" "$entry")
    group=$(stat -c "%G" "$entry")

    if [ "$permission" -eq 640 ] && [ "$owner" == "root" ] && [ "$group" == "root" ]; then
        pass "$entry permission is $permission and Owner is $owner and Group Owner is $group"
    else
        fail "$entry is found to be Non-compliant, Kindly check the file permission and change into 640 Permission and Ownership into root and Group Ownership into root"
    fi
else
    fail "$entry is not exist in the server"
fi
done


#Ensure Blutooth Service are not in use
dpkg-query -s bluez &>/dev/null && fail "Bluetooth service in Installed, kindly confim the need of this service" || pass "Bluetooth servive is not installed"


#Ensure Kernel parameter has been configured 
File="/etc/sysctl.conf"


#To Enable the setting use sysctl -w <parameter>=<value>
parameter=(
    #Ensure ip forwarding is disabled
    "net.ipv4.ip_forward=0"
    "net.ipv6.conf.all.forwarding=0"
    #Ensure packet redirect sending is disabled
    "net.ipv4.conf.all.send_redirects=0"
    "net.ipv4.conf.default.send_redirects=0"
    #Ensure broadcast icmp requests are ignored
    "net.ipv4.icmp_echo_ignore_broadcasts=1"
    #Ensure icmp redirects are not accepted 
    "net.ipv4.conf.all.accept_redirects=0" 
    "net.ipv4.conf.default.accept_redirects=0" 
    "net.ipv6.conf.all.accept_redirects=0" 
    "net.ipv6.conf.default.accept_redirects=0"
    #Ensure secure icmp redirects are not accepted 
    "net.ipv4.conf.all.secure_redirects=0" 
    "net.ipv4.conf.default.secure_redirects=0"
    #Ensure reverse path filtering is enabled
    "net.ipv4.conf.all.rp_filter=1" 
    "net.ipv4.conf.default.rp_filter=1"
    #Ensure source routed packets are not accepted 
    "net.ipv4.conf.all.accept_source_route=0" 
    "net.ipv4.conf.default.accept_source_route=0"
    "net.ipv6.conf.all.accept_source_route=0" 
    "net.ipv6.conf.default.accept_source_route=0"
    #Ensure suspicious packets are logged 
    "net.ipv4.conf.all.log_martians=1" 
    "net.ipv4.conf.default.log_martians=1"
    #Ensure tcp syn cookies is enabled
    "net.ipv4.tcp_syncookies=1"
    #Ensure ipv6 router advertisements are not accepted 
    "net.ipv6.conf.all.accept_ra=1"
    "net.ipv6.conf.default.accept_ra=1" 
)
for entry in "${parameter[@]}"; do
    grep -q "^[^#]*$entry" "$File" && pass "${entry%%:*} has been configured" || fail "${entry%%:*} has not configured properly"
done


#Ensure iptables-persistent is not installed with ufw
dpkg-query -s iptables-persistent &>/dev/null && fail "Iptables-persistent has been installed, So found to be Non-Compliant" || pass "Iptables-persistent has not been installed, So found to be Compliant"


#Ensure ufw service is enabled
dpkg-query -s ufw &>/dev/null && { 
if ufw status numbered | grep -qE "22/tcp\s+Allow"; then
    pass "ufw service had been enabled and TCP port 22 has been configured"
else
    fail "TCP port 22 has not configured"
fi 
} || fail "UFW firewall is not installed"


#Ensure nftables is installed
dpkg-query -s nftables &>/dev/null && pass "nftable has been installed" || fail "nftable has not installed"


#Ensure a nftables table exists
if nft list tables &>/dev/null; then
    pass "nftable list has been present"
else
    fail "nftable list is not configured"
fi


#Ensure permissions on /etc/ssh/sshd_config are configured 
Location="/etc/ssh/"
for file in "$Location"*_config; do
    if [ -f "$file" ]; then
        permission=$(stat -c "%a" "$file")
        owner=$(stat -c "%U" "$file")
        group=$(stat -c "%G" "$file")
        if [ "$permission" -eq 600 ] && [ "$owner" == "root" ] && [ "$group" == "root" ]; then
            pass "$file permission of the file is correct"
        else 
            fail "Change the file permission to 600 and owner and group must be root for $file"
        fi
        for file1 in "$file"/*.conf; do
            if [ -f "$file1" ]; then
                permission1=$(stat -c "%a" "$file1")
                owner1=$(stat -c "%U" "$file1")
                group1=$(stat -c "%G" "$file1")
                if [ "$permission1" -eq 600 ] && [ "$owner1" == "root" ] && [ "$group1" == "root" ]; then
                    pass "$file1 permission of the file is correct"
                else 
                    fail "Change the file permission to 600 and owner and group must be root for $file1"
                fi
            else
                fail "$file1 is not present in the directory"
            fi
        done
    else
        fail "$file is not present in the directory"
    fi
done


#Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured
parameter=(
    "clientaliveinterval 15" 
    "clientalivecountmax 3"
)
for value in "${parameter[@]}"; do

grep -q "^[^#]*$value" "/etc/ssh/sshd_config" && pass "The /etc/ssh/sshd_config file to set the $value is included" || fail "The /etc/ssh/sshd_config file to set the $value is not included" 

done

Parameter=(
    #Ensure sshd Banner is configured
    "Banner /etc/issue.net"
    #Ensure sshd Ciphers are configured
    "Ciphers -3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,chacha20-poly1305@openssh.com"
    #Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured
    "Clientaliveinterval 15" 
    "Clientalivecountmax 3"
    #Ensure sshd DisableForwarding is enabled 
    "DisableForwarding yes"
    #Ensure sshd GSSAPIAuthentication is disabled
    "GSSAPIAuthentication no"
    #Ensure sshd HostbasedAuthentication is disabled
    "HostbasedAuthentication no"
    #Ensure sshd IgnoreRhosts is enabled 
    "IgnoreRhosts yes"
    #Ensure sshd KexAlgorithms is configured
    "KexAlgorithms -diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1"
    #Ensure sshd LoginGraceTime is configured 
    "LoginGraceTime 60"
    #Ensure sshd LogLevel is configured
    "LogLevel INFO"
    #Ensure sshd MACs are configured 
    "MACs -hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-sha1-96,umac-64@openssh.com,hmac-md5-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com"
    #Ensure sshd MaxAuthTries is configured 
    "MaxAuthTries 4" 
    #Ensure sshd MaxSessions is configured
    "MaxSessions 10"
    #Ensure sshd PermitEmptyPasswords is disabled
    "PermitEmptyPasswords no"
    #Ensure sshd PermitRootLogin is disabled
    "PermitRootLogin no"
    #Ensure sshd PermitUserEnvironment is disabled 
    "PermitUserEnvironment no"
)

for entry in "${Parameter[@]}"; do
grep -q "^[^#]*$entry" "/etc/ssh/sshd_config" && pass "The /etc/ssh/sshd_config file to set  the $entry parameter is included" || fail "The /etc/ssh/sshd_config file to set the $entry parameter is not included" 
done


#Ensure users must provide password for privilege escalation
grep -r "^[^#].*NOPASSWD" /etc/sudoers && fail "Kindly remove NOPASSWD field and change it into ALL=ALL(ALL)" || pass "There is no issue on the sudoers"


path=(
    #Ensure pam_unix module is enabled
    "/etc/pam.d/common-account:account   [success=1 new_authtok_reqd=done default=ignore]   pam_unix.so" 
    "/etc/pam.d/common-session:session   required   pam_unix.so"
    "/etc/pam.d/common-auth:auth   [success=2 default=ignore]   pam_unix.so try_first_pass"
    "/etc/pam.d/common-password:password   [success=1 default=ignore]   pam_unix.so obscure use_authtok try_first_pass yescrypt"
    #Ensure pam_faillock module is enabled 
    "/etc/pam.d/common-auth:auth     requisite                       pam_faillock.so preauth"
    "/etc/pam.d/common-auth:auth     [default=die]                   pam_faillock.so authfail"
    "/etc/pam.d/common-account:account       required                        pam_faillock.so"
    #Ensure pam_pwquality module is enabled
    "/etc/pam.d/common-password:password   requisite   pam_pwquality.so retry=3" 
    #Ensure pam_pwhistory module is enabled
    "/etc/pam.d/common-password:password   requisite   pam_pwhistory.so remember=24 enforce_for_root try_first_pass use_authtok"
    #Ensure password failed attempts lockout is configured 
    "/etc/security/faillock.conf:deny=5"
    #Ensure password unlock time is configured
    "/etc/security/faillock.conf:unlock_time=900"
    
    #Ensure password quality checking is enforced
    "/etc/security/pwquality.conf:enforcing=0"
)

for entry in "${path[@]}"; do
    location="${entry%%:*}"
    parameter="${entry#*:}"

    if [ -f "$location" ]; then
        grep -q "^[[:space:]]*[^#].*$parameter" "$location" &>/dev/null && pass "$parameter is present in $location" || fail "$parameter is not present in $location"
    else
        fail "$location the itself not present"
    fi
done

path=(
    #Ensure minimum password length is configured 
    "/etc/security/pwquality.conf.d/:minlen=14"
    #Ensure password complexity is configured
    "/etc/security/pwquality.conf.d/:minclass=3"
    "/etc/security/pwquality.conf.d/:ucredit=-2"
    "/etc/security/pwquality.conf.d/:lcredit=-2"
    "/etc/security/pwquality.conf.d/:dcredit=-1"
    "/etc/security/pwquality.conf.d/:ocredit=0"
)
for entry in "${path[@]}"; do
    location="${entry%%:*}"
    parameter="${entry#*:}"
    for entry1 in "$location"*.conf; do
        if [ -f "$entry1" ]; then
            grep -q "^[^#]*$parameter" "$entry1" &>/dev/null && pass "$parameter is present in $entry1" || fail "$parameter is not present in $entry1"
        else
            fail "$entry1 the itself not present"
        fi
    done
done
path=(
    # Ensure password expiration is configured
    "/etc/login.defs:PASS_MAX_DAYS 60"
    #Ensure minimum password days is configured
    "/etc/login.defs:PASS_MIN_DAYS   10"
    #Ensure password expiration warning days is configured
    "/etc/login.defs:PASS_WARN_AGE 7"
    #Ensure root user umask is configured
    "/root/.bash_profile:umask 0027"
    "/root/.bashrc:umask 0027"
)
for entry in "${path[@]}"; do
    location="${entry%%:*}"
    parameter="${entry#*:}"
    para_name="${parameter%% *}"
    para_value="${parameter#* }"

    if [ -f "$location" ]; then
        if grep -Eq "^[[:space:]]*[^#]*${para_name}[[:space:]]+${para_value}" "$location"; then
            pass "$parameter is present in $location" 
        else 
            fail "$parameter is not present in $location"
        fi
    else
        fail "$location the itself not present"
    fi
done


#Ensure nologin is not listed in /etc/shells
grep -q "nologin" "/etc/shells" &>/dev/null && fail "Remove nologin from /etc/shells" || pass "nologin is not present in /etc/shells, so found to be compliant"


#Ensure default user shell timeout is configured
path=(
    "/etc/profile.d"
    "/etc/profile"
    "/etc/bashrc"
)

for entry in "${path[@]}"; do
    if [ -f $entry ]; then
        if [ "$entry" == "/etc/profile.d" ]; then
            for entry1 in "$entry"/*.sh; do
                if [ -f $entry1 ]; then
                    if grep -Pzq '^[^#]*TMOUT=900\s*\n\s*readonly\sTMOUT\s*\n\s*export\sTMOUT' $entry1 || grep -Eq '^[^#]*readonly\sTMOUT=900\s;\sexport\sTMOUT' $entry1; then
                        pass "TMOUT is present in $entry1"
                    else
                        fail "TMOUT id not present in $entry1"
                    fi
                else 
                    fail "$entry1 is not present"
                fi
            done
        else
            if [ -f $entry1 ]; then
                if grep -Pzq '^[^#]*TMOUT=900\s*\n\s*readonly\sTMOUT\s*\n\s*export\sTMOUT' $entry || grep -Eq '^[^#]*readonly\sTMOUT=900\s;\sexport\sTMOUT' $entry; then
                        pass "TMOUT is present in $entry"
                    else
                        fail "TMOUT id not present in $entry"
                fi
            else 
                    fail "$entry1 is not present"
            fi
        fi
    else
        fail "$entry file doesn't exist"
    fi
done
    
path=(
    #Ensure permissions on /etc/passwd are configured 644
    "/etc/passwd"
    #Ensure permissions on /etc/group are configured 644
    "/etc/group"
    #Ensure permissions on /etc/shadow are configured 640
    "/etc/shadow"
    #Ensure permissions on /etc/gshadow are configured 640
    "/etc/gshadow"
    #Ensure permissions on /etc/shells are configured 644
    "/etc/shells"
    #Ensure permissions on /etc/security/opasswd are 600
    "/etc/security/opasswd"
    "/etc/security/opasswd.old"
)

for entry in "${path[@]}"; do
    if [ -f "$entry" ]; then
        permission=$(stat -c "%a" "$entry")
        user=$(stat -c "%U" "$entry")
        group=$(stat -c "%G" "$entry")

        if [ $entry == "/etc/security/opasswd" ] || [ $entry == "/etc/security/opasswd.old" ]; then
            if [ $permission -eq 600 ] && [ "$user" == "root" ] && [ "$group" == "root" ]; then
                pass "$entry permissions are set properly"
            else
                fail "$entry check the file permissions"
            fi
        elif [ $entry == "/etc/shadow" ] || [ $entry == "/etc/gshadow" ]; then
            if [ $permission -eq 640 ] && [ "$user" == "root" ] && [ "$group" == "root" ]; then
                pass "$entry permissions are set properly"
            else
                fail "$entry check the file permissions"
            fi
        else 
            if [ $permission -eq 644 ] && [ "$user" == "root" ] && [ "$group" == "root" ]; then
                pass "$entry permissions are set properly"
            else
                fail "$entry check the file permissions"
            fi
        fi
    else
        fail "$entry file doesnot exist"
    fi
done


#Ensure /etc/shadow password fields are not empty
if [ -s "/etc/shadow" ]; then
    pass "/etc/shadow file is not empty"
else
    fail "/etc/shadow file is empty"
fi


#Ensure no duplicate UIDs and GIDs exist /etc/passwd and /etc/group
#Ensure no duplicate names exist /etc/passwd and /etc/group
path=(
    "/etc/passwd"
    "/etc/group"
)

for entry in "${path[@]}"; do
    duplicate_ID=$(cut -d: -f3 $entry | sort | uniq -d)
    duplicate_name=$(cut -d: -f1 $entry | sort | uniq -d)

    if [ -n "$duplicate_ID" ]; then
        fail "Duplicate IDs are present in $entry"
    else
        pass "No duplicate IDs present in $entry"
    fi
    if [ -n "$duplicate_name" ]; then
        fail "Duplicate name are present in $entry"
    else
        pass "No duplicate name present in $entry"
    fi
done

echo "This CIS Benchmark script check for 136 settings on Ubuntu 24 server"
echo "----------------------- This is end -------------------------------"
        
