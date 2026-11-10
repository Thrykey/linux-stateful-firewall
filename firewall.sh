 #!/bin/bash

# ==========================================
# ZMIENNE KONFIGURACYJNE
# ==========================================

UPLINK="enp0s3"              #
ADMIN_IP="192.0.2.10"        # IP windowsa, generic ip 
DNS1="8.8.8.8"               # Primary DNS
DNS2="1.1.1.1"               # Secondary DNS
PORT_WWW="80"
PORT_FTP="21"
PORT_SSH="22"


if [ "$1" = "start" ]; then
    echo "Uruchamiam dynamicznego firewalla z aktywna ochrona uslug..."
    # 1. Czyszczenie starych regul firewalla (w tym tablicy mangle)
    iptables -F
    iptables -X
    iptables -t mangle -F

    # 2. Wylaczenie forwardowania pakietow i obslugi IPv6 na poziomie jadra (sysctl)
    sysctl -w net.ipv4.ip_forward=0
    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1

    # 3. POLITYKA DOMYSLNA: DROP (Wszystko zakazane, dopoki nie zezwolimy)
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP

    # 4. Pelny dostep dla interfejsu lokalnego loopback (lo)
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # 5. BOGONS - Odrzucanie sfalszowanego ruchu z puli niedozwolonych adresow publicznych
    # (Pominąłem tu LAN 10.x.x.x, zeby nie odciac laboratorium)
    BOGONS=("0.0.0.0/8" "127.0.0.0/8" "224.0.0.0/3")
    for BOGON in "${BOGONS[@]}"; do
        iptables -A INPUT -i $UPLINK -s $BOGON -j DROP
    done
    
    # ==========================================
    # LOGIKA FIREWALLA DYNAMICZNEGO (STATEFUL)
    # ==========================================

    # Ladowanie modulu sledzacego dane protokolu FTP (ALG)
    # Bez tego FTP w trybie pasywnym nie dziala przy polityce DROP!
    modprobe nf_conntrack_ftp

    # 6. Dopuszczenie pelnego ruchu dla pakietow powiazanych z sesjami ESTABLISHED i RELATED
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # ==========================================
    # OTWIERANIE USLUG (Tylko nowe polaczenia - NEW)
    # ==========================================

    # 7. Usluga WWW + Ochrona przed atakiem DoS (connlimit - max 30 polaczen z IP)
    iptables -A INPUT -i $UPLINK -p tcp --dport $PORT_WWW -m state --state NEW -m connlimit --connlimit-above 30 -j REJECT --reject-with tcp-reset
    iptables -A INPUT -i $UPLINK -p tcp --dport $PORT_WWW -m state --state NEW -j ACCEPT

    # 8. Usluga FTP (handshake)
    iptables -A INPUT -i $UPLINK -p tcp --dport $PORT_FTP -m state --state NEW -j ACCEPT

    # 9. Ruch do zdefiniowanych serwerow DNS (na zewnatrz)
    iptables -A OUTPUT -o $UPLINK -p udp -d $DNS1 --dport 53 -m state --state NEW -j ACCEPT
    iptables -A OUTPUT -o $UPLINK -p udp -d $DNS2 --dport 53 -m state --state NEW -j ACCEPT
    iptables -A OUTPUT -o $UPLINK -p tcp -d $DNS1 --dport 53 -m state --state NEW -j ACCEPT
    iptables -A OUTPUT -o $UPLINK -p tcp -d $DNS2 --dport 53 -m state --state NEW -j ACCEPT

    # 10. SSH - dostep administracyjny TYLKO z przypisanego IP (Admin)
    iptables -A INPUT -i $UPLINK -p tcp --dport $PORT_SSH -s $ADMIN_IP -m state --state NEW -j ACCEPT

    # 11. Logowanie odrzucanych pakietow na port SSH od nieuprawnionych osob
    # (Zapisze sie do logow kernela zanim wpadnie w domyslny DROP)
    iptables -A INPUT -i $UPLINK -p tcp --dport $PORT_SSH -m state --state NEW -j LOG --log-prefix "HACK_SSH_DROP: " --log-level 4

    # ==========================================
    # MODYFIKACJE MANGLE
    # ==========================================

    # 12. Zmiana TTL dla wszystkich wychodzacych pakietow na 43
    iptables -t mangle -A POSTROUTING -o $UPLINK -j TTL --ttl-set 43
    echo "Firewall aktywny!"


elif [ "$1" = "stop" ]; then
    echo "Wylaczam firewalla..."
    iptables -F
    iptables -X
    iptables -t mangle -F
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    # Przywracanie sysctl
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv6.conf.all.disable_ipv6=0
    sysctl -w net.ipv6.conf.default.disable_ipv6=0

    echo "Firewall zdezaktywowany."
else
    echo "Błąd. Uzycie: $0 {start|stop}"

fi 
