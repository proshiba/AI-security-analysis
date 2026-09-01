#!/bin/sh
set -eu

CHAIN="RAT_EMU_PURERAT"
SOURCE="172.30.53.10/32"
TARGET="45.192.211.77/32"
PORT="56001"

require_rule() {
    iptables -C "$@" >/dev/null 2>&1
}

check_policy() {
    require_rule DOCKER-USER -s "$SOURCE" -j "$CHAIN"
    require_rule "$CHAIN" -d "$TARGET" -p tcp --dport "$PORT" -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    require_rule "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    require_rule "$CHAIN" -j DROP
}

apply_policy() {
    if iptables -nL "$CHAIN" >/dev/null 2>&1; then
        check_policy
        return
    fi
    iptables -N "$CHAIN"
    iptables -A "$CHAIN" -d "$TARGET" -p tcp --dport "$PORT" -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A "$CHAIN" -j DROP
    iptables -I DOCKER-USER 1 -s "$SOURCE" -j "$CHAIN"
    check_policy
}

remove_policy() {
    if iptables -nL "$CHAIN" >/dev/null 2>&1; then
        iptables -D DOCKER-USER -s "$SOURCE" -j "$CHAIN" 2>/dev/null || true
        iptables -F "$CHAIN"
        iptables -X "$CHAIN"
    fi
}

case "${1:-}" in
    apply) apply_policy ;;
    check) check_policy ;;
    remove) remove_policy ;;
    *) echo "usage: $0 apply|check|remove" >&2; exit 2 ;;
esac
