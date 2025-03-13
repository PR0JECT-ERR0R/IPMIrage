#!/bin/bash

IP="$1"
STATIC_IP="$2"
NETMASK="$3"
GATEWAY="$4"
USERNAME="${5:-ADMIN}"  # Default to ADMIN if not provided
PASSWORD="${6:-ADMIN}"  # Default to ADMIN if not provided

if [ -z "$IP" ] || [ -z "$STATIC_IP" ] || [ -z "$NETMASK" ] || [ -z "$GATEWAY" ]; then
    echo "  Usage: $0 <current_ip> <static_ip> <netmask> <gateway> [username] [password]"
    echo "  Note: If username/password are not provided, defaults will be used."
    exit 1
fi

echo "  [*] Configuring IPMI for IP: $IP (New IP: $STATIC_IP)"
echo "  [*] Using credentials: $USERNAME / [PASSWORD]"

# Convert dotted-decimal netmask to CIDR prefix length
get_netmask_prefix() {
    local netmask=$1
    local prefix=0
    
    # Split the netmask into octets
    IFS='.' read -r -a octets <<< "$netmask"
    
    for octet in "${octets[@]}"; do
        # Convert to binary and count ones
        while [ $octet -gt 0 ]; do
            prefix=$((prefix + octet % 2))
            octet=$((octet / 2))
        done
    done
    
    echo $prefix
}

# Calculate the CIDR prefix from the netmask
PREFIX=$(get_netmask_prefix "$NETMASK")

# Set static IP configuration
timeout 10s ipmitool -I lanplus -H "$IP" -U "$USERNAME" -P "$PASSWORD" lan set 1 ipsrc static
timeout 10s ipmitool -I lanplus -H "$IP" -U "$USERNAME" -P "$PASSWORD" lan set 1 ipaddr "$STATIC_IP"

# Changing IP temp to gateway to connect to IPMI
echo "  [-] Changing user IP to default gateway temporarily with netmask /$PREFIX"
sudo ip addr add "$GATEWAY"/"$PREFIX" dev eth0

# Wait for the IP change to apply
sleep 5

echo "  [*] Switching to new IP: $STATIC_IP"

# Set netmask and gateway using the new IP
timeout 10s ipmitool -I lanplus -H "$STATIC_IP" -U "$USERNAME" -P "$PASSWORD" lan set 1 netmask "$NETMASK"
timeout 10s ipmitool -I lanplus -H "$STATIC_IP" -U "$USERNAME" -P "$PASSWORD" lan set 1 defgw ipaddr "$GATEWAY"

# Reset BMC to apply settings
echo "  [-] Resetting BMC to apply settings..."
ipmitool -I lanplus -H "$STATIC_IP" -U "$USERNAME" -P "$PASSWORD" mc reset warm

# Restoring networking configurations
echo "  [*] Restoring network configurations"
sudo ip addr del "$GATEWAY"/"$PREFIX" dev eth0

echo "  [*] IPMI configuration completed for IP: $STATIC_IP"
