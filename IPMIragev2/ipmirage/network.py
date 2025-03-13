"""
IPMIrage - Network Module

This module handles network configuration and DHCP server management for IPMIrage.
"""

import os
import time
import re
import contextlib
import ipaddress
from typing import Dict, List, Any, Optional, Tuple, Set

# Import from package
from . import logger
from .utils import (
    run_command, 
    normalize_mac, 
    validate_ip_address, 
    get_interface_ip,
    create_temp_file,
    backup_file
)

class NetworkError(Exception):
    """Raised when there's a network-related issue."""
    pass

class DHCPError(NetworkError):
    """Raised when there's an issue with DHCP configuration."""
    pass

def verify_interface_exists(interface: str) -> bool:
    """
    Verify that the specified network interface exists.
    
    Args:
        interface: Network interface name
        
    Returns:
        True if the interface exists, False otherwise
    """
    exit_code, _, _ = run_command(
        ["ip", "link", "show", interface],
        check=False
    )
    return exit_code == 0

def verify_dnsmasq_installed() -> bool:
    """
    Verify that dnsmasq is installed.
    
    Returns:
        True if dnsmasq is installed, False otherwise
    """
    exit_code, _, _ = run_command(
        ["which", "dnsmasq"],
        check=False
    )
    return exit_code == 0

def backup_network_config(interface: str) -> Dict[str, Any]:
    """
    Backup current network configuration for restoration.
    
    Args:
        interface: Network interface name
        
    Returns:
        Dictionary containing backup information
    """
    logger.info(f"Backing up network configuration for {interface}")
    
    backup = {
        "interface": interface,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "addresses": [],
        "routes": []
    }
    
    try:
        # Backup IP addresses
        exit_code, stdout, _ = run_command(
            ["ip", "-j", "addr", "show", interface],
            check=False
        )
        
        if exit_code == 0 and stdout:
            import json
            addr_info = json.loads(stdout)
            backup["addresses"] = addr_info
        
        # Backup routes
        exit_code, stdout, _ = run_command(
            ["ip", "-j", "route", "show", "dev", interface],
            check=False
        )
        
        if exit_code == 0 and stdout:
            import json
            route_info = json.loads(stdout)
            backup["routes"] = route_info
        
        logger.debug(f"Network backup completed for {interface}")
        return backup
    
    except Exception as e:
        logger.error(f"Failed to backup network configuration: {e}")
        return backup  # Return what we have so far

def restore_network_config(backup: Dict[str, Any]) -> bool:
    """
    Restore network configuration from backup.
    
    Args:
        backup: Backup dictionary created by backup_network_config
        
    Returns:
        True if restoration was successful, False otherwise
    """
    if not backup or "interface" not in backup:
        logger.error("Invalid backup data for network restoration")
        return False
    
    interface = backup["interface"]
    logger.info(f"Restoring network configuration for {interface}")
    
    try:
        # Flush interface
        run_command(
            ["ip", "addr", "flush", "dev", interface],
            check=False
        )
        
        # Bring interface up
        run_command(
            ["ip", "link", "set", "dev", interface, "up"],
            check=False
        )
        
        # Restore IP addresses
        addresses_restored = 0
        
        for addr_obj in backup.get("addresses", []):
            for addr_info in addr_obj.get("addr_info", []):
                if "local" in addr_info and "prefixlen" in addr_info:
                    ip = addr_info["local"]
                    prefix = addr_info["prefixlen"]
                    
                    try:
                        run_command(
                            ["ip", "addr", "add", f"{ip}/{prefix}", "dev", interface],
                            check=False
                        )
                        addresses_restored += 1
                    except Exception as e:
                        logger.warning(f"Failed to restore IP {ip}/{prefix}: {e}")
        
        # Restore routes
        routes_restored = 0
        
        for route in backup.get("routes", []):
            dst = route.get("dst", "")
            gateway = route.get("gateway", "")
            
            if gateway:
                try:
                    cmd = ["ip", "route", "add", dst, "via", gateway, "dev", interface]
                    run_command(cmd, check=False)
                    routes_restored += 1
                except Exception as e:
                    logger.warning(f"Failed to restore route {dst} via {gateway}: {e}")
        
        logger.info(
            f"Network restoration completed: {addresses_restored} addresses and "
            f"{routes_restored} routes restored"
        )
        return True
    
    except Exception as e:
        logger.error(f"Failed to restore network configuration: {e}")
        return False

@contextlib.contextmanager
def network_configuration_context(interface: str):
    """
    Context manager for network configuration changes.
    
    Args:
        interface: Network interface name
        
    Yields:
        None
        
    Example:
        >>> with network_configuration_context("eth0"):
        ...     setup_eth0_for_dhcp("eth0", "192.168.100.1")
    """
    backup = backup_network_config(interface)
    try:
        yield
    except Exception as e:
        logger.error(f"Exception in network configuration: {e}")
        logger.info("Attempting to restore network configuration")
        restore_network_config(backup)
        raise
    # Note: We don't automatically restore on successful completion
    # as the changes may be desired

def setup_eth0_for_dhcp(interface: str, dhcp_ip: str) -> None:
    """
    Set up network interface for DHCP server.
    
    Args:
        interface: Network interface name
        dhcp_ip: IP address to assign to the interface
        
    Raises:
        NetworkError: If setup fails
    """
    logger.info(f"Setting up {interface} with IP {dhcp_ip} for DHCP server")
    
    # Verify interface exists
    if not verify_interface_exists(interface):
        raise NetworkError(f"Network interface {interface} does not exist")
    
    # Validate IP
    if not validate_ip_address(dhcp_ip):
        raise NetworkError(f"Invalid IP address: {dhcp_ip}")
    
    try:
        # Flush interface
        exit_code, _, stderr = run_command(
            ["ip", "addr", "flush", "dev", interface],
            check=False
        )
        
        if exit_code != 0:
            logger.warning(f"Failed to flush interface {interface}: {stderr}")
        
        # Add IP address
        exit_code, _, stderr = run_command(
            ["ip", "addr", "add", f"{dhcp_ip}/24", "dev", interface],
            check=True
        )
        
        # Bring interface up
        exit_code, _, stderr = run_command(
            ["ip", "link", "set", "dev", interface, "up"],
            check=True
        )
        
        # Verify IP was assigned
        current_ip = get_interface_ip(interface)
        if current_ip != dhcp_ip:
            raise NetworkError(
                f"Failed to assign IP {dhcp_ip} to {interface}, current IP: {current_ip or 'None'}"
            )
        
        logger.info(f"Successfully configured {interface} with IP {dhcp_ip}")
    
    except Exception as e:
        if isinstance(e, NetworkError):
            raise
        raise NetworkError(f"Error setting up interface {interface}: {e}")

@contextlib.contextmanager
def temp_dhcp_config(config_file: str, content: str):
    """
    Context manager for temporary DHCP configuration.
    
    Args:
        config_file: Path to configuration file
        content: Configuration content
        
    Yields:
        Path to the configuration file
        
    Example:
        >>> with temp_dhcp_config("/etc/dnsmasq.d/ipmirage.conf", "..."):
        ...     # Do DHCP operations
    """
    # Create parent directory if it doesn't exist
    os.makedirs(os.path.dirname(config_file), exist_ok=True)
    
    # Backup existing config if it exists
    backup_path = None
    if os.path.exists(config_file):
        backup_path = backup_file(config_file)
    
    try:
        # Write new configuration
        with open(config_file, "w") as f:
            f.write(content)
        
        yield config_file
        
    finally:
        # Clean up the configuration file
        try:
            if os.path.exists(config_file):
                os.remove(config_file)
                logger.debug(f"Removed temporary DHCP configuration: {config_file}")
            
            # Restore backup if it exists
            if backup_path and os.path.exists(backup_path):
                import shutil
                shutil.copy2(backup_path, config_file)
                os.remove(backup_path)
                logger.debug(f"Restored original DHCP configuration: {config_file}")
                
        except Exception as e:
            logger.warning(f"Failed to clean up DHCP configuration: {e}")

def create_dhcp_pool(config: Dict[str, Any]) -> None:
    """
    Create a DHCP pool for IPMI discovery.
    
    Args:
        config: Application configuration
        
    Raises:
        DHCPError: If DHCP setup fails
    """
    # Check for dnsmasq
    if not verify_dnsmasq_installed():
        raise DHCPError(
            "dnsmasq is not installed. Please install it with: "
            "apt-get install dnsmasq"
        )
    
    # Extract settings
    interface = config["network"]["interface"]
    dhcp_range_start = config["network"]["dhcp_range_start"]
    dhcp_range_end = config["network"]["dhcp_range_end"]
    subnet_mask = config["network"]["subnet_mask"]
    dhcp_config_file = config["dhcp"]["config_file"]
    
    logger.info(
        f"Creating DHCP pool on {interface} with range {dhcp_range_start}-{dhcp_range_end}"
    )
    
    # Create DHCP configuration
    dhcp_config = f"""
# IPMIrage DHCP Configuration
# Created: {time.strftime("%Y-%m-%d %H:%M:%S")}

# Disable DNS functionality (only DHCP)
port=0
bind-interfaces

interface={interface}
dhcp-range={dhcp_range_start},{dhcp_range_end},{subnet_mask},12h
log-dhcp
"""
    
    # Use context manager for DHCP configuration
    with temp_dhcp_config(dhcp_config_file, dhcp_config):
        try:
            # Check and stop dnsmasq if it's already running
            exit_code, _, _ = run_command(
                ["systemctl", "is-active", "dnsmasq"],
                check=False
            )
            
            if exit_code == 0:
                logger.info("Stopping existing dnsmasq service")
                run_command(
                    ["systemctl", "stop", "dnsmasq"],
                    check=False
                )
            
            # Start dnsmasq with our configuration
            logger.info("Starting dnsmasq with IPMIrage configuration")
            exit_code, _, stderr = run_command(
                ["systemctl", "start", "dnsmasq"],
                check=True
            )
            
            # Verify service is running
            exit_code, stdout, _ = run_command(
                ["systemctl", "is-active", "dnsmasq"],
                check=False
            )
            
            if exit_code != 0 or stdout.strip() != "active":
                raise DHCPError(f"Failed to start dnsmasq: {stderr}")
            
            logger.info("DHCP pool is now active")
            
        except Exception as e:
            if isinstance(e, DHCPError):
                raise
            raise DHCPError(f"Error creating DHCP pool: {e}")

def stop_dhcp_server() -> None:
    """
    Stop the DHCP server (dnsmasq).
    
    Raises:
        DHCPError: If stopping fails
    """
    logger.info("Stopping DHCP server")
    
    try:
        exit_code, stdout, stderr = run_command(
            ["systemctl", "stop", "dnsmasq"],
            check=False
        )
        
        if exit_code != 0:
            logger.warning(f"Failed to stop dnsmasq: {stderr}")
        else:
            logger.info("DHCP server stopped successfully")
    
    except Exception as e:
        raise DHCPError(f"Error stopping DHCP server: {e}")

def get_dhcp_ip(mac_addr: str, leases_file: str) -> Optional[str]:
    """
    Find the DHCP-assigned IP for a given MAC address.
    
    Args:
        mac_addr: MAC address to look up
        leases_file: Path to DHCP leases file
        
    Returns:
        IP address as string if found, None otherwise
    """
    if not os.path.exists(leases_file):
        logger.warning(f"DHCP leases file not found: {leases_file}")
        return None
    
    try:
        # Normalize the MAC address format for comparison
        normalized_mac = normalize_mac(mac_addr)
        
        with open(leases_file, "r") as file:
            leases = file.readlines()
        
        for lease in leases:
            parts = lease.split()
            if len(parts) >= 3:  # At least timestamp, MAC, IP
                lease_mac = normalize_mac(parts[1])
                if lease_mac == normalized_mac:
                    return parts[2]  # IP address
        
        return None
    
    except Exception as e:
        logger.error(f"Error reading DHCP leases: {e}")
        return None

def wait_for_dhcp_assignments(
    config: Dict[str, Any],
    mac_addresses: List[str],
    timeout: int = 60,
    check_interval: int = 5
) -> Dict[str, str]:
    """
    Wait for DHCP assignments for the given MAC addresses.
    
    Args:
        config: Application configuration
        mac_addresses: List of MAC addresses to monitor
        timeout: Maximum time to wait in seconds
        check_interval: How often to check for new assignments
        
    Returns:
        Dictionary mapping MAC addresses to assigned IPs
    """
    leases_file = config["dhcp"]["leases_file"]
    
    if not os.path.exists(os.path.dirname(leases_file)):
        raise DHCPError(f"DHCP leases directory does not exist: {os.path.dirname(leases_file)}")
    
    logger.info(f"Waiting for DHCP assignments (up to {timeout} seconds)")
    
    mac_to_ip = {}
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        # Check for new assignments
        for mac in mac_addresses:
            if mac in mac_to_ip:
                continue  # Already found
            
            ip = get_dhcp_ip(mac, leases_file)
            if ip:
                mac_to_ip[mac] = ip
                logger.info(f"Found DHCP assignment: {mac} -> {ip}")
        
        # Check if all found
        if len(mac_to_ip) == len(mac_addresses):
            logger.info("All MAC addresses have been assigned IPs")
            break
        
        # Wait before checking again
        remaining = len(mac_addresses) - len(mac_to_ip)
        logger.info(f"Waiting for {remaining} more DHCP assignments... ({check_interval}s)")
        time.sleep(check_interval)
    
    # Log missing assignments
    missing = [mac for mac in mac_addresses if mac not in mac_to_ip]
    if missing:
        logger.warning(f"Could not find DHCP assignments for {len(missing)} MAC addresses")
        for mac in missing:
            logger.warning(f"  - {mac}")
    
    return mac_to_ip
