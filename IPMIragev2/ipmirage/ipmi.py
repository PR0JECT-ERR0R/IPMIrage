"""
IPMIrage - IPMI Module

This module handles IPMI device discovery and configuration for IPMIrage.
"""

import os
import time
import concurrent.futures
import subprocess
import getpass
from typing import Dict, List, Any, Optional, Tuple, Union

# Import from package
from . import logger
from .utils import run_command, validate_ip_address

class IPMIError(Exception):
    """Raised when there's an issue with IPMI configuration."""
    pass

def verify_ipmitool_installed() -> bool:
    """
    Verify that ipmitool is installed.
    
    Returns:
        True if ipmitool is installed, False otherwise
    """
    exit_code, _, _ = run_command(
        ["which", "ipmitool"],
        check=False
    )
    return exit_code == 0

def check_ipmi_connectivity(
    ip: str, 
    username: str, 
    password: str,
    timeout: int = 5
) -> bool:
    """
    Check if an IPMI device is reachable.
    
    Args:
        ip: IP address of the IPMI device
        username: IPMI username
        password: IPMI password
        timeout: Command timeout in seconds
        
    Returns:
        True if the device is reachable, False otherwise
    """
    logger.debug(f"Checking IPMI connectivity for {ip}")
    
    try:
        cmd = [
            "ipmitool", "-I", "lanplus",
            "-H", ip,
            "-U", username,
            "-P", password,
            "chassis", "status"
        ]
        
        exit_code, _, _ = run_command(
            cmd,
            check=False,
            timeout=timeout
        )
        
        return exit_code == 0
    
    except Exception as e:
        logger.debug(f"IPMI connectivity check failed for {ip}: {e}")
        return False

def configure_ipmi_device(
    dhcp_ip: str,
    static_ip: str,
    netmask: str,
    gateway: str,
    username: str,
    password: str,
    interface: str = "eth0",
    temp_network_changes: bool = True
) -> bool:
    """
    Configure an IPMI device with a static IP.
    
    Args:
        dhcp_ip: Current DHCP-assigned IP
        static_ip: Target static IP
        netmask: Subnet mask
        gateway: Default gateway
        username: IPMI username
        password: IPMI password
        interface: Network interface name
        temp_network_changes: Whether to make temporary network changes
        
    Returns:
        True if configuration was successful, False otherwise
        
    Raises:
        IPMIError: If configuration fails
    """
    if not verify_ipmitool_installed():
        raise IPMIError(
            "ipmitool is not installed. Please install it with: "
            "apt-get install ipmitool"
        )
    
    logger.info(f"Configuring IPMI device at {dhcp_ip} with static IP {static_ip}")
    
    try:
        # Validate inputs
        for ip in [dhcp_ip, static_ip, gateway]:
            if not validate_ip_address(ip):
                raise IPMIError(f"Invalid IP address: {ip}")
        
        # First check if we can reach the device
        if not check_ipmi_connectivity(dhcp_ip, username, password):
            logger.warning(f"Cannot connect to IPMI device at {dhcp_ip}")
            logger.warning("Will attempt to configure anyway")
        else:
            logger.info(f"Successfully connected to IPMI device at {dhcp_ip} with provided credentials")
        
        # Set static IP
        logger.info(f"Setting static IP source for {dhcp_ip}")
        cmd = [
            "ipmitool", "-I", "lanplus",
            "-H", dhcp_ip,
            "-U", username,
            "-P", password,
            "lan", "set", "1", "ipsrc", "static"
        ]
        
        exit_code, stdout, stderr = run_command(cmd, timeout=10)
        
        # Set the static IP address
        logger.info(f"Setting static IP address to {static_ip}")
        cmd = [
            "ipmitool", "-I", "lanplus",
            "-H", dhcp_ip,
            "-U", username,
            "-P", password,
            "lan", "set", "1", "ipaddr", static_ip
        ]
        
        exit_code, stdout, stderr = run_command(cmd, timeout=10)
        
        # Temporarily change our IP to the gateway IP if needed
        original_ip = None
        if temp_network_changes:
            # Convert netmask to CIDR prefix
            import ipaddress
            network = ipaddress.IPv4Network(f"0.0.0.0/{netmask}", strict=False)
            prefix_length = network.prefixlen
            
            logger.info(f"Temporarily adding gateway IP {gateway} with netmask /{prefix_length} to {interface}")
            
            # Get current IP
            exit_code, stdout, _ = run_command(
                ["ip", "-4", "-o", "addr", "show", interface],
                check=False
            )
            
            if exit_code == 0 and stdout:
                import re
                match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", stdout)
                if match:
                    original_ip = match.group(1)
            
            # Add gateway IP temporarily with the correct prefix length
            exit_code, _, stderr = run_command(
                ["ip", "addr", "add", f"{gateway}/{prefix_length}", "dev", interface],
                check=False
            )
            
            if exit_code != 0 and "File exists" not in stderr:
                logger.warning(f"Failed to add gateway IP to {interface}: {stderr}")
        
        # Set subnet mask and gateway using the new IP
        try:
            # Let's wait a moment for the IP change to apply
            time.sleep(2)
            
            logger.info(f"Setting netmask to {netmask}")
            cmd = [
                "ipmitool", "-I", "lanplus",
                "-H", static_ip,
                "-U", username,
                "-P", password,
                "lan", "set", "1", "netmask", netmask
            ]
            
            exit_code, stdout, stderr = run_command(cmd, timeout=10)
            
            logger.info(f"Setting gateway to {gateway}")
            cmd = [
                "ipmitool", "-I", "lanplus",
                "-H", static_ip,
                "-U", username,
                "-P", password,
                "lan", "set", "1", "defgw", "ipaddr", gateway
            ]
            
            exit_code, stdout, stderr = run_command(cmd, timeout=10)
            
            # Reset BMC to apply settings
            logger.info(f"Resetting BMC for {static_ip} to apply settings")
            cmd = [
                "ipmitool", "-I", "lanplus",
                "-H", static_ip,
                "-U", username,
                "-P", password,
                "mc", "reset", "warm"
            ]
            
            exit_code, stdout, stderr = run_command(cmd, timeout=10, check=False)
            
            # BMC reset doesn't always return success, so we only log
            if exit_code != 0:
                logger.warning(f"BMC reset command for {static_ip} returned: {stderr or 'Unknown error'}")
                logger.warning("This may be normal as the BMC resets")
            
            # Give BMC time to reset
            logger.info(f"Waiting for BMC at {static_ip} to reset")
            time.sleep(10)
            
            # Verify configuration
            success = False
            for attempt in range(3):
                time.sleep(5)  # Wait before each attempt
                
                if check_ipmi_connectivity(static_ip, username, password, timeout=5):
                    logger.info(f"Successfully verified IPMI connectivity to {static_ip}")
                    success = True
                    break
                
                logger.warning(f"Attempt {attempt+1}/3: Cannot connect to {static_ip} after BMC reset")
            
            return success
            
        finally:
            # Restore original network config if necessary
            if temp_network_changes:
                # Convert netmask to CIDR prefix
                import ipaddress
                network = ipaddress.IPv4Network(f"0.0.0.0/{netmask}", strict=False)
                prefix_length = network.prefixlen
                
                logger.info(f"Removing temporary gateway IP {gateway}/{prefix_length} from {interface}")
                run_command(
                    ["ip", "addr", "del", f"{gateway}/{prefix_length}", "dev", interface],
                    check=False
                )
    
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout while configuring IPMI device at {dhcp_ip}")
        return False
    
    except Exception as e:
        if isinstance(e, IPMIError):
            raise
        raise IPMIError(f"Error configuring IPMI device: {e}")

def configure_ipmi_with_script(
    dhcp_ip: str,
    static_ip: str,
    netmask: str,
    gateway: str,
    username: str,
    password: str,
    script_path: str = "./ipmi_set_ip.sh"
) -> bool:
    """
    Configure an IPMI device using an external bash script.
    
    Args:
        dhcp_ip: Current DHCP-assigned IP
        static_ip: Target static IP
        netmask: Subnet mask
        gateway: Default gateway
        username: IPMI username
        password: IPMI password
        script_path: Path to the IPMI configuration script
        
    Returns:
        True if configuration was successful, False otherwise
        
    Raises:
        IPMIError: If script execution fails
    """
    if not os.path.exists(script_path):
        raise IPMIError(f"IPMI configuration script not found: {script_path}")
    
    if not os.access(script_path, os.X_OK):
        raise IPMIError(f"IPMI configuration script is not executable: {script_path}")
    
    logger.info(f"Configuring IPMI device at {dhcp_ip} with static IP {static_ip} using script")
    
    try:
        logger.debug(f"Using {'custom' if password != 'ADMIN' else 'default'} password for IPMI device at {dhcp_ip}")
        cmd = [
            script_path,
            dhcp_ip,
            static_ip,
            netmask,
            gateway,
            username,
            password
        ]
        
        exit_code, stdout, stderr = run_command(cmd, timeout=120)
        
        if exit_code != 0:
            logger.error(f"IPMI configuration script failed: {stderr}")
            return False
        
        logger.info(f"Successfully configured IPMI device: {dhcp_ip} -> {static_ip}")
        return True
    
    except Exception as e:
        logger.error(f"Error executing IPMI configuration script: {e}")
        return False

def configure_ipmi_devices_parallel(
    devices: List[Dict[str, str]],
    use_script: bool = True,
    script_path: str = "./ipmi_set_ip.sh",
    max_workers: int = 5
) -> Dict[str, bool]:
    """
    Configure multiple IPMI devices in parallel.
    
    Args:
        devices: List of device dictionaries with MAC, dhcp_ip, etc.
        use_script: Whether to use the external script
        script_path: Path to the IPMI configuration script
        max_workers: Maximum number of parallel workers
        
    Returns:
        Dictionary mapping MAC addresses to success status
    """
    logger.info(f"Configuring {len(devices)} IPMI devices with max {max_workers} parallel workers")
    
    results = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_mac = {}
        
        for device in devices:
            mac = device["mac"]
            
            if use_script:
                future = executor.submit(
                    configure_ipmi_with_script,
                    device["dhcp_ip"],
                    device["static_ip"],
                    device["netmask"],
                    device["gateway"],
                    device["username"],
                    device["password"],
                    script_path
                )
            else:
                future = executor.submit(
                    configure_ipmi_device,
                    device["dhcp_ip"],
                    device["static_ip"],
                    device["netmask"],
                    device["gateway"],
                    device["username"],
                    device["password"]
                )
            
            logger.debug(
                f"Configuration task submitted for MAC {mac} (Custom password: {'Yes' if device.get('password') != 'ADMIN' else 'No'})"
            )
            
            future_to_mac[future] = mac
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_mac):
            mac = future_to_mac[future]
            try:
                success = future.result()
                results[mac] = success
                
                if success:
                    logger.info(f"Successfully configured IPMI device for MAC {mac}")
                else:
                    logger.error(f"Failed to configure IPMI device for MAC {mac}")
                
            except Exception as e:
                logger.error(f"Exception configuring IPMI for {mac}: {e}")
                results[mac] = False
    
    # Summary
    success_count = sum(1 for success in results.values() if success)
    logger.info(f"Configured {success_count}/{len(devices)} devices successfully")
    
    return results

def create_configuration_device_list(
    mac_to_dhcp_ip: Dict[str, str],
    mappings: List[Dict[str, str]],
    config: Dict[str, Any]
) -> List[Dict[str, str]]:
    """
    Create a list of devices to configure with all necessary information.
    
    Args:
        mac_to_dhcp_ip: Dictionary mapping MAC addresses to DHCP IPs
        mappings: List of MAC-to-IP mappings from CSV
        config: Application configuration
        
    Returns:
        List of device dictionaries with all required information
    """
    devices = []
    
    # Default IPMI credentials from config
    default_username = config["ipmi"]["username"]
    default_password = config["ipmi"]["password"]
    
    for mapping in mappings:
        mac = mapping["mac"]
        
        if mac in mac_to_dhcp_ip:
            device = {
                "mac": mac,
                "dhcp_ip": mac_to_dhcp_ip[mac],
                "static_ip": mapping["static_ip"],
                "netmask": mapping["netmask"],
                "gateway": mapping["gateway"],
                "username": default_username
            }
            
            # Handle password setting and logging appropriately
            if "password" in mapping:
                logger.debug(f"Using custom password from CSV for MAC {mac}")
                device["password"] = mapping["password"]
            else:
                logger.debug(f"Using default password from config for MAC {mac}")
                device["password"] = default_password
            
            devices.append(device)
    
    return devices
