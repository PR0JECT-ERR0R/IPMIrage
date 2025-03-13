"""
IPMIrage - Utility Functions Module

This module contains utility functions used throughout the IPMIrage application.
"""

import re
import ipaddress
import os
import logging
import subprocess
from typing import Dict, List, Optional, Any, Tuple, Union

# Import the logger from the package
from . import logger

class ValidationError(Exception):
    """Raised when validation of an input fails."""
    pass


def normalize_mac(mac_address: str) -> str:
    """
    Convert various MAC address formats to a standardized format.
    
    Args:
        mac_address: MAC address in any format (AA:BB:CC:DD:EE:FF, AA-BB-CC-DD-EE-FF, AABBCCDDEEFF)
        
    Returns:
        Normalized MAC address in format aa:bb:cc:dd:ee:ff
    
    Examples:
        >>> normalize_mac("AA:BB:CC:DD:EE:FF")
        'aa:bb:cc:dd:ee:ff'
        >>> normalize_mac("AA-BB-CC-DD-EE-FF")
        'aa:bb:cc:dd:ee:ff'
        >>> normalize_mac("AABBCCDDEEFF")
        'aa:bb:cc:dd:ee:ff'
    """
    # Remove all separators and convert to lowercase
    mac = re.sub(r'[^a-fA-F0-9]', '', mac_address).lower()
    
    # Check if we have a valid MAC address (12 hex characters)
    if len(mac) != 12:
        logger.warning(f"Invalid MAC address format: {mac_address}")
        return mac_address
    
    # Format with colons (aa:bb:cc:dd:ee:ff)
    return ':'.join(mac[i:i+2] for i in range(0, 12, 2))


def validate_ip_address(ip: str) -> bool:
    """
    Validate if a string is a valid IP address.
    
    Args:
        ip: IP address string to validate
        
    Returns:
        True if valid, False otherwise
        
    Examples:
        >>> validate_ip_address("192.168.1.1")
        True
        >>> validate_ip_address("invalid_ip")
        False
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_subnet_mask(mask: str) -> bool:
    """
    Validate if a string is a valid subnet mask.
    
    Args:
        mask: Subnet mask (e.g., "255.255.255.0") to validate
        
    Returns:
        True if valid, False otherwise
        
    Examples:
        >>> validate_subnet_mask("255.255.255.0")
        True
        >>> validate_subnet_mask("255.255.255.5")
        False
    """
    try:
        # Try to create a network with this mask
        ipaddress.IPv4Network(f"0.0.0.0/{mask}")
        return True
    except ValueError:
        return False


def is_ip_in_subnet(ip: str, network_address: str, subnet_mask: str) -> bool:
    """
    Check if an IP address is within a given subnet.
    
    Args:
        ip: IP address to check
        network_address: Network address of the subnet
        subnet_mask: Subnet mask (e.g., "255.255.255.0")
        
    Returns:
        True if IP is in the subnet, False otherwise
        
    Raises:
        ValueError: If inputs are invalid
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        network = ipaddress.IPv4Network(f"{network_address}/{subnet_mask}", strict=False)
        return ip_obj in network
    except ValueError as e:
        raise ValueError(f"Invalid IP or subnet parameters: {e}")


def run_command(command: Union[str, List[str]], 
                shell: bool = False, 
                check: bool = True,
                capture_output: bool = True,
                timeout: Optional[int] = None) -> Tuple[int, str, str]:
    """
    Run a shell command with improved error handling.
    
    Args:
        command: Command to run (string or list)
        shell: Whether to use shell execution
        check: Whether to raise an exception on non-zero exit
        capture_output: Whether to capture stdout/stderr
        timeout: Command timeout in seconds
        
    Returns:
        Tuple of (return_code, stdout, stderr)
        
    Raises:
        subprocess.SubprocessError: If check is True and command fails
    """
    try:
        if logger.level <= logging.DEBUG:
            cmd_str = command if isinstance(command, str) else " ".join(command)
            logger.debug(f"Running command: {cmd_str}")
        
        result = subprocess.run(
            command,
            shell=shell,
            check=check,
            capture_output=capture_output,
            text=True,
            timeout=timeout
        )
        
        stdout = result.stdout.strip() if hasattr(result, 'stdout') and result.stdout else ""
        stderr = result.stderr.strip() if hasattr(result, 'stderr') and result.stderr else ""
        
        if logger.level <= logging.DEBUG:
            logger.debug(f"Command exit code: {result.returncode}")
            if stdout:
                logger.debug(f"Command stdout: {stdout[:500]}{'...' if len(stdout) > 500 else ''}")
            if stderr:
                logger.debug(f"Command stderr: {stderr[:500]}{'...' if len(stderr) > 500 else ''}")
        
        return result.returncode, stdout, stderr
    
    except subprocess.TimeoutExpired as e:
        logger.error(f"Command timed out after {timeout} seconds: {e}")
        return 124, "", str(e)  # 124 is the standard exit code for timeout
    
    except subprocess.SubprocessError as e:
        if check:
            raise
        logger.error(f"Command failed: {e}")
        return 1, "", str(e)


def get_interface_ip(interface: str) -> Optional[str]:
    """
    Get the current IP address of a network interface.
    
    Args:
        interface: Network interface name
        
    Returns:
        IP address as string if found, None otherwise
    """
    try:
        exit_code, stdout, stderr = run_command(
            ["ip", "-4", "-o", "addr", "show", interface],
            check=False
        )
        
        if exit_code != 0 or not stdout:
            return None
        
        # Parse the output to extract the IP address
        # Example output: "2: eth0    inet 192.168.1.1/24 brd 192.168.1.255 scope global eth0\       valid_lft forever preferred_lft forever"
        match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", stdout)
        if match:
            return match.group(1)
        
        return None
    
    except Exception as e:
        logger.error(f"Error getting IP for interface {interface}: {e}")
        return None


def backup_file(file_path: str) -> Optional[str]:
    """
    Create a backup of a file before modifying it.
    
    Args:
        file_path: Path to the file to backup
        
    Returns:
        Path to the backup file if successful, None otherwise
    """
    if not os.path.exists(file_path):
        return None
    
    backup_path = f"{file_path}.bak"
    try:
        import shutil
        shutil.copy2(file_path, backup_path)
        logger.debug(f"Created backup of {file_path} at {backup_path}")
        return backup_path
    except Exception as e:
        logger.error(f"Failed to create backup of {file_path}: {e}")
        return None


def create_temp_file(content: str, prefix: str = "ipmirage_", suffix: str = ".tmp") -> Optional[str]:
    """
    Create a temporary file with the given content.
    
    Args:
        content: Content to write to the file
        prefix: Prefix for the temporary file name
        suffix: Suffix for the temporary file name
        
    Returns:
        Path to the temporary file if successful, None otherwise
    """
    try:
        import tempfile
        fd, temp_path = tempfile.mkstemp(prefix=prefix, suffix=suffix)
        with os.fdopen(fd, 'w') as f:
            f.write(content)
        
        logger.debug(f"Created temporary file at {temp_path}")
        return temp_path
    except Exception as e:
        logger.error(f"Failed to create temporary file: {e}")
        return None
