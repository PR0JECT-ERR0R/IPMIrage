"""
IPMIrage - Configuration Module

This module handles loading and validating configuration for the IPMIrage application.
"""

import os
import csv
import yaml
import ipaddress
from typing import Dict, List, Any, Optional, Tuple

# Import from the package
from . import logger
from .utils import validate_ip_address, validate_subnet_mask, is_ip_in_subnet

class ConfigurationError(Exception):
    """Raised when there's an issue with configuration."""
    pass

class CSVFormatError(ConfigurationError):
    """Raised when there's an issue with CSV format."""
    pass

def load_yaml_config(config_file: str) -> Dict[str, Any]:
    """
    Load configuration from YAML file.
    
    Args:
        config_file: Path to YAML configuration file
        
    Returns:
        Configuration dictionary
        
    Raises:
        ConfigurationError: If file not found or has invalid format
    """
    try:
        with open(config_file, "r") as file:
            config = yaml.safe_load(file)
        
        if not config:
            raise ConfigurationError(f"Empty or invalid configuration in {config_file}")
            
        return config
    except FileNotFoundError:
        raise ConfigurationError(f"Configuration file not found: {config_file}")
    except yaml.YAMLError as e:
        raise ConfigurationError(f"Invalid YAML in configuration: {e}")
    except Exception as e:
        raise ConfigurationError(f"Error loading configuration: {e}")

def validate_network_config(config: Dict[str, Any]) -> None:
    """
    Validate network configuration section.
    
    Args:
        config: Configuration dictionary
        
    Raises:
        ConfigurationError: If configuration is invalid
    """
    # Check for required section
    if "network" not in config:
        raise ConfigurationError("Missing required 'network' section in configuration")
    
    network = config["network"]
    
    # Check for required keys
    required_keys = ["interface", "dhcp_range_start", "dhcp_range_end", 
                    "subnet_mask", "gateway"]
    
    missing_keys = [key for key in required_keys if key not in network]
    if missing_keys:
        raise ConfigurationError(f"Missing required network configuration: {', '.join(missing_keys)}")
    
    # Validate IP addresses
    for key in ["dhcp_range_start", "dhcp_range_end", "gateway"]:
        if not validate_ip_address(network[key]):
            raise ConfigurationError(f"Invalid IP address in {key}: {network[key]}")
    
    # Validate subnet mask
    if not validate_subnet_mask(network["subnet_mask"]):
        raise ConfigurationError(f"Invalid subnet mask: {network['subnet_mask']}")
    
    # Ensure DHCP range is valid
    try:
        start_ip = ipaddress.IPv4Address(network["dhcp_range_start"])
        end_ip = ipaddress.IPv4Address(network["dhcp_range_end"])
        
        if start_ip > end_ip:
            raise ConfigurationError("DHCP start IP must be less than end IP")
        
        # Check if they're in the same subnet
        gateway = network["gateway"]
        subnet_mask = network["subnet_mask"]
        
        if not is_ip_in_subnet(str(start_ip), gateway, subnet_mask):
            raise ConfigurationError(f"DHCP start IP {start_ip} is not in the same subnet as gateway {gateway}")
        
        if not is_ip_in_subnet(str(end_ip), gateway, subnet_mask):
            raise ConfigurationError(f"DHCP end IP {end_ip} is not in the same subnet as gateway {gateway}")
            
    except (ValueError, TypeError) as e:
        raise ConfigurationError(f"Invalid IP range configuration: {e}")

def validate_dhcp_config(config: Dict[str, Any]) -> None:
    """
    Validate DHCP configuration section.
    
    Args:
        config: Configuration dictionary
        
    Raises:
        ConfigurationError: If configuration is invalid
    """
    # Check for required section
    if "dhcp" not in config:
        raise ConfigurationError("Missing required 'dhcp' section in configuration")
    
    dhcp = config["dhcp"]
    
    # Check for required keys
    required_keys = ["config_file", "leases_file"]
    
    missing_keys = [key for key in required_keys if key not in dhcp]
    if missing_keys:
        raise ConfigurationError(f"Missing required DHCP configuration: {', '.join(missing_keys)}")
    
    # Check if paths are writable (if they exist)
    for key in ["config_file", "leases_file"]:
        path = dhcp[key]
        dir_path = os.path.dirname(path)
        
        # Check if the directory exists and is writable
        if os.path.exists(dir_path) and not os.access(dir_path, os.W_OK):
            raise ConfigurationError(f"Directory for {key} ({dir_path}) is not writable")

def validate_ipmi_config(config: Dict[str, Any]) -> None:
    """
    Validate IPMI configuration section.
    
    Args:
        config: Configuration dictionary
        
    Raises:
        ConfigurationError: If configuration is invalid
    """
    # Check for required section
    if "ipmi" not in config:
        raise ConfigurationError("Missing required 'ipmi' section in configuration")
    
    ipmi = config["ipmi"]
    
    # Check for required keys
    required_keys = ["username", "password"]
    
    missing_keys = [key for key in required_keys if key not in ipmi]
    if missing_keys:
        raise ConfigurationError(f"Missing required IPMI configuration: {', '.join(missing_keys)}")
    
    # Check for empty credentials
    for key in required_keys:
        if not ipmi[key]:
            logger.warning(f"IPMI {key} is empty. This may be insecure.")

def load_and_validate_config(config_file: str) -> Dict[str, Any]:
    """
    Load and validate the full configuration.
    
    Args:
        config_file: Path to YAML configuration file
        
    Returns:
        Validated configuration dictionary
        
    Raises:
        ConfigurationError: If configuration is invalid
    """
    # Load config
    config = load_yaml_config(config_file)
    
    # Validate each section
    validate_network_config(config)
    validate_dhcp_config(config)
    validate_ipmi_config(config)
    
    logger.info(f"Configuration loaded and validated from {config_file}")
    
    return config

def load_mac_ip_mappings(csv_file: str) -> List[Dict[str, str]]:
    """
    Load MAC-to-IP mappings from CSV file.
    
    Args:
        csv_file: Path to CSV file with mappings
        
    Returns:
        List of dictionaries containing MAC, static_ip, netmask, gateway, and optional password
        
    Raises:
        CSVFormatError: If CSV format is invalid
        ConfigurationError: If file not found
    """
    if not os.path.exists(csv_file):
        raise ConfigurationError(f"MAC-to-IP mapping file not found: {csv_file}")
    
    try:
        mappings = []
        with open(csv_file, "r") as file:
            reader = csv.reader(file)
            
            # Get headers
            try:
                headers = next(reader)
            except StopIteration:
                raise CSVFormatError(f"CSV file {csv_file} is empty")
            
            # Convert headers to uppercase and strip whitespace
            headers = [h.strip().upper() for h in headers]
            
            # Validate headers
            required_headers = ["MAC", "STATIC", "NETMASK", "GATEWAY"] 
            optional_headers = ["PASSWORD"]
            
            missing_headers = [h for h in required_headers if h not in headers]
            
            if missing_headers:
                raise CSVFormatError(
                    f"Missing required columns in CSV: {', '.join(missing_headers)}\n" 
                    f"Optional columns: {', '.join(optional_headers)}\n"
                    f"Note: If PASSWORD column is missing, default IPMI credentials from config will be used.\n"
                    f"Add PASSWORD column to specify custom passwords per device.\n"
                    f"Found columns: {', '.join(headers)}"
                )
            
            # Get column indices
            mac_idx = headers.index("MAC")
            static_idx = headers.index("STATIC")
            netmask_idx = headers.index("NETMASK")
            gateway_idx = headers.index("GATEWAY")
            password_idx = headers.index("PASSWORD") if "PASSWORD" in headers else -1
            
            # Process rows
            line_num = 1  # Start at 1 for header
            for row in reader:
                line_num += 1
                
                # Skip empty rows
                if not row or all(not cell.strip() for cell in row):
                    continue
                
                # Check row length
                if len(row) < len(required_headers):
                    logger.warning(f"Row {line_num} has insufficient columns: {row}")
                    continue
                
                # Clean up values
                row = [cell.strip() for cell in row]
                
                # Create mapping dictionary
                mapping = {
                    "mac": row[mac_idx],
                    "static_ip": row[static_idx],
                    "netmask": row[netmask_idx],
                    "gateway": row[gateway_idx]
                }
                
                # Add password if available
                if password_idx >= 0 and password_idx < len(row) and row[password_idx]:
                    logger.debug(f"Custom password found for MAC {row[mac_idx]}")
                    mapping["password"] = row[password_idx]
                else:
                    logger.debug(f"No custom password for MAC {row[mac_idx]}, will use default")
                
                # Validate values
                if not mapping["mac"]:
                    logger.warning(f"Row {line_num}: MAC address is empty, skipping")
                    continue
                
                if not validate_ip_address(mapping["static_ip"]):
                    logger.warning(f"Row {line_num}: Invalid static IP: {mapping['static_ip']}, skipping")
                    continue
                
                if not validate_subnet_mask(mapping["netmask"]):
                    logger.warning(f"Row {line_num}: Invalid netmask: {mapping['netmask']}, skipping")
                    continue
                
                if not validate_ip_address(mapping["gateway"]):
                    logger.warning(f"Row {line_num}: Invalid gateway: {mapping['gateway']}, skipping")
                    continue
                
                mappings.append(mapping)
        
        if not mappings:
            raise CSVFormatError("No valid MAC-to-IP mappings found in CSV")
        
        logger.info(f"Loaded {len(mappings)} MAC-to-IP mappings from {csv_file}")
        return mappings
    
    except csv.Error as e:
        raise CSVFormatError(f"CSV parsing error: {e}")
    except Exception as e:
        if isinstance(e, (ConfigurationError, CSVFormatError)):
            raise
        raise ConfigurationError(f"Error loading MAC-to-IP mappings: {e}")


def validate_mappings_with_config(mappings: List[Dict[str, str]], 
                                 config: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Validate that MAC-to-IP mappings are compatible with network configuration.
    
    Args:
        mappings: List of MAC-to-IP mappings
        config: Configuration dictionary
        
    Returns:
        List of validated mappings (invalid ones are filtered out)
        
    Raises:
        ConfigurationError: If all mappings are invalid
    """
    validated_mappings = []
    
    for mapping in mappings:
        try:
            # Check if the static IP is in the DHCP range
            dhcp_start = config["network"]["dhcp_range_start"]
            dhcp_end = config["network"]["dhcp_range_end"]
            static_ip = mapping["static_ip"]
            
            ip_int = int(ipaddress.IPv4Address(static_ip))
            start_int = int(ipaddress.IPv4Address(dhcp_start))
            end_int = int(ipaddress.IPv4Address(dhcp_end))
            
            if start_int <= ip_int <= end_int:
                logger.warning(
                    f"Static IP {static_ip} for MAC {mapping['mac']} is within the DHCP range. "
                    f"This may cause conflicts."
                )
            
            # Check for password presence and log appropriately 
            if "password" in mapping:
                logger.debug(f"Using custom password for MAC {mapping['mac']}")
            else:
                logger.debug(f"Using default password for MAC {mapping['mac']} from configuration")
            
            # Add to validated mappings
            validated_mappings.append(mapping)
            
        except Exception as e:
            logger.warning(f"Invalid mapping for MAC {mapping.get('mac', 'unknown')}: {e}")
    
    if not validated_mappings:
        raise ConfigurationError("All MAC-to-IP mappings are invalid")
    
    return validated_mappings

def print_mac_ip_mappings_template():
    """
    Print a template for the MAC-to-IP mappings CSV file.
    This is useful for users to understand the expected format.
    """
    template = """
# MAC-to-IP Mappings CSV Template for IPMIrage
# 
# Required columns:
# - MAC: MAC address of the IPMI interface
# - STATIC: Static IP address to assign
# - NETMASK: Subnet mask
# - GATEWAY: Gateway IP address
#
# Optional columns:
# - PASSWORD: Custom password for IPMI authentication (if omitted, uses default from config.yaml)
#
# Example:
MAC,STATIC,NETMASK,GATEWAY,PASSWORD
00:11:22:33:44:55,192.168.1.100,255.255.255.0,192.168.1.1,MyCustomPass1
aa:bb:cc:dd:ee:ff,192.168.1.101,255.255.255.0,192.168.1.1,MyCustomPass2
"""
    print(template)
    return template
