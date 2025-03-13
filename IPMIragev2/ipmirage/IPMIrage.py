#!/usr/bin/env python3
"""
IPMIrage - Main Module

This module contains the core orchestration logic for the IPMIrage application.
It handles the workflow of discovering and configuring IPMI devices.
"""

import os
import sys
import time
import argparse
import logging
from typing import Dict, List, Any, Optional, Tuple

# Import from the package
from . import logger, display_banner, __version__
from .config import (
    load_and_validate_config,
    load_mac_ip_mappings,
    validate_mappings_with_config,
    print_mac_ip_mappings_template,
    ConfigurationError,
    CSVFormatError
)
from .network import (
    NetworkError,
    DHCPError,
    verify_interface_exists,
    verify_dnsmasq_installed,
    setup_eth0_for_dhcp,
    create_dhcp_pool,
    wait_for_dhcp_assignments,
    network_configuration_context,
    stop_dhcp_server
)
from .ipmi import (
    IPMIError,
    verify_ipmitool_installed,
    configure_ipmi_devices_parallel,
    create_configuration_device_list
)
from .utils import run_command

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="IPMIrage - IPMI Configuration Tool")
    
    parser.add_argument(
        "--config", 
        default="config.yaml",
        help="Path to configuration file (default: config.yaml)"
    )
    
    parser.add_argument(
        "--csv", 
        default="mac_to_ip.csv",
        help="Path to MAC-to-IP mapping CSV (default: mac_to_ip.csv)"
    )
    
    parser.add_argument(
        "--dry-run", 
        action="store_true",
        help="Show what would be done without making changes"
    )
    
    parser.add_argument(
        "--debug", 
        action="store_true",
        help="Enable debug logging"
    )
    
    parser.add_argument(
        "--skip-dhcp",
        action="store_true",
        help="Skip DHCP server setup (use if you already have DHCP)"
    )
    
    parser.add_argument(
        "--show-template",
        action="store_true",
        help="Show a template for the MAC-to-IP CSV file and exit"
    )
    
    parser.add_argument(
        "--script",
        default="ipmirage/ipmi_set_ip.sh",
        help="Path to IPMI configuration script (default: ipmirage/ipmi_set_ip.sh)"
    )
    
    parser.add_argument(
        "--max-workers",
        type=int,
        default=5,
        help="Maximum number of parallel workers (default: 5)"
    )
    
    parser.add_argument(
        "--dhcp-timeout",
        type=int,
        default=60,
        help="Timeout for DHCP discovery in seconds (default: 60)"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version=f"IPMIrage v{__version__}",
        help="Show version information and exit"
    )
    
    return parser.parse_args()

def check_requirements() -> None:
    """
    Check for required tools and permissions.
    
    Raises:
        RuntimeError: If requirements are not met
    """
    # Check for root privileges
    if os.geteuid() != 0:
        # Special case for --show-template which doesn't require root
        if "--show-template" in sys.argv:
            # This is fine, we'll handle it in main()
            return
            
        # Otherwise, root is required
        raise RuntimeError("This script must be run as root to configure network and DHCP")
    
    # Check for required tools
    if not verify_ipmitool_installed():
        raise RuntimeError(
            "ipmitool is not installed. Please install it with: "
            "apt-get install ipmitool"
        )
    
    if not verify_dnsmasq_installed():
        raise RuntimeError(
            "dnsmasq is not installed. Please install it with: "
            "apt-get install dnsmasq"
        )

def run_ipmirage(args: Any) -> int:
    """
    Run the IPMIrage workflow.
    
    Args:
        args: Command-line arguments
        
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    # Set debug logging if requested
    if args.debug:
        logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.debug("Debug logging enabled")
    
    try:
        # Check requirements
        check_requirements()
        
        # Load configuration
        logger.info(f"Loading configuration from {args.config}")
        config = load_and_validate_config(args.config)
        
        # Load MAC-to-IP mappings
        logger.info(f"Loading MAC-to-IP mappings from {args.csv}")
        mappings = load_mac_ip_mappings(args.csv)
        
        # Log how many mappings have custom passwords
        custom_pass_count = sum(1 for m in mappings if "password" in m)
        logger.info(f"Found {custom_pass_count}/{len(mappings)} devices with custom passwords")
        
        validated_mappings = validate_mappings_with_config(mappings, config)
        logger.info(f"Loaded {len(validated_mappings)} valid MAC-to-IP mappings")
        
        # Extract MAC addresses
        mac_addresses = [mapping["mac"] for mapping in validated_mappings]
        
        # Check if dry run
        if args.dry_run:
            logger.info("DRY RUN MODE: No changes will be made")
            for mapping in validated_mappings:
                logger.info(f"Would configure: {mapping['mac']} -> {mapping['static_ip']}")
            return 0
        
        # Check script exists
        if not os.path.exists(args.script):
            raise ConfigurationError(f"IPMI configuration script not found: {args.script}")
        
        if not os.access(args.script, os.X_OK):
            raise ConfigurationError(f"IPMI configuration script is not executable: {args.script}")
        
        # Get DHCP IPs
        dhcp_ips = {}
        
        if not args.skip_dhcp:
            # Verify interface exists
            interface = config["network"]["interface"]
            if not verify_interface_exists(interface):
                raise NetworkError(f"Network interface {interface} does not exist")
            
            # Setup network with network configuration context for safety
            with network_configuration_context(interface):
                try:
                    # Setup interface for DHCP
                    gateway = config["network"]["gateway"]
                    setup_eth0_for_dhcp(interface, gateway)
                    
                    # Create DHCP pool
                    create_dhcp_pool(config)
                    
                    # Wait for DHCP assignments
                    dhcp_ips = wait_for_dhcp_assignments(
                        config, 
                        mac_addresses,
                        timeout=args.dhcp_timeout
                    )
                    
                    if not dhcp_ips:
                        logger.error("No DHCP assignments found, cannot proceed")
                        return 1
                
                finally:
                    # Always try to stop DHCP server
                    try:
                        stop_dhcp_server()
                    except DHCPError as e:
                        logger.warning(f"Error stopping DHCP server: {e}")
        else:
            logger.info("Skipping DHCP setup as requested")
            # In this case, use static_ip as dhcp_ip for testing/debugging
            dhcp_ips = {mapping["mac"]: mapping["static_ip"] for mapping in validated_mappings}
        
        # Create device list for configuration
        devices = create_configuration_device_list(dhcp_ips, validated_mappings, config)
        
        if not devices:
            logger.error("No devices to configure")
            return 1
        
        logger.info(f"Configuring {len(devices)} IPMI devices")
        
        # Log password usage summary without exposing actual passwords
        default_username = config["ipmi"]["username"]
        default_password = config["ipmi"]["password"]
        custom_pass_count = sum(1 for d in devices if d.get("password") != default_password)
        
        logger.info(f"Using default IPMI username '{default_username}' for all devices")
        logger.info(f"Using custom passwords for {custom_pass_count}/{len(devices)} devices")
        if custom_pass_count < len(devices):
            logger.info(f"Using default password for {len(devices) - custom_pass_count} devices")
        
        # Configure IPMI devices
        results = configure_ipmi_devices_parallel(
            devices,
            use_script=True,
            # Ensure script path is absolute
            script_path=os.path.abspath(args.script) if not os.path.isabs(args.script) else args.script,
            max_workers=args.max_workers
        )
        
        # Report results
        success_count = sum(1 for success in results.values() if success)
        if success_count == len(devices):
            logger.info("All devices successfully configured")
            return 0
        else:
            logger.warning(f"Only {success_count}/{len(devices)} devices were successfully configured")
            
            # List failed devices
            for mac, success in results.items():
                if not success:
                    # Find the corresponding device
                    device = next((d for d in devices if d["mac"] == mac), None)
                    if device:
                        logger.warning(f"Failed to configure: {mac} -> {device['static_ip']}")
            
            return 1
            
    except ConfigurationError as e:
        logger.error(f"Configuration error: {e}")
        return 1
    except NetworkError as e:
        logger.error(f"Network error: {e}")
        return 1
    except IPMIError as e:
        logger.error(f"IPMI error: {e}")
        return 1
    except RuntimeError as e:
        logger.error(f"Runtime error: {e}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.debug:
            import traceback
            logger.debug(traceback.format_exc())
        return 1

def main():
    """Main entry point for IPMIrage."""
    # Display the ASCII banner
    display_banner()
    
    # Parse command line arguments
    args = parse_arguments()
    
    # Show template if requested
    if args.show_template:
        print_mac_ip_mappings_template()
        sys.exit(0)
    
    # Run the IPMIrage workflow
    try:
        exit_code = run_ipmirage(args)
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.info("Operation interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Error during execution: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
