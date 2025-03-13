#!/usr/bin/env python3
"""
IPMIrage - Standalone Runner

This script allows running IPMIrage directly without installing it as a package.
"""

import os
import sys
import logging
import argparse

# Add the parent directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Now we can import from the package
from ipmirage import logger, display_banner, __version__
from ipmirage.IPMIrage import run_ipmirage

# ASCII Banner
BANNER = r"""



░▒▓█▓▒░▒▓███████▓▒░░▒▓██████████████▓▒░░▒▓█▓▒░▒▓███████▓▒░ ░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓████████▓▒░ 
░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░        
░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓███████▓▒░░▒▓████████▓▒░▒▓█▓▒▒▓███▓▒░▒▓██████▓▒░   
░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓████████▓▒░ 
                                                                                                   
                                                                                                   

"""

def display_banner_local():
    """Display the IPMIrage ASCII banner."""
    print(BANNER)
    print(f"IPMIrage v{__version__} - IPMI Configuration Tool")
    print(f"{'='*50}\n")

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
        "--script",
        default="./ipmi_set_ip.sh",
        help="Path to IPMI configuration script (default: ./ipmi_set_ip.sh)"
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

def main():
    """Main entry point for standalone IPMIrage."""
    # Display the ASCII banner
    display_banner_local()
    
    # Parse command line arguments
    args = parse_arguments()
    
    # Set debug logging if requested
    if args.debug:
        logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
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
