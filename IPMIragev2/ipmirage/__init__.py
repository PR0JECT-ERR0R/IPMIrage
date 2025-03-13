"""
IPMIrage

Automate IPMI network provisioning using DHCP discovery and static IP assignment.
"""

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

import logging
import os
import sys



# Package metadata
__version__ = "0.1.0"


# Create logging for packages
logger = logging.getLogger("ipmirage")


# Package initialization
def initialize():
    """Initialize the IPMIrage package."""

    # Check for virtual env
    if not (hasattr(sys, 'real_prefix') or
            (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix) or
            os.environ.get('VIRTUAL_ENV') is not None):
        logger.warning("Not running in virtual environment.")

    # Additional initialization
    logger.debug("IPMIrage initialized")

# Import components
try:
    from .network import setup_eth0_for_dhcp, create_dhcp_pool
    from .ipmi import configure_ipmi_device
    from .utils import normalize_mac, validate_ip_address
    from .config import load_and_validate_config
    
    __all__ = [
        "setup_eth0_for_dhcp",
        "create_dhcp_pool",
        "configure_ipmi_device",
        "normalize_mac",
        "validate_ip_address",
        "load_and_validate_config",
    ]

    pass
except ImportError as e:
    logger.warning(f"Some components failed to import: {e}")

# Display banner
def display_banner():
    """Display ASCI Banner"""
    print(BANNER)
    print(f"IPMIrage v{__version__}")
    print(f"{'='*50}\n")

# Initialize packages when imported
initialize()
