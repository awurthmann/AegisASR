"""
Utility Module

This module provides common utility functions for the application.

Functions:
    setup_logging: Configure logging for the application
    display_progress: Display a progress indicator
    display_warning: Display a warning message and get user confirmation
    shuffle_targets: Shuffle targets to avoid sequential scanning
    generate_random_delay: Generate a random delay between requests
"""

import logging
import random
import sys
import time
from typing import Dict, List, Any, Optional


def setup_logging(level: int = logging.INFO) -> None:
    """
    Configure logging for the application.
    
    Args:
        level (int): Logging level (default: logging.INFO)
    """
    # Configure root logger
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Set third-party loggers to WARNING to reduce noise
    for logger_name in ["boto3", "botocore", "urllib3", "azure", "google"]:
        logging.getLogger(logger_name).setLevel(logging.WARNING)


def display_progress(current: int, total: int, width: int = 50) -> None:
    """
    Display a progress indicator.
    
    Args:
        current (int): Current progress value
        total (int): Total progress value
        width (int): Width of the progress bar (default: 50)
    """
    # Calculate progress percentage
    progress = min(1.0, current / total if total > 0 else 1.0)
    filled_width = int(width * progress)
    
    # Create progress bar
    bar = "█" * filled_width + "░" * (width - filled_width)
    percentage = int(progress * 100)
    
    # Print progress bar
    sys.stdout.write(f"\r[{bar}] {percentage}% ({current}/{total})")
    sys.stdout.flush()
    
    # Print newline when complete
    if current >= total:
        sys.stdout.write("\n")


def display_warning() -> bool:
    """
    Display a warning message and get user confirmation.
    
    Returns:
        bool: True if user confirms, False otherwise
    """
    warning_message = """
⚠️ WARNING: USE RESPONSIBLY! ⚠️
- Only scan systems you own or have permission to test.
- Unauthorized scanning may be illegal and trigger security alerts.
- Excessive scanning can overload networks or get your cloud account flagged.
- Respect rate limits to avoid disruptions.

Proceeding means you accept all risks and responsibilities.
"""
    
    print(warning_message)
    
    # Get user confirmation
    while True:
        response = input("Are you sure you want to continue? (y/n): ").strip().lower()
        if response in ["y", "yes"]:
            return True
        elif response in ["n", "no"]:
            return False
        else:
            print("Please enter 'y' or 'n'.")


def shuffle_targets(targets: Dict[str, Any]) -> Dict[str, Any]:
    """
    Shuffle targets to avoid sequential scanning.
    
    Args:
        targets (Dict[str, Any]): Target dictionary
        
    Returns:
        Dict[str, Any]: Shuffled target dictionary
    """
    # Create a new dictionary with the same structure
    shuffled = {"ip_addresses": {}}
    
    # Get list of IP addresses and shuffle them
    ip_addresses = list(targets.get("ip_addresses", {}).keys())
    random.shuffle(ip_addresses)
    
    # Rebuild the dictionary with shuffled IP addresses
    for ip in ip_addresses:
        shuffled["ip_addresses"][ip] = targets["ip_addresses"][ip]
    
    return shuffled


def generate_random_delay(min_ms: int = 49, max_ms: int = 199) -> float:
    """
    Generate a random delay between requests.
    
    Args:
        min_ms (int): Minimum delay in milliseconds (default: 49)
        max_ms (int): Maximum delay in milliseconds (default: 199)
        
    Returns:
        float: Random delay in seconds
    """
    # Generate random delay in milliseconds
    delay_ms = random.randint(min_ms, max_ms)
    
    # Convert to seconds
    return delay_ms / 1000.0


def is_valid_ip(ip: str) -> bool:
    """
    Check if a string is a valid IP address.
    
    Args:
        ip (str): IP address to check
        
    Returns:
        bool: True if valid, False otherwise
    """
    # Split by dots
    parts = ip.split(".")
    
    # Check if we have 4 parts
    if len(parts) != 4:
        return False
    
    # Check if each part is a number between 0 and 255
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def is_valid_port(port: int) -> bool:
    """
    Check if a port number is valid.
    
    Args:
        port (int): Port number to check
        
    Returns:
        bool: True if valid, False otherwise
    """
    return 1 <= port <= 65535
