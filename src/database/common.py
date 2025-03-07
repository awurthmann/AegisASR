"""
Database Common Module

This module provides common functionality for database storage.

Functions:
    select_storage_platform: Prompt user to select a storage platform
    get_storage_handler: Get the appropriate storage handler for a platform
"""

import logging
from typing import Dict, List, Any, Optional

from ..config import get_aws_config, get_azure_config, get_gcp_config

logger = logging.getLogger(__name__)


def select_storage_platform(config: Dict[str, str], platforms: List[str]) -> Optional[str]:
    """
    Prompt user to select a storage platform.
    
    Args:
        config (Dict[str, str]): Configuration dictionary
        platforms (List[str]): List of available platforms
        
    Returns:
        Optional[str]: Selected platform or None if cancelled
    """
    logger.debug("Selecting storage platform")
    
    # Check if only one platform is available
    if len(platforms) == 1:
        logger.debug(f"Only one platform available: {platforms[0]}")
        return platforms[0]
    
    # Check which platforms have valid credentials
    available_platforms = []
    
    for platform in platforms:
        if platform == "aws" and get_aws_config(config):
            available_platforms.append(platform)
        elif platform == "azure" and get_azure_config(config):
            available_platforms.append(platform)
        elif platform == "gcp" and get_gcp_config(config):
            available_platforms.append(platform)
    
    if not available_platforms:
        logger.warning("No platforms have valid credentials")
        return None
    
    # If only one platform has valid credentials, use it
    if len(available_platforms) == 1:
        logger.debug(f"Only one platform has valid credentials: {available_platforms[0]}")
        return available_platforms[0]
    
    # Prompt user to select a platform
    print("\nSelect a platform for storing results:")
    for i, platform in enumerate(available_platforms, 1):
        print(f"{i}. {platform.upper()}")
    
    while True:
        selection = input("> ").strip()
        
        try:
            index = int(selection) - 1
            
            if index < 0 or index >= len(available_platforms):
                print("Invalid selection. Please try again.")
                continue
            
            selected_platform = available_platforms[index]
            logger.debug(f"Selected storage platform: {selected_platform}")
            return selected_platform
        
        except ValueError:
            print("Invalid selection. Please try again.")


def get_storage_handler(platform: str) -> Optional[Any]:
    """
    Get the appropriate storage handler for a platform.
    
    Args:
        platform (str): Storage platform
        
    Returns:
        Optional[Any]: Storage handler or None if platform is unknown
    """
    logger.debug(f"Getting storage handler for {platform}")
    
    if platform == "aws":
        from .aws_storage import AWSStorageHandler
        return AWSStorageHandler()
    
    elif platform == "azure":
        from .azure_storage import AzureStorageHandler
        return AzureStorageHandler()
    
    elif platform == "gcp":
        from .gcp_storage import GCPStorageHandler
        return GCPStorageHandler()
    
    else:
        logger.error(f"Unknown platform: {platform}")
        return None


def format_results_for_storage(results: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Format scan results for storage.
    
    Args:
        results (List[Dict[str, Any]]): List of scan results
        
    Returns:
        Dict[str, Dict[str, Any]]: Formatted results
    """
    logger.debug(f"Formatting {len(results)} results for storage")
    
    formatted = {}
    
    for result in results:
        ip = result["ip"]
        port = result["port"]
        is_open = result["is_open"]
        timestamp = result["timestamp"]
        
        if ip not in formatted:
            formatted[ip] = {
                "scan_time": timestamp,
                "ports": {}
            }
        
        formatted[ip]["ports"][str(port)] = is_open
    
    logger.debug(f"Formatted {len(formatted)} results for storage")
    return formatted
