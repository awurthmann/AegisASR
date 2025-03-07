"""
Cloud Common Module

This module provides common functionality for cloud platforms.

Functions:
    select_cloud_platforms: Prompt user to select cloud platforms
    validate_cloud_credentials: Validate cloud platform credentials
    get_cloud_handler: Get the appropriate cloud handler for a platform
"""

import logging
import os
from typing import Dict, List, Any, Optional, Tuple

from ..config import get_aws_config, get_azure_config, get_gcp_config

logger = logging.getLogger(__name__)


def select_cloud_platforms(config: Dict[str, str], default_platform: str = "aws") -> List[str]:
    """
    Prompt user to select cloud platforms.
    
    Args:
        config (Dict[str, str]): Configuration dictionary
        default_platform (str): Default platform if none selected
        
    Returns:
        List[str]: List of selected cloud platforms
    """
    logger.debug("Prompting user to select cloud platforms")
    
    # Check which platforms have valid credentials
    available_platforms = []
    
    if get_aws_config(config):
        available_platforms.append("aws")
    
    if get_azure_config(config):
        available_platforms.append("azure")
    
    if get_gcp_config(config):
        available_platforms.append("gcp")
    
    if not available_platforms:
        logger.warning("No cloud platforms have valid credentials")
        print("No cloud platforms have valid credentials. Please check your .env file.")
        return []
    
    # Print available platforms
    print("Available cloud platforms:")
    for i, platform in enumerate(available_platforms, 1):
        print(f"{i}. {platform.upper()}")
    
    # Prompt user to select platforms
    print("\nSelect cloud platforms (comma-separated numbers, or 'all'):")
    while True:
        selection = input("> ").strip().lower()
        
        if selection == "all":
            return available_platforms
        
        try:
            # Parse selection
            indices = [int(i.strip()) - 1 for i in selection.split(",")]
            
            # Validate indices
            if any(i < 0 or i >= len(available_platforms) for i in indices):
                print("Invalid selection. Please try again.")
                continue
            
            # Get selected platforms
            selected_platforms = [available_platforms[i] for i in indices]
            
            if not selected_platforms:
                print("No platforms selected. Please try again.")
                continue
            
            return selected_platforms
        
        except ValueError:
            print("Invalid selection. Please try again.")


def validate_cloud_credentials(config: Dict[str, str], platforms: List[str]) -> bool:
    """
    Validate cloud platform credentials.
    
    Args:
        config (Dict[str, str]): Configuration dictionary
        platforms (List[str]): List of cloud platforms
        
    Returns:
        bool: True if all platforms have valid credentials, False otherwise
    """
    logger.debug(f"Validating credentials for {', '.join(platforms)}")
    
    # Check each platform
    for platform in platforms:
        if platform == "aws":
            if not get_aws_config(config):
                logger.error("AWS credentials are missing or invalid")
                return False
        
        elif platform == "azure":
            if not get_azure_config(config):
                logger.error("Azure credentials are missing or invalid")
                return False
        
        elif platform == "gcp":
            if not get_gcp_config(config):
                logger.error("GCP credentials are missing or invalid")
                return False
        
        else:
            logger.error(f"Unknown platform: {platform}")
            return False
    
    logger.debug("All credentials are valid")
    return True


def get_cloud_handler(platform: str) -> Optional[Any]:
    """
    Get the appropriate cloud handler for a platform.
    
    Args:
        platform (str): Cloud platform
        
    Returns:
        Optional[Any]: Cloud handler or None if platform is unknown
    """
    logger.debug(f"Getting cloud handler for {platform}")
    
    if platform == "aws":
        from .aws.lambda_handler import AWSLambdaHandler
        return AWSLambdaHandler()
    
    elif platform == "azure":
        from .azure.function_handler import AzureFunctionHandler
        return AzureFunctionHandler()
    
    elif platform == "gcp":
        from .gcp.function_handler import GCPFunctionHandler
        return GCPFunctionHandler()
    
    else:
        logger.error(f"Unknown platform: {platform}")
        return None


def select_storage_platform(platforms: List[str]) -> Optional[str]:
    """
    Prompt user to select a storage platform.
    
    Args:
        platforms (List[str]): List of available platforms
        
    Returns:
        Optional[str]: Selected platform or None if cancelled
    """
    logger.debug("Prompting user to select a storage platform")
    
    if not platforms:
        logger.warning("No platforms available")
        return None
    
    if len(platforms) == 1:
        logger.debug(f"Only one platform available: {platforms[0]}")
        return platforms[0]
    
    # Print available platforms
    print("\nSelect a platform for storing results:")
    for i, platform in enumerate(platforms, 1):
        print(f"{i}. {platform.upper()}")
    
    # Prompt user to select a platform
    while True:
        selection = input("> ").strip()
        
        try:
            index = int(selection) - 1
            
            if index < 0 or index >= len(platforms):
                print("Invalid selection. Please try again.")
                continue
            
            return platforms[index]
        
        except ValueError:
            print("Invalid selection. Please try again.")
