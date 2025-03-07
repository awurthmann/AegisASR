"""
Configuration Module

This module handles loading and validating configuration from environment variables.
It uses python-dotenv to load variables from .env files.

Functions:
    load_config: Load configuration from .env files
    validate_config: Validate the loaded configuration
    get_aws_config: Get AWS-specific configuration
    get_azure_config: Get Azure-specific configuration
    get_gcp_config: Get GCP-specific configuration
"""

import os
import logging
from typing import Dict, Any, Optional
from pathlib import Path
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Required configuration keys for each cloud platform
AWS_REQUIRED_KEYS = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"]
AZURE_REQUIRED_KEYS = ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"]
GCP_REQUIRED_KEYS = ["GCP_PROJECT_ID", "GCP_CREDENTIALS_FILE"]

# Default configuration values
DEFAULT_CONFIG = {
    "SCAN_TIMEOUT": "1",  # Default timeout in seconds
    "MAX_CONCURRENCY": "1000",  # Default maximum concurrency
    "RANDOM_DELAY_MIN": "49",  # Minimum delay in milliseconds
    "RANDOM_DELAY_MAX": "199",  # Maximum delay in milliseconds
}


def load_config() -> Dict[str, str]:
    """
    Load configuration from .env files.
    
    Looks for .env files in the following locations:
    1. ./config/.env
    2. ./.env
    
    Returns:
        Dict[str, str]: Dictionary containing configuration values
    """
    # Get the project root directory
    project_root = Path(__file__).parent.parent
    
    # Try to load from config/.env first
    config_env_path = project_root / "config" / ".env"
    root_env_path = project_root / ".env"
    
    # Load environment variables from .env files
    if config_env_path.exists():
        logger.debug(f"Loading configuration from {config_env_path}")
        load_dotenv(dotenv_path=config_env_path)
    elif root_env_path.exists():
        logger.debug(f"Loading configuration from {root_env_path}")
        load_dotenv(dotenv_path=root_env_path)
    else:
        logger.warning("No .env file found. Using environment variables only.")
    
    # Create configuration dictionary with default values
    config = DEFAULT_CONFIG.copy()
    
    # Update with environment variables
    for key in list(DEFAULT_CONFIG.keys()) + AWS_REQUIRED_KEYS + AZURE_REQUIRED_KEYS + GCP_REQUIRED_KEYS:
        if key in os.environ:
            config[key] = os.environ[key]
    
    return config


def validate_config(config: Dict[str, str]) -> bool:
    """
    Validate the loaded configuration.
    
    Args:
        config (Dict[str, str]): Configuration dictionary
        
    Returns:
        bool: True if configuration is valid, False otherwise
    """
    # Validate common configuration
    try:
        int(config.get("SCAN_TIMEOUT", "1"))
        int(config.get("MAX_CONCURRENCY", "1000"))
        int(config.get("RANDOM_DELAY_MIN", "49"))
        int(config.get("RANDOM_DELAY_MAX", "199"))
    except ValueError:
        logger.error("Invalid numeric configuration values")
        return False
    
    # Validate that random delay min is less than max
    if int(config.get("RANDOM_DELAY_MIN", "49")) >= int(config.get("RANDOM_DELAY_MAX", "199")):
        logger.error("RANDOM_DELAY_MIN must be less than RANDOM_DELAY_MAX")
        return False
    
    return True


def get_aws_config(config: Dict[str, str]) -> Optional[Dict[str, str]]:
    """
    Get AWS-specific configuration.
    
    Args:
        config (Dict[str, str]): Configuration dictionary
        
    Returns:
        Optional[Dict[str, str]]: AWS configuration or None if incomplete
    """
    # Check if all required AWS keys are present
    if all(key in config for key in AWS_REQUIRED_KEYS):
        return {key: config[key] for key in AWS_REQUIRED_KEYS}
    return None


def get_azure_config(config: Dict[str, str]) -> Optional[Dict[str, str]]:
    """
    Get Azure-specific configuration.
    
    Args:
        config (Dict[str, str]): Configuration dictionary
        
    Returns:
        Optional[Dict[str, str]]: Azure configuration or None if incomplete
    """
    # Check if all required Azure keys are present
    if all(key in config for key in AZURE_REQUIRED_KEYS):
        return {key: config[key] for key in AZURE_REQUIRED_KEYS}
    return None


def get_gcp_config(config: Dict[str, str]) -> Optional[Dict[str, str]]:
    """
    Get GCP-specific configuration.
    
    Args:
        config (Dict[str, str]): Configuration dictionary
        
    Returns:
        Optional[Dict[str, str]]: GCP configuration or None if incomplete
    """
    # Check if all required GCP keys are present
    if all(key in config for key in GCP_REQUIRED_KEYS):
        return {key: config[key] for key in GCP_REQUIRED_KEYS}
    return None
