"""
JSON Handler Module

This module handles loading and validating JSON target files.

Functions:
    load_json_targets: Load targets from a JSON file
    validate_json_format: Validate the format of the JSON targets
    export_json_targets: Export targets to a JSON file
"""

import json
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

from ..utils import is_valid_ip, is_valid_port

logger = logging.getLogger(__name__)


def load_json_targets(file_path: str) -> Dict[str, Any]:
    """
    Load targets from a JSON file.
    
    Args:
        file_path (str): Path to the JSON file
        
    Returns:
        Dict[str, Any]: Dictionary containing targets
        
    Raises:
        FileNotFoundError: If the file does not exist
        json.JSONDecodeError: If the file is not valid JSON
    """
    logger.debug(f"Loading JSON targets from {file_path}")
    
    # Check if file exists
    path = Path(file_path)
    if not path.exists():
        logger.error(f"File not found: {file_path}")
        raise FileNotFoundError(f"File not found: {file_path}")
    
    # Load JSON file
    try:
        with open(path, "r") as f:
            data = json.load(f)
        
        logger.debug(f"Successfully loaded JSON targets from {file_path}")
        return data
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON file: {e}")
        raise


def validate_json_format(data: Dict[str, Any]) -> bool:
    """
    Validate the format of the JSON targets.
    
    Expected format:
    {
      "ip_addresses": {
        "192.168.1.1": {
          "hostnames": ["router.local", "gateway.example.com"],
          "tcp_ports": [80, 443]
        },
        "10.0.0.1": {
          "hostnames": ["firewall.example.com"],
          "tcp_ports": [22, 8080, 8443]
        }
      }
    }
    
    Args:
        data (Dict[str, Any]): Dictionary containing targets
        
    Returns:
        bool: True if the format is valid, False otherwise
    """
    logger.debug("Validating JSON format")
    
    # Check if the data has the required structure
    if not isinstance(data, dict):
        logger.error("JSON data is not a dictionary")
        return False
    
    # Check if the data has the required keys
    if "ip_addresses" not in data:
        logger.error("JSON data does not have 'ip_addresses' key")
        return False
    
    # Check if ip_addresses is a dictionary
    if not isinstance(data["ip_addresses"], dict):
        logger.error("'ip_addresses' is not a dictionary")
        return False
    
    # Check each IP address entry
    for ip, ip_data in data["ip_addresses"].items():
        # Check if IP address is valid
        if not is_valid_ip(ip):
            logger.error(f"Invalid IP address: {ip}")
            return False
        
        # Check if IP data is a dictionary
        if not isinstance(ip_data, dict):
            logger.error(f"Data for IP {ip} is not a dictionary")
            return False
        
        # Check if IP data has the required keys
        if "hostnames" not in ip_data:
            logger.error(f"Data for IP {ip} does not have 'hostnames' key")
            return False
        
        if "tcp_ports" not in ip_data:
            logger.error(f"Data for IP {ip} does not have 'tcp_ports' key")
            return False
        
        # Check if hostnames is a list
        if not isinstance(ip_data["hostnames"], list):
            logger.error(f"'hostnames' for IP {ip} is not a list")
            return False
        
        # Check if tcp_ports is a list
        if not isinstance(ip_data["tcp_ports"], list):
            logger.error(f"'tcp_ports' for IP {ip} is not a list")
            return False
        
        # Check if all ports are valid
        for port in ip_data["tcp_ports"]:
            if not isinstance(port, int) or not is_valid_port(port):
                logger.error(f"Invalid port for IP {ip}: {port}")
                return False
    
    logger.debug("JSON format is valid")
    return True


def export_json_targets(data: Dict[str, Any], file_path: str) -> None:
    """
    Export targets to a JSON file.
    
    Args:
        data (Dict[str, Any]): Dictionary containing targets
        file_path (str): Path to the output JSON file
    """
    logger.debug(f"Exporting JSON targets to {file_path}")
    
    # Create directory if it doesn't exist
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    # Write JSON file
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    
    logger.debug(f"Successfully exported JSON targets to {file_path}")
