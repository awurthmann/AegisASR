"""
DNS Handler Module

This module handles loading and converting DNS zone files to the required JSON format.

Functions:
    load_dns_zone: Load DNS records from a zone file
    convert_dns_to_json: Convert DNS records to the required JSON format
    extract_hostnames: Extract hostnames from DNS records
"""

import logging
import re
import socket
from typing import Dict, List, Any, Optional, Set, Tuple
from pathlib import Path

from ..utils import is_valid_ip
from .json_handler import export_json_targets

logger = logging.getLogger(__name__)

# Regular expressions for parsing DNS zone file records
RE_RECORD = re.compile(r'^(\S+)\s+(?:\d+\s+)?(?:IN\s+)?(\S+)\s+(.+)$', re.IGNORECASE)
RE_COMMENT = re.compile(r'^\s*;.*$')
RE_BLANK = re.compile(r'^\s*$')


def load_dns_zone(file_path: str) -> List[Dict[str, str]]:
    """
    Load DNS records from a zone file.
    
    Args:
        file_path (str): Path to the DNS zone file
        
    Returns:
        List[Dict[str, str]]: List of DNS records
        
    Raises:
        FileNotFoundError: If the file does not exist
    """
    logger.debug(f"Loading DNS zone file from {file_path}")
    
    # Check if file exists
    path = Path(file_path)
    if not path.exists():
        logger.error(f"File not found: {file_path}")
        raise FileNotFoundError(f"File not found: {file_path}")
    
    # Load zone file
    records = []
    current_origin = ""
    
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            
            # Skip comments and blank lines
            if RE_COMMENT.match(line) or RE_BLANK.match(line):
                continue
            
            # Handle $ORIGIN directive
            if line.startswith("$ORIGIN"):
                current_origin = line.split()[1]
                if not current_origin.endswith("."):
                    current_origin += "."
                continue
            
            # Parse record
            match = RE_RECORD.match(line)
            if match:
                name, record_type, data = match.groups()
                
                # Handle relative names
                if name == "@":
                    name = current_origin
                elif not name.endswith(".") and current_origin:
                    name = f"{name}.{current_origin}"
                
                # Remove trailing dot
                name = name.rstrip(".")
                
                # Add record
                records.append({
                    "name": name,
                    "type": record_type.upper(),
                    "data": data.strip()
                })
    
    logger.debug(f"Successfully loaded {len(records)} DNS records from {file_path}")
    return records


def extract_hostnames(records: List[Dict[str, str]]) -> Set[str]:
    """
    Extract hostnames from DNS records.
    
    Args:
        records (List[Dict[str, str]]): List of DNS records
        
    Returns:
        Set[str]: Set of hostnames
    """
    logger.debug("Extracting hostnames from DNS records")
    
    hostnames = set()
    
    for record in records:
        record_type = record["type"]
        
        # Extract hostname from A, AAAA records
        if record_type in ["A", "AAAA"]:
            hostnames.add(record["name"])
        
        # Extract hostname from CNAME records
        elif record_type == "CNAME":
            hostnames.add(record["name"])
        
        # Extract hostname from PTR records
        elif record_type == "PTR":
            hostnames.add(record["data"].rstrip("."))
        
        # Extract hostname from MX records
        elif record_type == "MX":
            # MX records have priority and hostname
            parts = record["data"].split()
            if len(parts) >= 2:
                hostnames.add(parts[1].rstrip("."))
        
        # Extract hostname from SRV records
        elif record_type == "SRV":
            # SRV records have priority, weight, port, and hostname
            parts = record["data"].split()
            if len(parts) >= 4:
                hostnames.add(parts[3].rstrip("."))
    
    logger.debug(f"Extracted {len(hostnames)} hostnames from DNS records")
    return hostnames


def resolve_hostnames(hostnames: Set[str]) -> Dict[str, List[str]]:
    """
    Resolve hostnames to IP addresses.
    
    Args:
        hostnames (Set[str]): Set of hostnames
        
    Returns:
        Dict[str, List[str]]: Dictionary mapping IP addresses to hostnames
    """
    logger.debug(f"Resolving {len(hostnames)} hostnames to IP addresses")
    
    ip_to_hostnames = {}
    
    for hostname in hostnames:
        try:
            # Resolve hostname to IP address
            ip_addresses = socket.gethostbyname_ex(hostname)[2]
            
            # Add IP address to dictionary
            for ip in ip_addresses:
                if ip not in ip_to_hostnames:
                    ip_to_hostnames[ip] = []
                if hostname not in ip_to_hostnames[ip]:
                    ip_to_hostnames[ip].append(hostname)
        except socket.gaierror:
            logger.warning(f"Could not resolve hostname: {hostname}")
    
    logger.debug(f"Resolved hostnames to {len(ip_to_hostnames)} IP addresses")
    return ip_to_hostnames


def convert_dns_to_json(records: List[Dict[str, str]], tcp_ports: List[int]) -> Dict[str, Any]:
    """
    Convert DNS records to the required JSON format.
    
    Args:
        records (List[Dict[str, str]]): List of DNS records
        tcp_ports (List[int]): List of TCP ports to scan
        
    Returns:
        Dict[str, Any]: Dictionary in the required JSON format
    """
    logger.debug("Converting DNS records to JSON format")
    
    # Extract hostnames from DNS records
    hostnames = extract_hostnames(records)
    
    # Resolve hostnames to IP addresses
    ip_to_hostnames = resolve_hostnames(hostnames)
    
    # Create JSON structure
    json_data = {
        "ip_addresses": {}
    }
    
    # Add IP addresses and hostnames
    for ip, hosts in ip_to_hostnames.items():
        json_data["ip_addresses"][ip] = {
            "hostnames": hosts,
            "tcp_ports": tcp_ports
        }
    
    logger.debug(f"Successfully converted DNS records to JSON format with {len(json_data['ip_addresses'])} IP addresses")
    return json_data


def export_dns_to_json(dns_file_path: str, json_file_path: str, tcp_ports: List[int]) -> None:
    """
    Export DNS zone file to JSON format.
    
    Args:
        dns_file_path (str): Path to the DNS zone file
        json_file_path (str): Path to the output JSON file
        tcp_ports (List[int]): List of TCP ports to scan
    """
    logger.debug(f"Exporting DNS zone file {dns_file_path} to JSON format {json_file_path}")
    
    # Load DNS zone file
    records = load_dns_zone(dns_file_path)
    
    # Convert DNS records to JSON format
    json_data = convert_dns_to_json(records, tcp_ports)
    
    # Export JSON data
    export_json_targets(json_data, json_file_path)
    
    logger.debug(f"Successfully exported DNS zone file to JSON format")
