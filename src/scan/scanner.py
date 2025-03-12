"""
Scanner Module

This module handles TCP port scanning functionality.

Functions:
    check_tcp_port: Check if a TCP port is open
    prepare_scan_jobs: Prepare scan jobs for distributed execution
    execute_scan: Execute a scan job
"""

import logging
import socket
import time
from typing import Dict, List, Any, Optional, Tuple

from ..utils import shuffle_targets, generate_random_delay, is_valid_ip, is_valid_port

logger = logging.getLogger(__name__)


def check_tcp_port(host: str, port: int, timeout: int = 1) -> bool:
    """
    Check if a TCP port is open.
    
    Args:
        host (str): Hostname or IP address
        port (int): TCP port number
        timeout (int): Connection timeout in seconds
        
    Returns:
        bool: True if the port is open, False otherwise
    """
    # Validate input
    if not is_valid_ip(host) and not host:
        logger.error(f"Invalid host: {host}")
        return False
    
    if not is_valid_port(port):
        logger.error(f"Invalid port: {port}")
        return False
    
    # Attempt to connect to the port
    try:
        with socket.create_connection((host, port), timeout=timeout):
            logger.debug(f"Port {port} is open on {host}")
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        logger.debug(f"Port {port} is closed on {host}")
        return False


def prepare_scan_jobs(targets: Dict[str, Any], concurrency_limit: int) -> List[Dict[str, Any]]:
    """
    Prepare scan jobs for distributed execution.
    
    Args:
        targets (Dict[str, Any]): Dictionary containing targets
        concurrency_limit (int): Maximum number of concurrent scans
        
    Returns:
        List[Dict[str, Any]]: List of scan jobs
    """
    logger.debug("Preparing scan jobs")
    
    # Shuffle targets to avoid sequential scanning
    shuffled_targets = shuffle_targets(targets)
    
    # Prepare scan jobs
    scan_jobs = []
    
    for ip, ip_data in shuffled_targets.get("ip_addresses", {}).items():
        for port in ip_data.get("tcp_ports", []):
            scan_jobs.append({
                "ip": ip,
                "port": port,
                "hostnames": ip_data.get("hostnames", [])
            })
    
    # Shuffle scan jobs
    import random
    random.shuffle(scan_jobs)
    
    # Split scan jobs into batches based on concurrency limit
    batches = []
    for i in range(0, len(scan_jobs), concurrency_limit):
        batches.append(scan_jobs[i:i + concurrency_limit])
    
    logger.debug(f"Prepared {len(scan_jobs)} scan jobs in {len(batches)} batches")
    return scan_jobs


def execute_scan(scan_job: Dict[str, Any], timeout: int = 1) -> Dict[str, Any]:
    """
    Execute a scan job.
    
    Args:
        scan_job (Dict[str, Any]): Scan job dictionary
        timeout (int): Connection timeout in seconds
        
    Returns:
        Dict[str, Any]: Scan result
    """
    ip = scan_job["ip"]
    port = scan_job["port"]
    hostnames = scan_job.get("hostnames", [])
    
    # Check if the port is open
    is_open = check_tcp_port(ip, port, timeout)
    
    # Return scan result
    return {
        "ip": ip,
        "port": port,
        "is_open": is_open,
        "hostnames": hostnames,
        "timestamp": time.time()
    }


def execute_batch(batch: List[Dict[str, Any]], timeout: int = 1, min_delay: int = 49, max_delay: int = 199) -> List[Dict[str, Any]]:
    """
    Execute a batch of scan jobs.
    
    Args:
        batch (List[Dict[str, Any]]): List of scan jobs
        timeout (int): Connection timeout in seconds
        min_delay (int): Minimum delay between scans in milliseconds
        max_delay (int): Maximum delay between scans in milliseconds
        
    Returns:
        List[Dict[str, Any]]: List of scan results
    """
    results = []
    
    for job in batch:
        # Execute scan
        result = execute_scan(job, timeout)
        results.append(result)
        
        # Generate random delay
        delay = generate_random_delay(min_delay, max_delay)
        time.sleep(delay)
    
    return results


def format_results_for_storage(results: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Format scan results for storage.
    
    Args:
        results (List[Dict[str, Any]]): List of scan results
        
    Returns:
        Dict[str, Dict[str, Any]]: Formatted results
    """
    formatted = {}
    
    for result in results:
        ip = result["ip"]
        port = result["port"]
        is_open = result["is_open"]
        timestamp = result["timestamp"]
        
        if ip not in formatted:
            formatted_ip = {
                "scan_time": timestamp,
                "ports": {}
            }
            
            # Add organization information if available
            if "organization" in result:
                formatted_ip["organization"] = result["organization"]
            
            formatted[ip] = formatted_ip
        
        formatted[ip]["ports"][str(port)] = is_open
    
    return formatted
