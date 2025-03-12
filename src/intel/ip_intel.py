"""
IP Intelligence Module

This module provides IP intelligence functionality, including organization lookup.

Functions:
    get_ip_organization: Get organization information for an IP address
    enrich_targets_with_organization: Enrich targets with organization information
"""

import os
import logging
import time
from typing import Dict, List, Any, Optional, Set, Tuple
import ipaddress

# Setup logging
logger = logging.getLogger(__name__)

# Try to import MaxMind GeoIP2 library
try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True
except ImportError:
    logger.warning("geoip2 library not installed. MaxMind GeoLite2 functionality will not be available.")
    GEOIP2_AVAILABLE = False

# Try to import ipwhois library
try:
    from ipwhois import IPWhois
    IPWHOIS_AVAILABLE = True
except ImportError:
    logger.warning("ipwhois library not installed. WHOIS lookup functionality will not be available.")
    IPWHOIS_AVAILABLE = False

# Try to import requests library for API calls
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    logger.warning("requests library not installed. IP API functionality will not be available.")
    REQUESTS_AVAILABLE = False


def get_ip_organization(ip: str, 
                        maxmind_db_path: Optional[str] = None, 
                        ipinfo_token: Optional[str] = None,
                        use_cache: bool = True,
                        cache: Optional[Dict[str, str]] = None) -> Optional[str]:
    """
    Get organization information for an IP address.
    
    Args:
        ip (str): IP address
        maxmind_db_path (Optional[str]): Path to MaxMind GeoLite2-ASN database
        ipinfo_token (Optional[str]): Token for ipinfo.io API
        use_cache (bool): Whether to use cache
        cache (Optional[Dict[str, str]]): Cache dictionary
        
    Returns:
        Optional[str]: Organization name or None if not found
    """
    # Validate IP address
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        logger.error(f"Invalid IP address: {ip}")
        return None
    
    # Check cache if enabled
    if use_cache and cache is not None and ip in cache:
        return cache[ip]
    
    # Try MaxMind GeoLite2 database first
    if GEOIP2_AVAILABLE and maxmind_db_path and os.path.exists(maxmind_db_path):
        try:
            with geoip2.database.Reader(maxmind_db_path) as reader:
                response = reader.asn(ip)
                organization = response.autonomous_system_organization
                
                # Update cache
                if use_cache and cache is not None:
                    cache[ip] = organization
                
                return organization
        except geoip2.errors.AddressNotFoundError:
            logger.debug(f"IP address not found in MaxMind database: {ip}")
        except Exception as e:
            logger.error(f"Error querying MaxMind database: {e}")
    
    # For private IP addresses, return a standard label
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            return "Private Network"
    except Exception:
        pass
    
    # For small batches or individual lookups, try ipwhois
    if IPWHOIS_AVAILABLE:
        try:
            ipwhois = IPWhois(ip)
            result = ipwhois.lookup_rdap(depth=1)
            organization = result.get('asn_description') or result.get('network', {}).get('name')
            
            # Update cache
            if organization and use_cache and cache is not None:
                cache[ip] = organization
            
            return organization
        except Exception as e:
            logger.debug(f"Error in WHOIS lookup for {ip}: {e}")
    
    # For medium batches, try ipinfo.io API
    if REQUESTS_AVAILABLE and ipinfo_token:
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json?token={ipinfo_token}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                organization = data.get('org', '').split(' ', 1)[1] if ' ' in data.get('org', '') else data.get('org')
                
                # Update cache
                if organization and use_cache and cache is not None:
                    cache[ip] = organization
                
                return organization
        except Exception as e:
            logger.debug(f"Error querying ipinfo.io API for {ip}: {e}")
    
    # If all methods fail, return None
    return None


def enrich_targets_with_organization(targets: Dict[str, Any], 
                                     maxmind_db_path: Optional[str] = None,
                                     ipinfo_token: Optional[str] = None) -> Dict[str, Any]:
    """
    Enrich targets with organization information.
    
    Args:
        targets (Dict[str, Any]): Targets dictionary
        maxmind_db_path (Optional[str]): Path to MaxMind GeoLite2-ASN database
        ipinfo_token (Optional[str]): Token for ipinfo.io API
        
    Returns:
        Dict[str, Any]: Enriched targets dictionary
    """
    logger.info("Enriching targets with organization information")
    
    # Create a cache for organization lookups
    org_cache = {}
    
    # Get IP addresses
    ip_addresses = targets.get("ip_addresses", {})
    ip_count = len(ip_addresses)
    
    # Determine lookup method based on IP count
    if ip_count < 1000:
        logger.info(f"Small batch ({ip_count} IPs), using direct lookups")
        use_ipinfo = False
    else:
        logger.info(f"Medium batch ({ip_count} IPs), using ipinfo.io API if available")
        use_ipinfo = True and ipinfo_token is not None
    
    # Process each IP address
    for i, (ip, ip_data) in enumerate(ip_addresses.items()):
        # Get organization
        organization = get_ip_organization(
            ip, 
            maxmind_db_path=maxmind_db_path,
            ipinfo_token=ipinfo_token if use_ipinfo else None,
            use_cache=True,
            cache=org_cache
        )
        
        # Add organization to IP data
        if organization:
            ip_addresses[ip]["organization"] = organization
        
        # Log progress for large batches
        if i > 0 and i % 100 == 0:
            logger.info(f"Processed {i}/{ip_count} IP addresses")
        
        # Rate limiting for API calls
        if use_ipinfo and i > 0 and i % 10 == 0:
            time.sleep(1)  # Respect API rate limits
    
    logger.info(f"Completed organization enrichment for {ip_count} IP addresses")
    return targets


def format_results_with_organization(results: List[Dict[str, Any]], 
                                     targets: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Format scan results with organization information.
    
    Args:
        results (List[Dict[str, Any]]): Scan results
        targets (Dict[str, Any]): Targets dictionary with organization information
        
    Returns:
        List[Dict[str, Any]]: Formatted results with organization information
    """
    # Get IP addresses with organization information
    ip_addresses = targets.get("ip_addresses", {})
    
    # Add organization to results
    for result in results:
        ip = result.get("ip")
        if ip and ip in ip_addresses and "organization" in ip_addresses[ip]:
            result["organization"] = ip_addresses[ip]["organization"]
    
    return results
