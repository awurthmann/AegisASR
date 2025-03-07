#!/usr/bin/env python3
"""
AegisASR

A modular open-source platform for scanning network assets across multiple cloud environments.
This tool allows users to scan network assets for open TCP ports with appropriate rate limiting
and security considerations.

Usage:
    python main.py

Author: Cline
Date: 2025-03-07
"""

import argparse
import logging
import os
import sys
from typing import Dict, List, Optional, Set, Tuple

from src.config import load_config, validate_config
from src.input.json_handler import load_json_targets, validate_json_format
from src.input.dns_handler import load_dns_zone, convert_dns_to_json
from src.cloud.common import select_cloud_platforms
from src.scan.scanner import prepare_scan_jobs
from src.scan.rate_limiter import calculate_concurrency_limit
from src.utils import setup_logging, display_progress, display_warning

# Setup logging
logger = logging.getLogger(__name__)


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="AegisASR - Network Asset Scanner"
    )
    parser.add_argument(
        "--input", "-i", 
        type=str, 
        help="Path to input file (JSON or DNS zone file)"
    )
    parser.add_argument(
        "--output", "-o", 
        type=str, 
        help="Path to output directory for results"
    )
    parser.add_argument(
        "--cloud", "-c", 
        type=str, 
        choices=["aws", "azure", "gcp", "all"],
        default="aws", 
        help="Cloud platform(s) to use for scanning"
    )
    parser.add_argument(
        "--ports", "-p", 
        type=str, 
        help="Comma-separated list of TCP ports to scan (for DNS input only)"
    )
    parser.add_argument(
        "--verbose", "-v", 
        action="store_true", 
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--dry-run", "-d", 
        action="store_true", 
        help="Perform a dry run without executing scans"
    )
    
    return parser.parse_args()


def main() -> int:
    """Main entry point for the application."""
    # Parse command line arguments
    args = parse_arguments()
    
    # Setup logging based on verbosity
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(log_level)
    
    logger.info("Starting AegisASR")
    
    try:
        # Load and validate configuration
        config = load_config()
        if not validate_config(config):
            logger.error("Invalid configuration. Please check your .env file.")
            return 1
        
        # Process input file
        targets = {}
        if args.input:
            if args.input.lower().endswith(('.json')):
                logger.info(f"Loading JSON targets from {args.input}")
                targets = load_json_targets(args.input)
                if not validate_json_format(targets):
                    logger.error("Invalid JSON format. Please check your input file.")
                    return 1
            elif args.input.lower().endswith(('.zone', '.dns')):
                logger.info(f"Loading DNS zone file from {args.input}")
                dns_records = load_dns_zone(args.input)
                default_ports = [80, 443]
                if args.ports:
                    try:
                        custom_ports = [int(p.strip()) for p in args.ports.split(',')]
                        targets = convert_dns_to_json(dns_records, custom_ports)
                    except ValueError:
                        logger.error("Invalid port specification. Please provide comma-separated integers.")
                        return 1
                else:
                    targets = convert_dns_to_json(dns_records, default_ports)
            else:
                logger.error("Unsupported input file format. Please provide a JSON or DNS zone file.")
                return 1
        else:
            logger.error("No input file specified. Use --input to provide a JSON or DNS zone file.")
            return 1
        
        # Select cloud platforms
        selected_platforms = []
        if args.cloud == "all":
            selected_platforms = ["aws", "azure", "gcp"]
        else:
            selected_platforms = [args.cloud]
        
        logger.info(f"Selected cloud platforms: {', '.join(selected_platforms)}")
        
        # Calculate concurrency limit based on target count
        target_count = len(targets.get("ip_addresses", {}))
        concurrency_limit = calculate_concurrency_limit(target_count)
        logger.info(f"Target count: {target_count}, Concurrency limit: {concurrency_limit}")
        
        # Display warning and get confirmation
        if not args.dry_run:
            if not display_warning():
                logger.info("Scan cancelled by user.")
                return 0
        
        # Prepare scan jobs
        scan_jobs = prepare_scan_jobs(targets, concurrency_limit)
        
        if args.dry_run:
            logger.info("Dry run completed. No scans were executed.")
            return 0
        
        # Execute scans (implementation will be added in cloud modules)
        logger.info("Executing scans...")
        # This will be implemented in the cloud modules
        
        logger.info("Scan completed successfully.")
        return 0
        
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user.")
        return 130
    except Exception as e:
        logger.exception(f"An unexpected error occurred: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
