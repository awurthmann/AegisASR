#!/usr/bin/env python3
"""
AegisASR

A modular open-source attack surface reconnaissance platform for scanning network assets across multiple cloud environments.
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

from src.config import load_config, validate_config, get_ip_intel_config
from src.input.json_handler import load_json_targets, validate_json_format
from src.input.dns_handler import load_dns_zone, convert_dns_to_json
from src.cloud.common import select_cloud_platforms
from src.scan.scanner import prepare_scan_jobs
from src.scan.rate_limiter import calculate_concurrency_limit
from src.utils import setup_logging, display_progress, display_warning
from src.intel import enrich_targets_with_organization, format_results_with_organization

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
        "--maxmind-db", "-m",
        type=str,
        help="Path to MaxMind GeoLite2-ASN database (overrides config file)"
    )
    parser.add_argument(
        "--ipinfo-token", "-t",
        type=str,
        help="Token for ipinfo.io API (overrides config file)"
    )
    parser.add_argument(
        "--no-ip-intel",
        action="store_true",
        help="Disable IP intelligence enrichment"
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
        
        # Enrich targets with organization information if not disabled
        if not args.no_ip_intel:
            # Get IP intelligence configuration
            ip_intel_config = get_ip_intel_config(config)
            
            # Override with command line arguments if provided
            if args.maxmind_db:
                ip_intel_config["MAXMIND_DB_PATH"] = args.maxmind_db
            if args.ipinfo_token:
                ip_intel_config["IPINFO_TOKEN"] = args.ipinfo_token
            
            # Check if MaxMind database exists
            maxmind_db_path = ip_intel_config.get("MAXMIND_DB_PATH")
            if maxmind_db_path and os.path.exists(maxmind_db_path):
                logger.info(f"Using MaxMind GeoLite2-ASN database: {maxmind_db_path}")
            else:
                if maxmind_db_path:
                    logger.warning(f"MaxMind database not found at: {maxmind_db_path}")
                logger.info("Falling back to alternative IP intelligence sources")
            
            # Enrich targets with organization information
            logger.info("Enriching targets with organization information")
            targets = enrich_targets_with_organization(
                targets,
                maxmind_db_path=ip_intel_config.get("MAXMIND_DB_PATH"),
                ipinfo_token=ip_intel_config.get("IPINFO_TOKEN")
            )
        
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
        
        # Execute scans using the selected cloud platform(s)
        logger.info("Executing scans...")
        
        from src.cloud.common import get_cloud_handler, select_storage_platform
        
        # Initialize handlers for selected platforms
        handlers = {}
        for platform in selected_platforms:
            handler = get_cloud_handler(platform)
            if handler and handler.initialize(config):
                handlers[platform] = handler
                logger.info(f"Initialized {platform.upper()} handler")
            else:
                logger.error(f"Failed to initialize {platform.upper()} handler")
                return 1
        
        if not handlers:
            logger.error("No cloud handlers were initialized")
            return 1
        
        # If multiple platforms are selected, ask user which one to use for storage
        storage_platform = None
        if len(handlers) > 1:
            logger.info("Multiple cloud platforms selected, choosing one for result storage")
            storage_platform = select_storage_platform(list(handlers.keys()))
            if not storage_platform:
                logger.error("No storage platform selected")
                return 1
            logger.info(f"Selected {storage_platform.upper()} for result storage")
        else:
            # If only one platform, use it for storage
            storage_platform = list(handlers.keys())[0]
        
        # Create cloud resources
        for platform, handler in handlers.items():
            if platform == "aws":
                handler.create_lambda_function()
                if platform == storage_platform:
                    handler.create_s3_bucket()
                    handler.create_athena_database()
            elif platform == "azure":
                handler.create_resource_group()
                handler.create_storage_account()
                handler.create_function_app()
                if platform == storage_platform:
                    handler.create_synapse_workspace()
            elif platform == "gcp":
                handler.create_storage_bucket()
                if platform == storage_platform:
                    handler.create_bigquery_dataset()
            
            # Deploy function
            handler.deploy_function()
        
        # Execute scan jobs on each platform
        all_results = []
        for platform, handler in handlers.items():
            logger.info(f"Executing scan jobs on {platform.upper()}")
            results = handler.execute_scan_jobs(scan_jobs, concurrency_limit)
            all_results.extend(results)
        
        # Add organization information to results if IP intelligence is enabled
        if not args.no_ip_intel:
            logger.info("Adding organization information to scan results")
            all_results = format_results_with_organization(all_results, targets)
        
        # Store results in the selected platform
        storage_handler = handlers[storage_platform]
        if storage_handler.store_results(all_results):
            logger.info(f"Results stored successfully in {storage_platform.upper()}")
        else:
            logger.error(f"Failed to store results in {storage_platform.upper()}")
            return 1
        
        # Clean up resources (except storage)
        for platform, handler in handlers.items():
            if handler.cleanup():
                logger.info(f"Cleaned up {platform.upper()} resources")
            else:
                logger.warning(f"Failed to clean up some {platform.upper()} resources")
        
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
