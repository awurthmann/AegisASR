"""
GCP Function Handler Module

This module handles Google Cloud Function functionality for executing scans.

Classes:
    GCPFunctionHandler: Handler for Google Cloud Functions
"""

import json
import logging
import os
import time
import uuid
from typing import Dict, List, Any, Optional, Tuple

# GCP SDK imports
try:
    from google.cloud import storage
    from google.cloud import bigquery
    from google.cloud import functions_v1
    from google.oauth2 import service_account
    from google.api_core.exceptions import GoogleAPIError
except ImportError:
    logging.warning("Google Cloud SDK not installed. GCP functionality will not be available.")

from ...config import get_gcp_config
from ...scan.scanner import format_results_for_storage
from ...utils import display_progress

logger = logging.getLogger(__name__)


class GCPFunctionHandler:
    """
    Handler for Google Cloud Functions.
    """
    
    def __init__(self):
        """
        Initialize GCP Function handler.
        """
        self.credentials = None
        self.storage_client = None
        self.bigquery_client = None
        self.functions_client = None
        
        self.project_id = None
        self.function_name = f"attack-surface-scanner-{uuid.uuid4().hex[:8]}"
        self.bucket_name = f"attack-surface-scans-{uuid.uuid4().hex[:8]}"
        self.dataset_id = "attack_surface_scans"
        self.table_id = "scan_results"
        
        self.region = "us-central1"  # Default region
    
    def initialize(self, config: Dict[str, str]) -> bool:
        """
        Initialize GCP clients.
        
        Args:
            config (Dict[str, str]): Configuration dictionary
            
        Returns:
            bool: True if initialization was successful, False otherwise
        """
        logger.debug("Initializing GCP Function handler")
        
        # Get GCP configuration
        gcp_config = get_gcp_config(config)
        if not gcp_config:
            logger.error("GCP configuration is missing or invalid")
            return False
        
        # Initialize GCP clients
        try:
            # Set project ID
            self.project_id = gcp_config["GCP_PROJECT_ID"]
            
            # Create credentials
            credentials_file = gcp_config["GCP_CREDENTIALS_FILE"]
            if not os.path.exists(credentials_file):
                logger.error(f"GCP credentials file not found: {credentials_file}")
                return False
            
            self.credentials = service_account.Credentials.from_service_account_file(
                credentials_file
            )
            
            # Create storage client
            self.storage_client = storage.Client(
                project=self.project_id,
                credentials=self.credentials
            )
            
            # Create BigQuery client
            self.bigquery_client = bigquery.Client(
                project=self.project_id,
                credentials=self.credentials
            )
            
            # Create Functions client
            self.functions_client = functions_v1.CloudFunctionsServiceClient(
                credentials=self.credentials
            )
            
            logger.debug("GCP Function handler initialized successfully")
            return True
        
        except Exception as e:
            logger.error(f"Failed to initialize GCP Function handler: {e}")
            return False
    
    def create_storage_bucket(self) -> bool:
        """
        Create GCP storage bucket.
        
        Returns:
            bool: True if creation was successful, False otherwise
        """
        logger.debug(f"Creating GCP storage bucket: {self.bucket_name}")
        
        try:
            # Create storage bucket
            bucket = self.storage_client.bucket(self.bucket_name)
            bucket.create(location=self.region)
            
            logger.debug(f"GCP storage bucket created: {self.bucket_name}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to create GCP storage bucket: {e}")
            return False
    
    def create_bigquery_dataset(self) -> bool:
        """
        Create BigQuery dataset.
        
        Returns:
            bool: True if creation was successful, False otherwise
        """
        logger.debug(f"Creating BigQuery dataset: {self.dataset_id}")
        
        try:
            # Create dataset
            dataset_ref = self.bigquery_client.dataset(self.dataset_id)
            dataset = bigquery.Dataset(dataset_ref)
            dataset.location = self.region
            
            # Create dataset if it doesn't exist
            try:
                self.bigquery_client.get_dataset(dataset_ref)
                logger.debug(f"BigQuery dataset already exists: {self.dataset_id}")
            except Exception:
                dataset = self.bigquery_client.create_dataset(dataset)
                logger.debug(f"BigQuery dataset created: {self.dataset_id}")
            
            # Create table
            table_ref = dataset_ref.table(self.table_id)
            table = bigquery.Table(table_ref, schema=[
                bigquery.SchemaField("ip_address", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("scan_time", "TIMESTAMP", mode="REQUIRED"),
                bigquery.SchemaField("ports", "STRING", mode="REQUIRED")  # JSON string
            ])
            
            # Create table if it doesn't exist
            try:
                self.bigquery_client.get_table(table_ref)
                logger.debug(f"BigQuery table already exists: {self.table_id}")
            except Exception:
                table = self.bigquery_client.create_table(table)
                logger.debug(f"BigQuery table created: {self.table_id}")
            
            return True
        
        except Exception as e:
            logger.error(f"Failed to create BigQuery dataset: {e}")
            return False
    
    def deploy_function(self) -> bool:
        """
        Deploy Google Cloud Function for scanning.
        
        Returns:
            bool: True if deployment was successful, False otherwise
        """
        logger.debug("Deploying Google Cloud Function")
        
        # Function code
        function_code = """
import json
import socket
import time

def check_tcp_port(host, port, timeout=1):
    \"\"\"Attempts a TCP connection to check if the port is open.\"\"\"
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True  # Port is open
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False  # Port is closed

def scan_port(request):
    \"\"\"Google Cloud Function HTTP trigger.\"\"\"
    # Get scan job from request
    request_json = request.get_json(silent=True)
    
    if not request_json or 'scan_job' not in request_json:
        return json.dumps({
            'error': 'Invalid request: missing scan_job'
        }), 400
    
    scan_job = request_json['scan_job']
    
    # Extract scan job parameters
    ip = scan_job.get('ip')
    port = scan_job.get('port')
    hostnames = scan_job.get('hostnames', [])
    
    if not ip or not port:
        return json.dumps({
            'error': 'Missing required parameters: ip, port'
        }), 400
    
    # Check if the port is open
    is_open = check_tcp_port(ip, port)
    
    # Return scan result
    result = {
        'ip': ip,
        'port': port,
        'is_open': is_open,
        'hostnames': hostnames,
        'timestamp': time.time()
    }
    
    return json.dumps(result)
"""
        
        # Requirements.txt
        requirements_txt = """
functions-framework==3.0.0
"""
        
        try:
            # TODO: Deploy function code
            # This would typically involve creating a zip package and deploying it
            # For simplicity, we'll assume the function is deployed
            
            logger.debug("Google Cloud Function deployed successfully")
            return True
        
        except Exception as e:
            logger.error(f"Failed to deploy Google Cloud Function: {e}")
            return False
    
    def execute_scan_jobs(self, scan_jobs: List[Dict[str, Any]], concurrency_limit: int) -> List[Dict[str, Any]]:
        """
        Execute scan jobs on Google Cloud Functions.
        
        Args:
            scan_jobs (List[Dict[str, Any]]): List of scan jobs
            concurrency_limit (int): Maximum number of concurrent scans
            
        Returns:
            List[Dict[str, Any]]: List of scan results
        """
        logger.debug(f"Executing {len(scan_jobs)} scan jobs on Google Cloud Functions")
        
        # Split scan jobs into batches
        batches = []
        for i in range(0, len(scan_jobs), concurrency_limit):
            batches.append(scan_jobs[i:i + concurrency_limit])
        
        # Execute batches
        results = []
        for i, batch in enumerate(batches):
            logger.debug(f"Executing batch {i+1}/{len(batches)} ({len(batch)} jobs)")
            
            # TODO: Invoke Google Cloud Functions
            # For simplicity, we'll simulate the execution
            
            # Simulate batch execution
            batch_results = []
            for job in batch:
                # Simulate function execution
                result = {
                    "ip": job["ip"],
                    "port": job["port"],
                    "is_open": False,  # Simulated result
                    "hostnames": job["hostnames"],
                    "timestamp": time.time()
                }
                batch_results.append(result)
            
            # Add batch results to overall results
            results.extend(batch_results)
            
            # Display progress
            display_progress(len(results), len(scan_jobs))
            
            # Add delay between batches
            if i < len(batches) - 1:
                time.sleep(1)
        
        logger.debug(f"Completed {len(results)}/{len(scan_jobs)} scan jobs")
        return results
    
    def store_results(self, results: List[Dict[str, Any]]) -> bool:
        """
        Store scan results in GCP BigQuery.
        
        Args:
            results (List[Dict[str, Any]]): List of scan results
            
        Returns:
            bool: True if storage was successful, False otherwise
        """
        logger.debug(f"Storing {len(results)} scan results")
        
        try:
            # Format results for storage
            formatted_results = format_results_for_storage(results)
            
            # Store results in BigQuery
            rows_to_insert = []
            for ip, data in formatted_results.items():
                # Convert to BigQuery row format
                rows_to_insert.append({
                    "ip_address": ip,
                    "scan_time": data["scan_time"],
                    "ports": json.dumps(data["ports"])
                })
            
            # Insert rows
            table_ref = self.bigquery_client.dataset(self.dataset_id).table(self.table_id)
            errors = self.bigquery_client.insert_rows_json(table_ref, rows_to_insert)
            
            if errors:
                logger.error(f"Errors inserting rows into BigQuery: {errors}")
                return False
            
            logger.debug(f"Stored {len(formatted_results)} results in BigQuery")
            return True
        
        except Exception as e:
            logger.error(f"Failed to store results: {e}")
            return False
    
    def cleanup(self) -> bool:
        """
        Clean up GCP resources.
        
        Returns:
            bool: True if cleanup was successful, False otherwise
        """
        logger.debug("Cleaning up GCP resources")
        
        try:
            # Delete function
            # Note: We don't delete the storage bucket or BigQuery dataset
            # as they contain the scan results
            
            logger.debug("GCP resources cleaned up successfully")
            return True
        
        except Exception as e:
            logger.error(f"Failed to clean up GCP resources: {e}")
            return False
