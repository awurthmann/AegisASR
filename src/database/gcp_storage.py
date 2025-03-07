"""
GCP Storage Handler Module

This module handles Google Cloud Platform storage functionality for scan results.

Classes:
    GCPStorageHandler: Handler for GCP storage
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
    from google.oauth2 import service_account
    from google.api_core.exceptions import GoogleAPIError
except ImportError:
    logging.warning("Google Cloud SDK not installed. GCP functionality will not be available.")

from ..config import get_gcp_config
from .common import format_results_for_storage

logger = logging.getLogger(__name__)


class GCPStorageHandler:
    """
    Handler for GCP storage.
    """
    
    def __init__(self):
        """
        Initialize GCP storage handler.
        """
        self.credentials = None
        self.storage_client = None
        self.bigquery_client = None
        
        self.project_id = None
        self.bucket_name = f"attack-surface-scans-{uuid.uuid4().hex[:8]}"
        self.dataset_id = "attack_surface_scans"
        self.table_id = "scan_results"
        
        self.location = "us-central1"  # Default location
    
    def initialize(self, config: Dict[str, str]) -> bool:
        """
        Initialize GCP clients.
        
        Args:
            config (Dict[str, str]): Configuration dictionary
            
        Returns:
            bool: True if initialization was successful, False otherwise
        """
        logger.debug("Initializing GCP storage handler")
        
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
            
            logger.debug("GCP storage handler initialized successfully")
            return True
        
        except Exception as e:
            logger.error(f"Failed to initialize GCP storage handler: {e}")
            return False
    
    def create_storage_resources(self) -> bool:
        """
        Create GCP storage resources.
        
        Returns:
            bool: True if creation was successful, False otherwise
        """
        logger.debug("Creating GCP storage resources")
        
        try:
            # Create storage bucket
            if not self.create_storage_bucket():
                return False
            
            # Create BigQuery dataset and table
            if not self.create_bigquery_dataset():
                return False
            
            logger.debug("GCP storage resources created successfully")
            return True
        
        except Exception as e:
            logger.error(f"Failed to create GCP storage resources: {e}")
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
            bucket.create(location=self.location)
            
            logger.debug(f"GCP storage bucket created: {self.bucket_name}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to create GCP storage bucket: {e}")
            return False
    
    def create_bigquery_dataset(self) -> bool:
        """
        Create BigQuery dataset and table.
        
        Returns:
            bool: True if creation was successful, False otherwise
        """
        logger.debug(f"Creating BigQuery dataset: {self.dataset_id}")
        
        try:
            # Create dataset
            dataset_ref = self.bigquery_client.dataset(self.dataset_id)
            dataset = bigquery.Dataset(dataset_ref)
            dataset.location = self.location
            
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
    
    def query_results(self, query: str) -> List[Dict[str, Any]]:
        """
        Query scan results using BigQuery.
        
        Args:
            query (str): SQL query
            
        Returns:
            List[Dict[str, Any]]: Query results
        """
        logger.debug(f"Querying scan results: {query}")
        
        try:
            # Execute query
            query_job = self.bigquery_client.query(query)
            
            # Get results
            results = []
            for row in query_job:
                # Convert row to dictionary
                result = {}
                for key, value in row.items():
                    result[key] = value
                results.append(result)
            
            logger.debug(f"Query returned {len(results)} results")
            return results
        
        except Exception as e:
            logger.error(f"Failed to query results: {e}")
            return []
    
    def get_open_ports(self) -> List[Dict[str, Any]]:
        """
        Get all open ports from scan results.
        
        Returns:
            List[Dict[str, Any]]: List of open ports
        """
        logger.debug("Getting open ports")
        
        query = f"""
        SELECT ip_address, port
        FROM `{self.project_id}.{self.dataset_id}.{self.table_id}`,
        UNNEST(JSON_EXTRACT_ARRAY(ports)) AS port_data
        WHERE JSON_EXTRACT_SCALAR(port_data, '$.value') = 'true'
        ORDER BY ip_address, port
        """
        
        return self.query_results(query)
    
    def get_closed_ports(self) -> List[Dict[str, Any]]:
        """
        Get all closed ports from scan results.
        
        Returns:
            List[Dict[str, Any]]: List of closed ports
        """
        logger.debug("Getting closed ports")
        
        query = f"""
        SELECT ip_address, port
        FROM `{self.project_id}.{self.dataset_id}.{self.table_id}`,
        UNNEST(JSON_EXTRACT_ARRAY(ports)) AS port_data
        WHERE JSON_EXTRACT_SCALAR(port_data, '$.value') = 'false'
        ORDER BY ip_address, port
        """
        
        return self.query_results(query)
    
    def get_results_by_ip(self, ip: str) -> List[Dict[str, Any]]:
        """
        Get scan results for a specific IP address.
        
        Args:
            ip (str): IP address
            
        Returns:
            List[Dict[str, Any]]: Scan results
        """
        logger.debug(f"Getting results for IP: {ip}")
        
        query = f"""
        SELECT ip_address, port, is_open
        FROM `{self.project_id}.{self.dataset_id}.{self.table_id}`,
        UNNEST(JSON_EXTRACT_ARRAY(ports)) AS port_data
        WHERE ip_address = '{ip}'
        ORDER BY port
        """
        
        return self.query_results(query)
