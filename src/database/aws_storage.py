"""
AWS Storage Handler Module

This module handles AWS storage functionality for scan results.

Classes:
    AWSStorageHandler: Handler for AWS storage
"""

import json
import logging
import os
import time
import uuid
from typing import Dict, List, Any, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

from ..config import get_aws_config
from .common import format_results_for_storage

logger = logging.getLogger(__name__)


class AWSStorageHandler:
    """
    Handler for AWS storage.
    """
    
    def __init__(self):
        """
        Initialize AWS storage handler.
        """
        self.s3_client = None
        self.athena_client = None
        self.bucket_name = None
        self.database_name = "attack_surface_scans"
        self.table_name = "scan_results"
    
    def initialize(self, config: Dict[str, str]) -> bool:
        """
        Initialize AWS clients.
        
        Args:
            config (Dict[str, str]): Configuration dictionary
            
        Returns:
            bool: True if initialization was successful, False otherwise
        """
        logger.debug("Initializing AWS storage handler")
        
        # Get AWS configuration
        aws_config = get_aws_config(config)
        if not aws_config:
            logger.error("AWS configuration is missing or invalid")
            return False
        
        # Initialize AWS clients
        try:
            self.s3_client = boto3.client(
                "s3",
                aws_access_key_id=aws_config["AWS_ACCESS_KEY_ID"],
                aws_secret_access_key=aws_config["AWS_SECRET_ACCESS_KEY"],
                region_name=aws_config["AWS_REGION"]
            )
            
            self.athena_client = boto3.client(
                "athena",
                aws_access_key_id=aws_config["AWS_ACCESS_KEY_ID"],
                aws_secret_access_key=aws_config["AWS_SECRET_ACCESS_KEY"],
                region_name=aws_config["AWS_REGION"]
            )
            
            # Create S3 bucket for results
            self.bucket_name = f"attack-surface-scans-{uuid.uuid4().hex[:8]}"
            
            logger.debug("AWS storage handler initialized successfully")
            return True
        
        except Exception as e:
            logger.error(f"Failed to initialize AWS storage handler: {e}")
            return False
    
    def create_storage_resources(self) -> bool:
        """
        Create AWS storage resources.
        
        Returns:
            bool: True if creation was successful, False otherwise
        """
        logger.debug("Creating AWS storage resources")
        
        try:
            # Create S3 bucket
            if not self.create_s3_bucket():
                return False
            
            # Create Athena database and table
            if not self.create_athena_database():
                return False
            
            logger.debug("AWS storage resources created successfully")
            return True
        
        except Exception as e:
            logger.error(f"Failed to create AWS storage resources: {e}")
            return False
    
    def create_s3_bucket(self) -> bool:
        """
        Create S3 bucket for storing scan results.
        
        Returns:
            bool: True if creation was successful, False otherwise
        """
        logger.debug(f"Creating S3 bucket: {self.bucket_name}")
        
        try:
            # Create S3 bucket
            self.s3_client.create_bucket(
                Bucket=self.bucket_name,
                CreateBucketConfiguration={
                    "LocationConstraint": self.s3_client.meta.region_name
                }
            )
            
            logger.debug(f"S3 bucket created: {self.bucket_name}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to create S3 bucket: {e}")
            return False
    
    def create_athena_database(self) -> bool:
        """
        Create Athena database for querying scan results.
        
        Returns:
            bool: True if creation was successful, False otherwise
        """
        logger.debug(f"Creating Athena database: {self.database_name}")
        
        try:
            # Create Athena database
            self.athena_client.start_query_execution(
                QueryString=f"CREATE DATABASE IF NOT EXISTS {self.database_name}",
                ResultConfiguration={
                    "OutputLocation": f"s3://{self.bucket_name}/athena-results/"
                }
            )
            
            # Create Athena table
            query = f"""
            CREATE EXTERNAL TABLE IF NOT EXISTS {self.database_name}.{self.table_name} (
                ip_address STRING,
                scan_time TIMESTAMP,
                ports MAP<STRING, BOOLEAN>
            )
            STORED AS PARQUET
            LOCATION 's3://{self.bucket_name}/scan-results/'
            """
            
            self.athena_client.start_query_execution(
                QueryString=query,
                ResultConfiguration={
                    "OutputLocation": f"s3://{self.bucket_name}/athena-results/"
                }
            )
            
            logger.debug(f"Athena database and table created: {self.database_name}.{self.table_name}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to create Athena database: {e}")
            return False
    
    def store_results(self, results: List[Dict[str, Any]]) -> bool:
        """
        Store scan results in S3 and Athena.
        
        Args:
            results (List[Dict[str, Any]]): List of scan results
            
        Returns:
            bool: True if storage was successful, False otherwise
        """
        logger.debug(f"Storing {len(results)} scan results")
        
        try:
            # Format results for storage
            formatted_results = format_results_for_storage(results)
            
            # Store results in S3
            for ip, data in formatted_results.items():
                # Convert to Parquet format (simplified for now)
                parquet_data = {
                    "ip_address": ip,
                    "scan_time": data["scan_time"],
                    "ports": data["ports"]
                }
                
                # Store in S3
                self.s3_client.put_object(
                    Bucket=self.bucket_name,
                    Key=f"scan-results/{ip}.json",
                    Body=json.dumps(parquet_data)
                )
            
            logger.debug(f"Stored {len(formatted_results)} results in S3")
            return True
        
        except Exception as e:
            logger.error(f"Failed to store results: {e}")
            return False
    
    def query_results(self, query: str) -> List[Dict[str, Any]]:
        """
        Query scan results using Athena.
        
        Args:
            query (str): SQL query
            
        Returns:
            List[Dict[str, Any]]: Query results
        """
        logger.debug(f"Querying scan results: {query}")
        
        try:
            # Execute query
            response = self.athena_client.start_query_execution(
                QueryString=query,
                QueryExecutionContext={
                    "Database": self.database_name
                },
                ResultConfiguration={
                    "OutputLocation": f"s3://{self.bucket_name}/athena-results/"
                }
            )
            
            # Get query execution ID
            query_execution_id = response["QueryExecutionId"]
            
            # Wait for query to complete
            while True:
                response = self.athena_client.get_query_execution(
                    QueryExecutionId=query_execution_id
                )
                
                state = response["QueryExecution"]["Status"]["State"]
                
                if state == "SUCCEEDED":
                    break
                elif state == "FAILED" or state == "CANCELLED":
                    logger.error(f"Query failed: {response}")
                    return []
                
                time.sleep(1)
            
            # Get query results
            response = self.athena_client.get_query_results(
                QueryExecutionId=query_execution_id
            )
            
            # Parse results
            results = []
            header = [col["Name"] for col in response["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]]
            
            for row in response["ResultSet"]["Rows"][1:]:  # Skip header row
                data = {}
                for i, value in enumerate(row["Data"]):
                    if "VarCharValue" in value:
                        data[header[i]] = value["VarCharValue"]
                    else:
                        data[header[i]] = None
                results.append(data)
            
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
        SELECT ip_address, k AS port
        FROM {self.database_name}.{self.table_name}
        CROSS JOIN UNNEST(ports) AS t(k, v)
        WHERE v = true
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
        SELECT ip_address, k AS port
        FROM {self.database_name}.{self.table_name}
        CROSS JOIN UNNEST(ports) AS t(k, v)
        WHERE v = false
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
        SELECT ip_address, k AS port, v AS is_open
        FROM {self.database_name}.{self.table_name}
        CROSS JOIN UNNEST(ports) AS t(k, v)
        WHERE ip_address = '{ip}'
        ORDER BY port
        """
        
        return self.query_results(query)
