"""
AWS Lambda Handler Module

This module handles AWS Lambda functionality for executing scans.

Classes:
    AWSLambdaHandler: Handler for AWS Lambda
"""

import json
import logging
import os
import time
import uuid
from typing import Dict, List, Any, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

from ...config import get_aws_config
from ...scan.scanner import format_results_for_storage
from ...utils import display_progress

logger = logging.getLogger(__name__)


class AWSLambdaHandler:
    """
    Handler for AWS Lambda.
    """
    
    def __init__(self):
        """
        Initialize AWS Lambda handler.
        """
        self.lambda_client = None
        self.s3_client = None
        self.athena_client = None
        self.function_name = f"attack-surface-scanner-{uuid.uuid4().hex[:8]}"
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
        logger.debug("Initializing AWS Lambda handler")
        
        # Get AWS configuration
        aws_config = get_aws_config(config)
        if not aws_config:
            logger.error("AWS configuration is missing or invalid")
            return False
        
        # Initialize AWS clients
        try:
            self.lambda_client = boto3.client(
                "lambda",
                aws_access_key_id=aws_config["AWS_ACCESS_KEY_ID"],
                aws_secret_access_key=aws_config["AWS_SECRET_ACCESS_KEY"],
                region_name=aws_config["AWS_REGION"]
            )
            
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
            
            logger.debug("AWS Lambda handler initialized successfully")
            return True
        
        except Exception as e:
            logger.error(f"Failed to initialize AWS Lambda handler: {e}")
            return False
    
    def create_lambda_function(self) -> bool:
        """
        Create AWS Lambda function for scanning.
        
        Returns:
            bool: True if creation was successful, False otherwise
        """
        logger.debug("Creating AWS Lambda function")
        
        # Lambda function code
        lambda_code = """
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

def lambda_handler(event, context):
    \"\"\"AWS Lambda handler.\"\"\"
    # Get scan job from event
    scan_job = event.get('scan_job', {})
    
    # Extract scan job parameters
    ip = scan_job.get('ip')
    port = scan_job.get('port')
    hostnames = scan_job.get('hostnames', [])
    
    # Check if the port is open
    is_open = check_tcp_port(ip, port)
    
    # Return scan result
    return {
        'ip': ip,
        'port': port,
        'is_open': is_open,
        'hostnames': hostnames,
        'timestamp': time.time()
    }
"""
        
        # Create Lambda function
        try:
            # Create IAM role for Lambda
            iam_client = boto3.client("iam")
            
            # Create role
            role_name = f"attack-surface-scanner-role-{uuid.uuid4().hex[:8]}"
            assume_role_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "lambda.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            }
            
            role_response = iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(assume_role_policy)
            )
            
            # Attach basic execution policy
            iam_client.attach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
            )
            
            # Wait for role to propagate
            time.sleep(10)
            
            # Create Lambda function
            response = self.lambda_client.create_function(
                FunctionName=self.function_name,
                Runtime="python3.9",
                Role=role_response["Role"]["Arn"],
                Handler="lambda_function.lambda_handler",
                Code={
                    "ZipFile": lambda_code.encode()
                },
                Timeout=10,
                MemorySize=128
            )
            
            logger.debug(f"AWS Lambda function created: {self.function_name}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to create AWS Lambda function: {e}")
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
    
    def execute_scan_jobs(self, scan_jobs: List[Dict[str, Any]], concurrency_limit: int) -> List[Dict[str, Any]]:
        """
        Execute scan jobs on AWS Lambda.
        
        Args:
            scan_jobs (List[Dict[str, Any]]): List of scan jobs
            concurrency_limit (int): Maximum number of concurrent scans
            
        Returns:
            List[Dict[str, Any]]: List of scan results
        """
        logger.debug(f"Executing {len(scan_jobs)} scan jobs on AWS Lambda")
        
        # Split scan jobs into batches
        batches = []
        for i in range(0, len(scan_jobs), concurrency_limit):
            batches.append(scan_jobs[i:i + concurrency_limit])
        
        # Execute batches
        results = []
        for i, batch in enumerate(batches):
            logger.debug(f"Executing batch {i+1}/{len(batches)} ({len(batch)} jobs)")
            
            # Invoke Lambda functions
            batch_results = []
            for job in batch:
                try:
                    # Invoke Lambda function
                    response = self.lambda_client.invoke(
                        FunctionName=self.function_name,
                        InvocationType="RequestResponse",
                        Payload=json.dumps({"scan_job": job})
                    )
                    
                    # Parse response
                    result = json.loads(response["Payload"].read().decode())
                    batch_results.append(result)
                
                except Exception as e:
                    logger.error(f"Failed to invoke Lambda function: {e}")
                    # Add error result
                    batch_results.append({
                        "ip": job["ip"],
                        "port": job["port"],
                        "is_open": False,
                        "hostnames": job["hostnames"],
                        "timestamp": time.time(),
                        "error": str(e)
                    })
            
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
    
    def cleanup(self) -> bool:
        """
        Clean up AWS resources.
        
        Returns:
            bool: True if cleanup was successful, False otherwise
        """
        logger.debug("Cleaning up AWS resources")
        
        try:
            # Delete Lambda function
            if self.lambda_client and self.function_name:
                self.lambda_client.delete_function(
                    FunctionName=self.function_name
                )
                logger.debug(f"Deleted Lambda function: {self.function_name}")
            
            # Note: We don't delete the S3 bucket or Athena database
            # as they contain the scan results
            
            logger.debug("AWS resources cleaned up successfully")
            return True
        
        except Exception as e:
            logger.error(f"Failed to clean up AWS resources: {e}")
            return False
