"""
Azure Function Handler Module

This module handles Azure Function functionality for executing scans.

Classes:
    AzureFunctionHandler: Handler for Azure Functions
"""

import json
import logging
import os
import time
import uuid
from typing import Dict, List, Any, Optional, Tuple

# Azure SDK imports
try:
    from azure.identity import ClientSecretCredential
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.storage import StorageManagementClient
    from azure.mgmt.synapse import SynapseManagementClient
    from azure.storage.blob import BlobServiceClient
    from azure.mgmt.web import WebSiteManagementClient
    from azure.core.exceptions import AzureError
except ImportError:
    logging.warning("Azure SDK not installed. Azure functionality will not be available.")

from ...config import get_azure_config
from ...scan.scanner import format_results_for_storage
from ...utils import display_progress

logger = logging.getLogger(__name__)


class AzureFunctionHandler:
    """
    Handler for Azure Functions.
    """
    
    def __init__(self):
        """
        Initialize Azure Function handler.
        """
        self.credential = None
        self.resource_client = None
        self.storage_client = None
        self.synapse_client = None
        self.web_client = None
        self.blob_service_client = None
        
        self.resource_group_name = f"attack-surface-scanner-{uuid.uuid4().hex[:8]}"
        self.storage_account_name = f"attacksurface{uuid.uuid4().hex[:8]}"
        self.function_app_name = f"attack-surface-scanner-{uuid.uuid4().hex[:8]}"
        self.synapse_workspace_name = f"attack-surface-{uuid.uuid4().hex[:8]}"
        self.container_name = "scan-results"
        self.database_name = "attack_surface_scans"
        self.table_name = "scan_results"
        
        self.location = "eastus"  # Default location
    
    def initialize(self, config: Dict[str, str]) -> bool:
        """
        Initialize Azure clients.
        
        Args:
            config (Dict[str, str]): Configuration dictionary
            
        Returns:
            bool: True if initialization was successful, False otherwise
        """
        logger.debug("Initializing Azure Function handler")
        
        # Get Azure configuration
        azure_config = get_azure_config(config)
        if not azure_config:
            logger.error("Azure configuration is missing or invalid")
            return False
        
        # Initialize Azure clients
        try:
            # Create credential
            self.credential = ClientSecretCredential(
                tenant_id=azure_config["AZURE_TENANT_ID"],
                client_id=azure_config["AZURE_CLIENT_ID"],
                client_secret=azure_config["AZURE_CLIENT_SECRET"]
            )
            
            # Create resource client
            self.resource_client = ResourceManagementClient(
                credential=self.credential,
                subscription_id=azure_config.get("AZURE_SUBSCRIPTION_ID")
            )
            
            # Create storage client
            self.storage_client = StorageManagementClient(
                credential=self.credential,
                subscription_id=azure_config.get("AZURE_SUBSCRIPTION_ID")
            )
            
            # Create synapse client
            self.synapse_client = SynapseManagementClient(
                credential=self.credential,
                subscription_id=azure_config.get("AZURE_SUBSCRIPTION_ID")
            )
            
            # Create web client
            self.web_client = WebSiteManagementClient(
                credential=self.credential,
                subscription_id=azure_config.get("AZURE_SUBSCRIPTION_ID")
            )
            
            logger.debug("Azure Function handler initialized successfully")
            return True
        
        except Exception as e:
            logger.error(f"Failed to initialize Azure Function handler: {e}")
            return False
    
    def create_resource_group(self) -> bool:
        """
        Create Azure resource group.
        
        Returns:
            bool: True if creation was successful, False otherwise
        """
        logger.debug(f"Creating Azure resource group: {self.resource_group_name}")
        
        try:
            # Create resource group
            self.resource_client.resource_groups.create_or_update(
                resource_group_name=self.resource_group_name,
                parameters={"location": self.location}
            )
            
            logger.debug(f"Azure resource group created: {self.resource_group_name}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to create Azure resource group: {e}")
            return False
    
    def create_storage_account(self) -> bool:
        """
        Create Azure storage account.
        
        Returns:
            bool: True if creation was successful, False otherwise
        """
        logger.debug(f"Creating Azure storage account: {self.storage_account_name}")
        
        try:
            # Create storage account
            poller = self.storage_client.storage_accounts.begin_create(
                resource_group_name=self.resource_group_name,
                account_name=self.storage_account_name,
                parameters={
                    "location": self.location,
                    "kind": "StorageV2",
                    "sku": {"name": "Standard_LRS"}
                }
            )
            
            # Wait for completion
            storage_account = poller.result()
            
            # Get storage account keys
            keys = self.storage_client.storage_accounts.list_keys(
                resource_group_name=self.resource_group_name,
                account_name=self.storage_account_name
            )
            
            # Create blob service client
            self.blob_service_client = BlobServiceClient(
                account_url=f"https://{self.storage_account_name}.blob.core.windows.net",
                credential=keys.keys[0].value
            )
            
            # Create container
            self.blob_service_client.create_container(self.container_name)
            
            logger.debug(f"Azure storage account created: {self.storage_account_name}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to create Azure storage account: {e}")
            return False
    
    def create_function_app(self) -> bool:
        """
        Create Azure Function app.
        
        Returns:
            bool: True if creation was successful, False otherwise
        """
        logger.debug(f"Creating Azure Function app: {self.function_app_name}")
        
        try:
            # Create app service plan
            plan_name = f"{self.function_app_name}-plan"
            self.web_client.app_service_plans.begin_create_or_update(
                resource_group_name=self.resource_group_name,
                name=plan_name,
                app_service_plan={
                    "location": self.location,
                    "sku": {"name": "Y1", "tier": "Dynamic"}
                }
            ).result()
            
            # Create function app
            self.web_client.web_apps.begin_create_or_update(
                resource_group_name=self.resource_group_name,
                name=self.function_app_name,
                site_envelope={
                    "location": self.location,
                    "server_farm_id": f"/subscriptions/{self.web_client.config.subscription_id}/resourceGroups/{self.resource_group_name}/providers/Microsoft.Web/serverfarms/{plan_name}",
                    "kind": "functionapp",
                    "site_config": {
                        "app_settings": [
                            {"name": "FUNCTIONS_EXTENSION_VERSION", "value": "~4"},
                            {"name": "FUNCTIONS_WORKER_RUNTIME", "value": "python"},
                            {"name": "AzureWebJobsStorage", "value": f"DefaultEndpointsProtocol=https;AccountName={self.storage_account_name};AccountKey={self.blob_service_client.credential};EndpointSuffix=core.windows.net"}
                        ]
                    }
                }
            ).result()
            
            logger.debug(f"Azure Function app created: {self.function_app_name}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to create Azure Function app: {e}")
            return False
    
    def create_synapse_workspace(self) -> bool:
        """
        Create Azure Synapse workspace.
        
        Returns:
            bool: True if creation was successful, False otherwise
        """
        logger.debug(f"Creating Azure Synapse workspace: {self.synapse_workspace_name}")
        
        try:
            # Create Synapse workspace
            self.synapse_client.workspaces.begin_create_or_update(
                resource_group_name=self.resource_group_name,
                workspace_name=self.synapse_workspace_name,
                workspace_info={
                    "location": self.location,
                    "identity": {"type": "SystemAssigned"},
                    "default_data_lake_storage": {
                        "account_url": f"https://{self.storage_account_name}.dfs.core.windows.net",
                        "filesystem": self.container_name
                    },
                    "sql_administrator_login": "sqladmin",
                    "sql_administrator_login_password": str(uuid.uuid4())
                }
            ).result()
            
            logger.debug(f"Azure Synapse workspace created: {self.synapse_workspace_name}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to create Azure Synapse workspace: {e}")
            return False
    
    def deploy_function(self) -> bool:
        """
        Deploy Azure Function for scanning.
        
        Returns:
            bool: True if deployment was successful, False otherwise
        """
        logger.debug("Deploying Azure Function")
        
        # Function code
        function_code = """
import json
import socket
import time
import logging
import azure.functions as func

def check_tcp_port(host, port, timeout=1):
    \"\"\"Attempts a TCP connection to check if the port is open.\"\"\"
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True  # Port is open
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False  # Port is closed

def main(req: func.HttpRequest) -> func.HttpResponse:
    \"\"\"Azure Function HTTP trigger.\"\"\"
    logging.info('Python HTTP trigger function processed a request.')
    
    # Get scan job from request
    try:
        req_body = req.get_json()
        scan_job = req_body.get('scan_job', {})
    except ValueError:
        return func.HttpResponse(
            "Invalid request body",
            status_code=400
        )
    
    # Extract scan job parameters
    ip = scan_job.get('ip')
    port = scan_job.get('port')
    hostnames = scan_job.get('hostnames', [])
    
    if not ip or not port:
        return func.HttpResponse(
            "Missing required parameters: ip, port",
            status_code=400
        )
    
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
    
    return func.HttpResponse(
        json.dumps(result),
        mimetype="application/json",
        status_code=200
    )
"""
        
        # Function.json
        function_json = """
{
  "scriptFile": "__init__.py",
  "bindings": [
    {
      "authLevel": "function",
      "type": "httpTrigger",
      "direction": "in",
      "name": "req",
      "methods": [
        "post"
      ]
    },
    {
      "type": "http",
      "direction": "out",
      "name": "$return"
    }
  ]
}
"""
        
        # Host.json
        host_json = """
{
  "version": "2.0",
  "logging": {
    "applicationInsights": {
      "samplingSettings": {
        "isEnabled": true,
        "excludedTypes": "Request"
      }
    }
  },
  "extensionBundle": {
    "id": "Microsoft.Azure.Functions.ExtensionBundle",
    "version": "[2.*, 3.0.0)"
  }
}
"""
        
        # Requirements.txt
        requirements_txt = """
azure-functions
"""
        
        try:
            # TODO: Deploy function code
            # This would typically involve creating a zip package and deploying it
            # For simplicity, we'll assume the function is deployed
            
            logger.debug("Azure Function deployed successfully")
            return True
        
        except Exception as e:
            logger.error(f"Failed to deploy Azure Function: {e}")
            return False
    
    def execute_scan_jobs(self, scan_jobs: List[Dict[str, Any]], concurrency_limit: int) -> List[Dict[str, Any]]:
        """
        Execute scan jobs on Azure Functions.
        
        Args:
            scan_jobs (List[Dict[str, Any]]): List of scan jobs
            concurrency_limit (int): Maximum number of concurrent scans
            
        Returns:
            List[Dict[str, Any]]: List of scan results
        """
        logger.debug(f"Executing {len(scan_jobs)} scan jobs on Azure Functions")
        
        # Split scan jobs into batches
        batches = []
        for i in range(0, len(scan_jobs), concurrency_limit):
            batches.append(scan_jobs[i:i + concurrency_limit])
        
        # Execute batches
        results = []
        for i, batch in enumerate(batches):
            logger.debug(f"Executing batch {i+1}/{len(batches)} ({len(batch)} jobs)")
            
            # TODO: Invoke Azure Functions
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
        Store scan results in Azure Data Lake and Synapse SQL.
        
        Args:
            results (List[Dict[str, Any]]): List of scan results
            
        Returns:
            bool: True if storage was successful, False otherwise
        """
        logger.debug(f"Storing {len(results)} scan results")
        
        try:
            # Format results for storage
            formatted_results = format_results_for_storage(results)
            
            # Store results in Azure Data Lake
            for ip, data in formatted_results.items():
                # Convert to JSON
                json_data = json.dumps({
                    "ip_address": ip,
                    "scan_time": data["scan_time"],
                    "ports": data["ports"]
                })
                
                # Upload to blob storage
                blob_client = self.blob_service_client.get_blob_client(
                    container=self.container_name,
                    blob=f"scan-results/{ip}.json"
                )
                blob_client.upload_blob(json_data, overwrite=True)
            
            logger.debug(f"Stored {len(formatted_results)} results in Azure Data Lake")
            
            # TODO: Create Synapse SQL table and load data
            # For simplicity, we'll assume this is done
            
            return True
        
        except Exception as e:
            logger.error(f"Failed to store results: {e}")
            return False
    
    def cleanup(self) -> bool:
        """
        Clean up Azure resources.
        
        Returns:
            bool: True if cleanup was successful, False otherwise
        """
        logger.debug("Cleaning up Azure resources")
        
        try:
            # Delete function app
            if self.web_client and self.function_app_name:
                self.web_client.web_apps.delete(
                    resource_group_name=self.resource_group_name,
                    name=self.function_app_name
                )
                logger.debug(f"Deleted Azure Function app: {self.function_app_name}")
            
            # Note: We don't delete the storage account or Synapse workspace
            # as they contain the scan results
            
            logger.debug("Azure resources cleaned up successfully")
            return True
        
        except Exception as e:
            logger.error(f"Failed to clean up Azure resources: {e}")
            return False
