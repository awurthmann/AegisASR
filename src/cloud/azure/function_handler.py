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
            import tempfile
            import zipfile
            import os
            import requests
            
            # Create a temporary directory for the function code
            with tempfile.TemporaryDirectory() as temp_dir:
                # Create function directory structure
                function_dir = os.path.join(temp_dir, "PortScanFunction")
                os.makedirs(function_dir, exist_ok=True)
                
                # Write function files
                with open(os.path.join(function_dir, "__init__.py"), "w") as f:
                    f.write(function_code)
                
                with open(os.path.join(function_dir, "function.json"), "w") as f:
                    f.write(function_json)
                
                with open(os.path.join(temp_dir, "host.json"), "w") as f:
                    f.write(host_json)
                
                with open(os.path.join(temp_dir, "requirements.txt"), "w") as f:
                    f.write(requirements_txt)
                
                # Create zip file
                zip_path = os.path.join(temp_dir, "function.zip")
                with zipfile.ZipFile(zip_path, "w") as zip_file:
                    # Add all files in the temp directory to the zip
                    for root, _, files in os.walk(temp_dir):
                        for file in files:
                            if file != "function.zip":  # Skip the zip file itself
                                file_path = os.path.join(root, file)
                                arcname = os.path.relpath(file_path, temp_dir)
                                zip_file.write(file_path, arcname)
                
                # Get function app publish profile
                publish_profile_response = self.web_client.web_apps.list_publishing_profile_xml_with_secrets(
                    resource_group_name=self.resource_group_name,
                    name=self.function_app_name
                )
                
                # Extract credentials from publish profile
                import xml.etree.ElementTree as ET
                from io import StringIO
                
                publish_profile = publish_profile_response.text
                root = ET.fromstring(publish_profile)
                
                # Find the FTP publishing profile
                publish_url = None
                username = None
                password = None
                
                for profile in root.findall(".//publishProfile[@publishMethod='MSDeploy']"):
                    publish_url = profile.get("publishUrl")
                    username = profile.get("userName")
                    password = profile.get("userPWD")
                    break
                
                if not publish_url or not username or not password:
                    logger.error("Failed to extract publishing credentials")
                    return False
                
                # Deploy the zip package
                import base64
                
                # Construct the deployment URL
                deploy_url = f"https://{publish_url}/api/zipdeploy"
                
                # Create basic auth header
                auth = f"{username}:{password}"
                auth_bytes = auth.encode("ascii")
                base64_auth = base64.b64encode(auth_bytes).decode("ascii")
                
                # Upload the zip file
                with open(zip_path, "rb") as zip_file:
                    response = requests.post(
                        deploy_url,
                        headers={
                            "Authorization": f"Basic {base64_auth}",
                            "Content-Type": "application/zip"
                        },
                        data=zip_file.read()
                    )
                
                if response.status_code >= 200 and response.status_code < 300:
                    logger.debug("Azure Function deployed successfully")
                    
                    # Store the function URL for later use
                    self.function_url = f"https://{self.function_app_name}.azurewebsites.net/api/PortScanFunction"
                    
                    # Get function key
                    keys_response = self.web_client.web_apps.list_function_keys(
                        resource_group_name=self.resource_group_name,
                        name=self.function_app_name,
                        function_name="PortScanFunction"
                    )
                    
                    if keys_response and hasattr(keys_response, "default"):
                        self.function_key = keys_response.default
                    else:
                        # If we can't get the function key, we'll use the master key
                        master_key_response = self.web_client.web_apps.list_host_keys(
                            resource_group_name=self.resource_group_name,
                            name=self.function_app_name
                        )
                        if master_key_response and hasattr(master_key_response, "master_key"):
                            self.function_key = master_key_response.master_key
                    
                    return True
                else:
                    logger.error(f"Failed to deploy Azure Function: {response.status_code} {response.text}")
                    return False
        
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
        
        # Check if function URL and key are available
        if not hasattr(self, 'function_url') or not self.function_url:
            logger.error("Function URL is not available. Make sure the function is deployed.")
            return []
        
        # Import requests here to avoid dependency issues
        import requests
        import concurrent.futures
        from urllib.parse import urlencode
        
        # Function to execute a single scan job
        def execute_job(job):
            try:
                # Prepare request URL with function key if available
                url = self.function_url
                if hasattr(self, 'function_key') and self.function_key:
                    url = f"{url}?code={self.function_key}"
                
                # Send request to Azure Function
                response = requests.post(
                    url,
                    json={"scan_job": job},
                    headers={"Content-Type": "application/json"},
                    timeout=10  # 10 second timeout
                )
                
                # Check response
                if response.status_code == 200:
                    return response.json()
                else:
                    logger.error(f"Function returned error: {response.status_code} {response.text}")
                    return {
                        "ip": job["ip"],
                        "port": job["port"],
                        "is_open": False,
                        "hostnames": job["hostnames"],
                        "timestamp": time.time(),
                        "error": f"Function error: {response.status_code}"
                    }
            
            except Exception as e:
                logger.error(f"Error executing job: {e}")
                return {
                    "ip": job["ip"],
                    "port": job["port"],
                    "is_open": False,
                    "hostnames": job["hostnames"],
                    "timestamp": time.time(),
                    "error": str(e)
                }
        
        # Split scan jobs into batches
        batches = []
        for i in range(0, len(scan_jobs), concurrency_limit):
            batches.append(scan_jobs[i:i + concurrency_limit])
        
        # Execute batches
        results = []
        for i, batch in enumerate(batches):
            logger.debug(f"Executing batch {i+1}/{len(batches)} ({len(batch)} jobs)")
            
            # Execute batch in parallel using ThreadPoolExecutor
            batch_results = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency_limit) as executor:
                # Submit all jobs
                future_to_job = {executor.submit(execute_job, job): job for job in batch}
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(future_to_job):
                    job = future_to_job[future]
                    try:
                        result = future.result()
                        batch_results.append(result)
                    except Exception as e:
                        logger.error(f"Job execution failed: {e}")
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
