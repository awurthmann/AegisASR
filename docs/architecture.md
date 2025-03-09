# AegisASR - Architecture

This document provides a detailed overview of the AegisASR (Attack Surface Reconnaissance) architecture, explaining how the different components work together to provide a scalable, multi-cloud port scanning solution for attack surface reconnaissance.

## System Overview

The AegisASR platform is designed with modularity and cloud-agnosticism in mind. It leverages serverless computing across multiple cloud providers to perform distributed TCP port scanning with appropriate rate limiting and security considerations.

```
┌─────────────┐     ┌───────────────┐     ┌───────────────────┐
│ Input Files │────▶│ Input Module  │────▶│ Cloud Module      │
└─────────────┘     └───────────────┘     │                   │
                                          │  ┌─────────────┐  │
                                          │  │ AWS Lambda  │  │
                                          │  └─────────────┘  │
                                          │                   │
                                          │  ┌─────────────┐  │
                                          │  │ Azure Func  │  │
                                          │  └─────────────┘  │
                                          │                   │
                                          │  ┌─────────────┐  │
                                          │  │ GCP Func    │  │
                                          │  └─────────────┘  │
                                          └───────┬───────────┘
                                                  │
                                                  ▼
┌─────────────┐     ┌───────────────┐     ┌───────────────────┐
│ Query       │◀────│ Database      │◀────│ Scan Results      │
│ Interface   │     │ Module        │     │                   │
└─────────────┘     └───────────────┘     └───────────────────┘
```

## Core Components

### 1. Input Module

The Input Module is responsible for importing and validating data from two source types:

- **JSON files**: Structured data in a specified format depicting IP addresses, hostnames, and target TCP ports.
- **DNS zone files**: Standard DNS zone files with automatic extraction of relevant records.

The module performs validation to ensure the input data meets the required format and contains valid IP addresses and port numbers.

### 2. Cloud Modules

The Cloud Modules handle the deployment and execution of scan jobs across different cloud platforms:

- **AWS Module**: Uses AWS Lambda for serverless execution, with S3 and Athena for storage and querying.
- **Azure Module**: Uses Azure Functions for serverless execution, with Data Lake and Synapse SQL for storage and querying.
- **GCP Module**: Uses Google Cloud Functions for serverless execution, with BigQuery for storage and querying.

Each cloud module is responsible for:
- Initializing cloud-specific clients
- Creating necessary cloud resources
- Deploying serverless functions
- Executing scan jobs
- Collecting and processing results

### 3. Scan Modules

The Scan Modules handle the core TCP port scanning functionality:

- **Scanner**: Implements the TCP port scanning logic using socket connections.
- **Rate Limiter**: Controls scan concurrency and timing to prevent network disruption.

The scan modules implement several safety measures:
- Concurrency controls based on target count
- Non-sequential IP scanning (shuffle order)
- Variable timing between requests (randomized intervals)
- Distribution of requests over time

### 4. Database Modules

The Database Modules handle the storage and querying of scan results:

- **AWS Storage**: Uses S3 for storage and Athena for querying.
- **Azure Storage**: Uses Data Lake for storage and Synapse SQL for querying.
- **GCP Storage**: Uses BigQuery for storage and querying.

Each database module provides methods for:
- Creating storage resources
- Storing scan results
- Querying scan results

## Data Flow

1. The user provides input data in the form of a JSON file or DNS zone file.
2. The Input Module validates the input data and converts it to the required format.
3. The user selects one or more cloud platforms to use for scanning.
4. The Cloud Modules prepare scan jobs and distribute them to serverless functions.
5. The Scan Modules execute the scan jobs with appropriate rate limiting.
6. The results are collected and stored in the selected cloud platform's database.
7. The user can query the results using the provided database interfaces.

## Security Considerations

The platform implements several security measures:

- **Defensive Programming**: Input validation, error handling, and type checking.
- **Credential Management**: Secure storage of credentials in .env files excluded from version control.
- **Rate Limiting**: Prevents network disruption and reduces the risk of triggering security alerts.
- **User Confirmation**: Explicit confirmation required before executing scans.
- **Warning Messages**: Clear warnings about legal implications and responsible use.

## Extensibility

The modular design of the platform allows for easy extension:

- **Additional Cloud Providers**: New cloud providers can be added by implementing the required modules.
- **Additional Input Formats**: New input formats can be added by implementing the required parsers.
- **Additional Database Backends**: New database backends can be added by implementing the required storage handlers.
