# AegisASR

# ⚠️ Experimental Project: Use with Caution ⚠️

🚀 **An experimental, modular, open-source attack surface reconnaissance platform** written in Python.  
This project enables users to scan network assets across multiple cloud environments using **serverless computing** and **defensive programming** principles. It performs **distributed port scanning** with built-in **rate limiting and security considerations** to minimize disruption.  

⚠️ **This project is actively evolving and should be used for research, testing, and educational purposes only.** Expect changes, or no changes, improvements, or no improvments, and potential issues as development progresses or doesn't progress.

## Features

- **Multi-Cloud Support**: Deploy across AWS, Azure, GCP, or any combination
- **Distributed Scanning**: Leverage serverless functions for efficient, scalable scanning
- **Rate Limiting**: Intelligent rate limiting to prevent network disruption
- **Security-Focused**: Built with defensive programming practices and security in mind
- **Flexible Input**: Support for JSON files and DNS zone files
- **Cloud Storage**: Store results in cloud-native databases for analysis

## Installation

### Prerequisites

- Python 3.9 or higher
- pip (Python package manager)
- AWS, Azure, or GCP account (at least one)
- Appropriate cloud credentials

### Setup

1. Clone the repository:
   ```
   git clone https://github.com/awurthmann/AegisASR.git
   cd AegisASR
   ```

2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Configure environment variables:
   ```
   cp config/sample.env .env
   ```
   Edit the `.env` file with your cloud credentials and configuration.

## Usage

### Basic Usage

Run the main application with an input file:

```
python main.py --input targets.json --cloud aws
```

### Command Line Options

- `--input`, `-i`: Path to input file (JSON or DNS zone file)
- `--output`, `-o`: Path to output directory for results
- `--cloud`, `-c`: Cloud platform(s) to use for scanning (aws, azure, gcp, or all)
- `--ports`, `-p`: Comma-separated list of TCP ports to scan (for DNS input only)
- `--verbose`, `-v`: Enable verbose logging
- `--dry-run`, `-d`: Perform a dry run without executing scans

### Input File Format

#### JSON Format

```json
{
  "ip_addresses": {
    "192.168.1.1": {
      "hostnames": ["router.local", "gateway.example.com"],
      "tcp_ports": [80, 443]
    },
    "10.0.0.1": {
      "hostnames": ["firewall.example.com"],
      "tcp_ports": [22, 8080, 8443]
    }
  }
}
```

#### DNS Zone Files

The platform can also import DNS zone files and automatically extract relevant records (A, AAAA, CNAME, PTR, MX, SRV).

## Configuration

### Environment Variables

See `config/sample.env` for a complete list of configuration options.

### Cloud Credentials

#### AWS

Required environment variables:
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_REGION`

#### Azure

Required environment variables:
- `AZURE_TENANT_ID`
- `AZURE_CLIENT_ID`
- `AZURE_CLIENT_SECRET`
- `AZURE_SUBSCRIPTION_ID`

#### GCP

Required environment variables:
- `GCP_PROJECT_ID`
- `GCP_CREDENTIALS_FILE` (path to service account JSON file)

## Architecture

### System Components

1. **Input Module**: Imports and validates data from JSON files or DNS zone files
2. **Cloud Modules**: Handles deployment and execution on AWS, Azure, and GCP
3. **Database Modules**: Stores results in cloud-specific databases
4. **Scan Modules**: Performs TCP port scanning with appropriate rate limiting

### Cloud-Specific Implementation

- **AWS**: Lambda + S3 + Athena
- **Azure**: Functions + Data Lake + Synapse SQL
- **GCP**: Functions + BigQuery

## Security and Legal Considerations

### Important Warning

This tool is designed for security professionals to scan systems they own or have explicit permission to test. Unauthorized scanning may be illegal and trigger security alerts.

### Responsible Use

- Only scan systems you own or have permission to test
- Respect rate limits to avoid disruptions
- Be aware of cloud provider terms of service

## License

This project is licensed under the Creative Commons BY-NC 4.0 (Non-Commercial License) - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
