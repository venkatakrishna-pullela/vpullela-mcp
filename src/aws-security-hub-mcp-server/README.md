# AWS Security Hub MCP Server

Model Context Protocol (MCP) server for AWS Security Hub

This MCP server provides tools to interact with AWS Security Hub, enabling security findings analysis, standards management, and security posture monitoring through AI assistants. All tools use official AWS Security Hub APIs with complete data access and proper pagination.

## Features

- **Get Security Findings**: Retrieve and filter security findings from Security Hub
- **Get Finding Statistics**: Analyze security findings with aggregated statistics  
- **Get Security Score**: Calculate overall security posture score
- **Get Enabled Standards**: List currently enabled security standards
- **List Security Control Definitions**: Browse available security controls
- **Get Finding History**: Track changes to specific findings over time
- **Describe Standards Controls**: Get detailed control information for standards

## Prerequisites

1. Install `uv` from [Astral](https://docs.astral.sh/uv/getting-started/installation/) or the [GitHub README](https://github.com/astral-sh/uv#installation)
2. Install Python 3.10 or newer using `uv python install 3.10` (or a more recent version)
3. AWS credentials configured (via AWS CLI, environment variables, or IAM roles)
4. AWS Security Hub enabled in your AWS account
5. Appropriate IAM permissions for Security Hub operations

### Required IAM Permissions

**Minimum Required Permissions (Recommended):**
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "securityhub:GetFindings",
                "securityhub:GetFindingHistory",
                "securityhub:DescribeStandards",
                "securityhub:DescribeStandardsControls",
                "securityhub:GetEnabledStandards",
                "securityhub:ListSecurityControlDefinitions"
            ],
            "Resource": [
                "arn:aws:securityhub:*:*:hub/*",
                "arn:aws:securityhub:*:*:finding/*",
                "arn:aws:securityhub:*:*:standard/*"
            ]
        }
    ]
}
```

## Installation

| Cursor | VS Code |
|:------:|:-------:|
| [![Install MCP Server](https://cursor.com/deeplink/mcp-install-light.svg)](https://cursor.com/en/install-mcp?name=awslabs.aws-security-hub-mcp-server&config=eyJjb21tYW5kIjoidXZ4IGF3c2xhYnMuYXdzLXNlY3VyaXR5LWh1Yi1tY3Atc2VydmVyQGxhdGVzdCIsImVudiI6eyJGQVNUTUNQX0xPR19MRVZFTCI6IkVSUk9SIiwiQVdTX1BST0ZJTEUiOiJ5b3VyLWF3cy1wcm9maWxlIiwiQVdTX1JFR0lPTiI6InVzLWVhc3QtMSJ9LCJkaXNhYmxlZCI6ZmFsc2UsImF1dG9BcHByb3ZlIjpbXX0%3D) | [![Install on VS Code](https://img.shields.io/badge/Install_on-VS_Code-FF9900?style=flat-square&logo=visualstudiocode&logoColor=white)](https://insiders.vscode.dev/redirect/mcp/install?name=AWS%20Security%20Hub%20MCP%20Server&config=%7B%22command%22%3A%22uvx%22%2C%22args%22%3A%5B%22awslabs.aws-security-hub-mcp-server%40latest%22%5D%2C%22env%22%3A%7B%22FASTMCP_LOG_LEVEL%22%3A%22ERROR%22%2C%22AWS_PROFILE%22%3A%22your-aws-profile%22%2C%22AWS_REGION%22%3A%22us-east-1%22%7D%2C%22disabled%22%3Afalse%2C%22autoApprove%22%3A%5B%5D%7D) |

Configure the MCP server in your MCP client configuration:

```json
{
  "mcpServers": {
    "aws-security-hub-mcp-server": {
      "command": "uvx",
      "args": ["awslabs.aws-security-hub-mcp-server@latest"],
      "env": {
        "FASTMCP_LOG_LEVEL": "ERROR",
        "AWS_PROFILE": "your-aws-profile",
        "AWS_REGION": "us-east-1"
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

For [Amazon Q Developer CLI](https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/command-line.html), add the MCP client configuration and tool command to the agent file in `~/.aws/amazonq/cli-agents`.

Example, `~/.aws/amazonq/cli-agents/default.json`

```json
{
  "version": "1.0",
  "mcpServers": {
    "aws-security-hub-mcp-server": {
      "command": "uvx",
      "args": ["awslabs.aws-security-hub-mcp-server@latest"],
      "env": {
        "FASTMCP_LOG_LEVEL": "ERROR",
        "AWS_PROFILE": "your-aws-profile",
        "AWS_REGION": "us-east-1"
      }
    }
  }
}
```

## Configuration

### Environment Variables

- `AWS_PROFILE`: AWS profile to use (optional, defaults to default profile)
- `AWS_REGION`: AWS region to use (optional, defaults to us-east-1)
- `FASTMCP_LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `SECURITY_HUB_MAX_RESULTS`: Maximum number of results to return per query (default: 50)

## Tools

### get-security-findings
Retrieves security findings from AWS Security Hub with comprehensive filtering capabilities. You can filter by severity levels (CRITICAL, HIGH, MEDIUM, LOW), compliance status (PASSED, FAILED), workflow status (NEW, NOTIFIED, RESOLVED), resource types, and time ranges. This tool supports pagination to handle large datasets and returns detailed finding information including remediation guidance and affected resources.

**Example:** *"Show me all CRITICAL and HIGH severity findings from the last 7 days that are still NEW"*

### get-finding-statistics  
Provides aggregated statistical analysis of your security findings, helping you understand trends and distributions across your security posture. You can group statistics by severity level, workflow status, product name, resource type, or compliance status. This tool is perfect for generating security dashboards and identifying patterns in your security findings over time.

**Example:** *"Get security finding statistics grouped by severity for the last 30 days to see our security trend"*

### get-security-score
Calculates your overall security score based on the severity distribution of active findings in your environment. The score uses a weighted algorithm that considers the number and severity of findings to provide a single metric (0-100) representing your security posture. This helps track security improvements over time and compare security status across different time periods.

**Example:** *"What's my current security score and how has it changed over the past month?"*

### get-enabled-standards
Lists all security standards currently enabled in your AWS Security Hub configuration, such as AWS Foundational Security Best Practices, CIS AWS Foundations Benchmark, and PCI DSS. For each standard, it shows the enablement status, subscription details, and any configuration issues that might prevent proper compliance checking.

**Example:** *"Show me which security standards are enabled and their current status"*

### list-security-control-definitions
Browses the complete catalog of available security controls in AWS Security Hub, providing detailed information about each control including its purpose, severity rating, remediation guidance, and regional availability. This tool helps you understand what security checks are available and plan your security standard implementations.

**Example:** *"List all available security controls related to S3 and their severity ratings"*

### get-finding-history
Tracks the complete change history for specific security findings, showing how findings have evolved over time. This includes status changes, severity updates, workflow modifications, and compliance status transitions. It's essential for understanding the lifecycle of security issues and demonstrating remediation progress for compliance reporting.

**Example:** *"Show me the complete history of changes for finding arn:aws:securityhub:us-east-1:123456789012:finding/abc123"*

### describe-standards-controls
Provides detailed information about the specific controls within enabled security standards, including their current status (ENABLED/DISABLED), control requirements, related compliance frameworks, and configuration parameters. This tool helps you understand exactly what each standard is checking and manage control configurations.

**Example:** *"Show me all controls in the AWS Foundational Security Best Practices standard and their current status"*

## Development

### Local Development

1. Clone the repository
2. Navigate to the server directory: `cd src/aws-security-hub-mcp-server`
3. Install dependencies: `uv sync --all-groups`
4. Run tests: `uv run pytest`
5. Run the server locally: `uv run awslabs.aws-security-hub-mcp-server`

### Testing

The server includes comprehensive tests:

- **Unit tests**: Mock-based tests for all 7 tools covering success cases, error handling, and edge cases
- **Integration tests**: MCP protocol tests for server functionality

Run tests with:
```bash
# Run all available tests
uv run pytest

# Run with coverage reporting
uv run pytest --cov --cov-branch --cov-report=term-missing

# Run only unit tests (recommended for development)
uv run pytest tests/test_server.py -v
```

## Security Considerations

When using this MCP server, you should consider:

### AWS Shared Responsibility Model
This MCP server operates under the [AWS Shared Responsibility Model](https://aws.amazon.com/compliance/shared-responsibility-model/). AWS is responsible for Security Hub service security, while you are responsible for secure configuration of IAM policies, credential management, and proper use of this server.

### Data Security
- Security findings contain sensitive information about vulnerabilities and security posture
- All data is processed in memory only with no persistent storage
- Data transmission uses HTTPS encryption via AWS SDK
- Implement data classification procedures according to your organization's policy

### Authentication and Access Control
- Use IAM roles with temporary credentials in production environments
- Follow the principle of least privilege with scoped IAM policies
- Implement credential rotation for long-lived access keys
- Monitor credential usage with CloudTrail logging

### IAM Policy Best Practices
- Use resource-specific ARNs instead of wildcards when possible
- Implement condition statements to restrict access by region or time
- Regularly review and audit IAM policies
- Test policies using IAM policy simulator before deployment

### Monitoring and Auditing
- Enable CloudTrail logging for all Security Hub API calls
- Set up CloudWatch monitoring for unusual access patterns
- Implement application logging with appropriate log levels
- Review access logs regularly for security incidents

### Network Security
- Deploy in private subnets when running on AWS infrastructure
- Use VPC endpoints for Security Hub API calls
- Implement security groups restricting inbound access
- Enable VPC Flow Logs for network monitoring

Before using this server in production environments, conduct your own independent assessment to ensure compliance with your organization's security and quality control practices, as well as applicable laws, rules, and regulations.

## Troubleshooting

### Common Issues

1. **AccessDenied errors**: Ensure your AWS credentials have the required Security Hub permissions
2. **Security Hub not enabled**: Enable Security Hub in your AWS account and region  
3. **No findings returned**: Check if Security Hub has findings in the specified region and time range
4. **Rate limiting**: The server implements appropriate rate limiting and pagination for AWS API calls
5. **Finding history not available**: Some findings may not have history records if they haven't been updated

### Debug Mode

Enable debug logging by setting `FASTMCP_LOG_LEVEL=DEBUG` to see detailed API calls and responses.

## Contributing

See the main repository [CONTRIBUTING.md](https://github.com/awslabs/mcp-server-collection/blob/main/CONTRIBUTING.md) for contribution guidelines.

## License

This project is licensed under the Apache License 2.0. See [LICENSE](https://github.com/awslabs/mcp-server-collection/blob/main/LICENSE) for details.
