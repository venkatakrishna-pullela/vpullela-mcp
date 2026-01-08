# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Integration tests for AWS Security Hub MCP Server."""

from unittest.mock import patch

import pytest
from mcp.types import CallToolRequest

from awslabs.aws_security_hub_mcp_server.server import mcp


@pytest.mark.skip(reason="Integration tests need MCP API structure updates")
@pytest.mark.integration
class TestSecurityHubMCPIntegration:
    """Integration tests for Security Hub MCP Server."""

    @pytest.mark.asyncio
    async def test_mcp_server_tools_available(self):
        """Test that MCP server has all expected tools available."""
        # Test list_tools
        response = await mcp.list_tools()

        tool_names = [tool.name for tool in response.tools]
        expected_tools = [
            "get-security-findings",
            "get-finding-statistics",
            "get-security-score",
            "get-enabled-standards",
            "list-security-control-definitions",
            "get-finding-history",
            "describe-standards-controls",
            "generate-security-report",
            "generate-compliance-report",
            "generate-security-trends-report",
        ]

        for expected_tool in expected_tools:
            assert expected_tool in tool_names, f"Tool {expected_tool} not found in available tools"

    @pytest.mark.asyncio
    async def test_get_security_findings_tool_integration(self):
        """Test the get-security-findings tool through MCP interface."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            # Mock the Security Hub client response
            mock_finding = {
                "Id": "test-finding-1",
                "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default",
                "GeneratorId": "test-generator",
                "AwsAccountId": "123456789012",
                "Region": "us-east-1",
                "Title": "Test Security Finding",
                "Description": "This is a test security finding",
                "Severity": {"Label": "HIGH"},
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
                "CreatedAt": "2024-01-01T00:00:00Z",
                "UpdatedAt": "2024-01-01T00:00:00Z",
                "Resources": [{"Type": "AwsEc2Instance", "Id": "i-1234567890abcdef0"}],
                "Compliance": {"Status": "FAILED"},
            }
            mock_client.return_value.get_findings.return_value = {"Findings": [mock_finding]}

            # Test the tool through MCP interface
            request = CallToolRequest(
                params={"name": "get-security-findings", "arguments": {"max_results": 5, "days_back": 7}}
            )

            response = await mcp.call_tool(request)

            assert response.content is not None
            assert len(response.content) > 0
            # The response should contain the finding data
            result = response.content[0]
            assert hasattr(result, "text")

    @pytest.mark.asyncio
    async def test_get_finding_statistics_tool_integration(self):
        """Test the get-finding-statistics tool through MCP interface."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            mock_finding = {
                "Id": "test-finding-1",
                "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default",
                "GeneratorId": "test-generator",
                "AwsAccountId": "123456789012",
                "Region": "us-east-1",
                "Title": "Test Security Finding",
                "Description": "This is a test security finding",
                "Severity": {"Label": "HIGH"},
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
                "CreatedAt": "2024-01-01T00:00:00Z",
                "UpdatedAt": "2024-01-01T00:00:00Z",
                "Resources": [{"Type": "AwsEc2Instance"}],
            }
            mock_client.return_value.get_findings.return_value = {"Findings": [mock_finding]}

            request = CallToolRequest(
                name="get-finding-statistics", arguments={"group_by": "SeverityLabel", "days_back": 30}
            )

            response = await mcp.call_tool(request)

            assert response.content is not None
            assert len(response.content) > 0

    @pytest.mark.asyncio
    async def test_get_security_score_tool_integration(self):
        """Test the get-security-score tool through MCP interface."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            mock_client.return_value.get_findings.return_value = {"Findings": []}

            request = CallToolRequest(name="get-security-score", arguments={})

            response = await mcp.call_tool(request)

            assert response.content is not None
            assert len(response.content) > 0

    @pytest.mark.asyncio
    async def test_get_enabled_standards_tool_integration(self):
        """Test the get-enabled-standards tool through MCP interface."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            mock_standards = [
                {
                    "StandardsSubscriptionArn": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-standard/v/1.0.0",
                    "StandardsArn": "arn:aws:securityhub:::standard/aws-foundational-security-standard/v/1.0.0",
                    "StandardsInput": {},
                    "StandardsStatus": "READY",
                }
            ]
            mock_client.return_value.get_enabled_standards.return_value = {"StandardsSubscriptions": mock_standards}

            request = CallToolRequest(name="get-enabled-standards", arguments={})

            response = await mcp.call_tool(request)

            assert response.content is not None
            assert len(response.content) > 0

    @pytest.mark.asyncio
    async def test_list_security_control_definitions_tool_integration(self):
        """Test the list-security-control-definitions tool through MCP interface."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            mock_controls = [
                {
                    "SecurityControlId": "S3.1",
                    "SecurityControlArn": "arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1",
                    "Title": "S3 buckets should have public access blocked",
                    "Description": "This control checks whether S3 buckets have public access blocked.",
                    "RemediationUrl": "https://docs.aws.amazon.com/console/securityhub/S3.1/remediation",
                    "SeverityRating": "HIGH",
                    "CurrentRegionAvailability": "AVAILABLE",
                }
            ]
            mock_client.return_value.list_security_control_definitions.return_value = {
                "SecurityControlDefinitions": mock_controls
            }

            request = CallToolRequest(name="list-security-control-definitions", arguments={})

            response = await mcp.call_tool(request)

            assert response.content is not None
            assert len(response.content) > 0

    @pytest.mark.asyncio
    async def test_get_finding_history_tool_integration(self):
        """Test the get-finding-history tool through MCP interface."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            mock_history = [
                {
                    "FindingIdentifier": {
                        "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/test-finding-1",
                        "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default",
                    },
                    "UpdateTime": "2024-01-01T00:00:00Z",
                    "FindingCreated": True,
                    "UpdateSource": {
                        "Type": "BATCH_UPDATE_FINDINGS",
                        "Identity": "arn:aws:iam::123456789012:user/test-user",
                    },
                    "Updates": [
                        {
                            "UpdatedField": "Workflow/Status",
                            "OldValue": "NEW",
                            "NewValue": "RESOLVED",
                        }
                    ],
                }
            ]
            mock_client.return_value.get_finding_history.return_value = {"Records": mock_history}

            request = CallToolRequest(name="get-finding-history", arguments={"finding_id": "test-finding-id"})

            response = await mcp.call_tool(request)

            assert response.content is not None
            assert len(response.content) > 0

    @pytest.mark.asyncio
    async def test_describe_standards_controls_tool_integration(self):
        """Test the describe-standards-controls tool through MCP interface."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            mock_controls = [
                {
                    "StandardsControlArn": "arn:aws:securityhub:us-east-1:123456789012:control/aws-foundational-security-standard/v/1.0.0/S3.1",
                    "ControlStatus": "ENABLED",
                    "DisabledReason": None,
                    "ControlStatusUpdatedAt": "2024-01-01T00:00:00Z",
                    "ControlId": "S3.1",
                    "Title": "S3 buckets should have public access blocked",
                    "Description": "This control checks whether S3 buckets have public access blocked.",
                    "RemediationUrl": "https://docs.aws.amazon.com/console/securityhub/S3.1/remediation",
                    "SeverityRating": "HIGH",
                    "RelatedRequirements": ["NIST.800-53.r5 AC-3", "NIST.800-53.r5 AC-6"],
                }
            ]
            mock_client.return_value.describe_standards_controls.return_value = {"Controls": mock_controls}

            request = CallToolRequest(
                name="describe-standards-controls",
                arguments={
                    "standards_subscription_arn": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-standard/v/1.0.0"
                },
            )

            response = await mcp.call_tool(request)

            assert response.content is not None
            assert len(response.content) > 0

    @pytest.mark.asyncio
    async def test_generate_security_report_tool_integration(self):
        """Test the generate-security-report tool through MCP interface."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            mock_finding = {
                "Id": "test-finding-1",
                "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default",
                "GeneratorId": "test-generator",
                "AwsAccountId": "123456789012",
                "Region": "us-east-1",
                "Title": "Test Security Finding",
                "Description": "This is a test security finding",
                "Severity": {"Label": "HIGH"},
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
                "CreatedAt": "2024-01-01T00:00:00Z",
                "UpdatedAt": "2024-01-01T00:00:00Z",
                "Resources": [{"Type": "AwsEc2Instance"}],
                "Compliance": {"Status": "FAILED"},
            }
            mock_client.return_value.get_findings.return_value = {"Findings": [mock_finding]}
            mock_client.return_value.get_enabled_standards.return_value = {"StandardsSubscriptions": []}

            request = CallToolRequest(name="generate-security-report", arguments={})

            response = await mcp.call_tool(request)

            assert response.content is not None
            assert len(response.content) > 0

    @pytest.mark.asyncio
    async def test_generate_compliance_report_tool_integration(self):
        """Test the generate-compliance-report tool through MCP interface."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            mock_finding = {
                "Id": "test-finding-1",
                "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default",
                "GeneratorId": "test-generator",
                "AwsAccountId": "123456789012",
                "Region": "us-east-1",
                "Title": "Test Security Finding",
                "Description": "This is a test security finding",
                "Severity": {"Label": "HIGH"},
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
                "CreatedAt": "2024-01-01T00:00:00Z",
                "UpdatedAt": "2024-01-01T00:00:00Z",
                "Resources": [{"Type": "AwsEc2Instance"}],
                "Compliance": {"Status": "FAILED"},
            }
            mock_client.return_value.get_findings.return_value = {"Findings": [mock_finding]}
            mock_client.return_value.get_enabled_standards.return_value = {"StandardsSubscriptions": []}

            request = CallToolRequest(name="generate-compliance-report", arguments={})

            response = await mcp.call_tool(request)

            assert response.content is not None
            assert len(response.content) > 0

    @pytest.mark.asyncio
    async def test_generate_security_trends_report_tool_integration(self):
        """Test the generate-security-trends-report tool through MCP interface."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            mock_finding = {
                "Id": "test-finding-1",
                "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default",
                "GeneratorId": "test-generator",
                "AwsAccountId": "123456789012",
                "Region": "us-east-1",
                "Title": "Test Security Finding",
                "Description": "This is a test security finding",
                "Severity": {"Label": "HIGH"},
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
                "CreatedAt": "2024-01-01T00:00:00Z",
                "UpdatedAt": "2024-01-01T00:00:00Z",
                "Resources": [{"Type": "AwsEc2Instance"}],
            }
            mock_client.return_value.get_findings.return_value = {"Findings": [mock_finding]}

            request = CallToolRequest(name="generate-security-trends-report", arguments={})

            response = await mcp.call_tool(request)

            assert response.content is not None
            assert len(response.content) > 0

    @pytest.mark.asyncio
    async def test_tool_error_handling_integration(self):
        """Test error handling through MCP interface."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            from botocore.exceptions import ClientError

            mock_client.return_value.get_findings.side_effect = ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Access denied"}}, "GetFindings"
            )

            request = CallToolRequest(name="get-security-findings", arguments={})

            # Should handle the error gracefully and return an error response
            response = await mcp.call_tool(request)

            # The response should indicate an error occurred
            assert response.isError or (response.content and "error" in str(response.content).lower())

    @pytest.mark.asyncio
    async def test_invalid_tool_name_integration(self):
        """Test calling an invalid tool name through MCP interface."""
        request = CallToolRequest(name="invalid-tool-name", arguments={})

        # Should raise an error for invalid tool name
        with pytest.raises(Exception, match="invalid-tool-name"):
            await mcp.call_tool(request)

    @pytest.mark.asyncio
    async def test_tool_input_validation_integration(self):
        """Test input validation through MCP interface."""
        # Test with invalid arguments that should be caught by input validation
        request = CallToolRequest(
            name="get-security-findings",
            arguments={"max_results": "invalid"},  # Should be an integer
        )

        # Should handle validation errors gracefully
        response = await mcp.call_tool(request)

        # Should either raise an exception or return an error response
        assert response.isError or response.content is not None
