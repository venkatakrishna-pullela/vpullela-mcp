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
"""Tests for AWS Security Hub MCP Server."""

from unittest.mock import patch

import pytest

from awslabs.aws_security_hub_mcp_server.models import (
    ComplianceStatus,
    SeverityLabel,
    WorkflowStatus,
)
from awslabs.aws_security_hub_mcp_server.server import (
    get_finding_statistics,
    get_security_findings,
    get_security_score,
    parse_finding,
)


class TestSecurityHubServer:
    """Test cases for Security Hub MCP Server."""

    @pytest.mark.asyncio
    async def test_get_security_findings_success(self, mock_context, sample_finding):
        """Test successful retrieval of security findings."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            mock_client.return_value.get_findings.return_value = {"Findings": [sample_finding]}

            findings = await get_security_findings(mock_context, severity_labels=[SeverityLabel.HIGH], max_results=10)

            assert len(findings) == 1
            assert findings[0].severity_label == SeverityLabel.HIGH
            assert findings[0].title == "Test Security Finding"

    @pytest.mark.asyncio
    async def test_get_security_findings_with_filters(self, mock_context, sample_finding):
        """Test security findings retrieval with multiple filters."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            mock_client.return_value.get_findings.return_value = {"Findings": [sample_finding]}

            findings = await get_security_findings(
                mock_context,
                severity_labels=[SeverityLabel.HIGH, SeverityLabel.CRITICAL],
                workflow_status=[WorkflowStatus.NEW],
                compliance_status=[ComplianceStatus.FAILED],
                resource_type="AwsEc2Instance",
                days_back=30,
            )

            assert len(findings) == 1
            mock_client.return_value.get_findings.assert_called_once()

            # Verify filters were applied
            call_args = mock_client.return_value.get_findings.call_args
            filters = call_args[1]["Filters"]
            assert "SeverityLabel" in filters
            assert "WorkflowStatus" in filters
            assert "ComplianceStatus" in filters
            assert "ResourceType" in filters
            assert "UpdatedAt" in filters

    @pytest.mark.asyncio
    async def test_get_finding_statistics_success(self, mock_context, sample_finding):
        """Test successful retrieval of finding statistics."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            # Create multiple findings with different severities
            findings = [
                {**sample_finding, "Severity": {"Label": "HIGH"}},
                {**sample_finding, "Severity": {"Label": "HIGH"}},
                {**sample_finding, "Severity": {"Label": "MEDIUM"}},
            ]

            mock_client.return_value.get_findings.return_value = {"Findings": findings}

            stats = await get_finding_statistics(mock_context, group_by="SeverityLabel", days_back=30)

            assert len(stats) == 2  # HIGH and MEDIUM
            # Should be sorted by count descending
            assert stats[0].group_key == "HIGH"
            assert stats[0].count == 2
            assert stats[0].percentage == 66.67
            assert stats[1].group_key == "MEDIUM"
            assert stats[1].count == 1
            assert stats[1].percentage == 33.33

    @pytest.mark.asyncio
    async def test_get_security_score_success(self, mock_context, sample_finding):
        """Test successful calculation of security score."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            # Create findings with different severities
            findings = [
                {**sample_finding, "Severity": {"Label": "CRITICAL"}},
                {**sample_finding, "Severity": {"Label": "HIGH"}},
                {**sample_finding, "Severity": {"Label": "LOW"}},
            ]

            mock_client.return_value.get_findings.return_value = {"Findings": findings}

            score = await get_security_score(mock_context)

            assert score.max_score == 100.0
            assert 0 <= score.current_score <= 100
            assert score.security_score_percentage == score.current_score
            assert isinstance(score.score_date, str)  # Changed from datetime to str

    def test_parse_finding_success(self, sample_finding):
        """Test successful parsing of finding data."""
        finding = parse_finding(sample_finding)

        assert finding.id == sample_finding["Id"]
        assert finding.title == sample_finding["Title"]
        assert finding.severity_label == SeverityLabel.HIGH
        assert finding.workflow_status == WorkflowStatus.NEW
        assert finding.compliance_status == ComplianceStatus.FAILED
        assert finding.resource_type == "AwsEc2Instance"

    @pytest.mark.asyncio
    async def test_get_security_findings_client_error(self, mock_context):
        """Test handling of AWS client errors."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            from botocore.exceptions import ClientError

            mock_client.return_value.get_findings.side_effect = ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Access denied"}}, "GetFindings"
            )

            with pytest.raises(Exception) as exc_info:
                await get_security_findings(mock_context)

            assert "Security Hub API error" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_get_security_findings_empty_response(self, mock_context):
        """Test handling of empty findings response."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            mock_client.return_value.get_findings.return_value = {"Findings": []}

            findings = await get_security_findings(mock_context)

            assert len(findings) == 0
