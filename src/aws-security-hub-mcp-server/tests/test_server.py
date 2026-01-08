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

from datetime import datetime, timedelta
from unittest.mock import Mock, patch

import pytest
from botocore.exceptions import ClientError, NoCredentialsError

from awslabs.aws_security_hub_mcp_server.models import (
    ComplianceStatus,
    SeverityLabel,
    WorkflowStatus,
)
from awslabs.aws_security_hub_mcp_server.server import (
    analyze_compliance_trends,
    analyze_resource_type_trends,
    analyze_severity_trends,
    calculate_compliance_score_trend,
    describe_standards_controls,
    determine_overall_trend_direction,
    generate_compliance_report,
    generate_detailed_trend_analysis,
    generate_security_report,
    generate_security_trends_report,
    generate_trend_insights,
    get_enabled_standards,
    get_finding_history,
    get_finding_statistics,
    get_security_findings,
    get_security_hub_client,
    get_security_score,
    identify_most_affected_resources,
    list_security_control_definitions,
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

    # Test get_security_hub_client function
    def test_get_security_hub_client_success(self):
        """Test successful creation of Security Hub client."""
        with patch("awslabs.aws_security_hub_mcp_server.server.boto3.Session") as mock_session:
            mock_client = Mock()
            mock_session.return_value.client.return_value = mock_client
            
            client = get_security_hub_client()
            
            assert client == mock_client
            mock_session.assert_called_once()

    def test_get_security_hub_client_no_credentials(self):
        """Test Security Hub client creation with no credentials."""
        with patch("awslabs.aws_security_hub_mcp_server.server.boto3.Session") as mock_session:
            mock_session.side_effect = NoCredentialsError()
            
            with pytest.raises(NoCredentialsError):
                get_security_hub_client()

    def test_get_security_hub_client_client_error(self):
        """Test Security Hub client creation with client error."""
        with patch("awslabs.aws_security_hub_mcp_server.server.boto3.Session") as mock_session:
            mock_session.side_effect = Exception("Connection error")
            
            with pytest.raises(Exception):
                get_security_hub_client()

    # Test get_enabled_standards function
    @pytest.mark.asyncio
    async def test_get_enabled_standards_success(self, mock_context):
        """Test successful retrieval of enabled standards."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            mock_standards = [
                {
                    "StandardsSubscriptionArn": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-standard/v/1.0.0",
                    "StandardsArn": "arn:aws:securityhub:::standard/aws-foundational-security-standard/v/1.0.0",
                    "StandardsInput": {},
                    "StandardsStatus": "READY"
                }
            ]
            mock_client.return_value.get_enabled_standards.return_value = {"StandardsSubscriptions": mock_standards}
            
            standards = await get_enabled_standards(mock_context)
            
            assert len(standards) == 1
            assert standards[0].standards_subscription_arn == mock_standards[0]["StandardsSubscriptionArn"]
            assert standards[0].standards_arn == mock_standards[0]["StandardsArn"]
            assert standards[0].standards_status == "READY"

    @pytest.mark.asyncio
    async def test_get_enabled_standards_client_error(self, mock_context):
        """Test get_enabled_standards with client error."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            mock_client.return_value.get_enabled_standards.side_effect = ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Access denied"}}, 
                "GetEnabledStandards"
            )
            
            with pytest.raises(Exception) as exc_info:
                await get_enabled_standards(mock_context)
            
            assert "Security Hub API error" in str(exc_info.value)

    # Test list_security_control_definitions function
    @pytest.mark.asyncio
    async def test_list_security_control_definitions_success(self, mock_context):
        """Test successful listing of security control definitions."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            mock_controls = [
                {
                    "SecurityControlId": "S3.1",
                    "SecurityControlArn": "arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1",
                    "Title": "S3 buckets should have public access blocked",
                    "Description": "This control checks whether S3 buckets have public access blocked.",
                    "RemediationUrl": "https://docs.aws.amazon.com/console/securityhub/S3.1/remediation",
                    "SeverityRating": "HIGH",
                    "CurrentRegionAvailability": "AVAILABLE"
                }
            ]
            mock_client.return_value.list_security_control_definitions.return_value = {"SecurityControlDefinitions": mock_controls}
            
            controls = await list_security_control_definitions(mock_context)
            
            assert len(controls) == 1
            assert controls[0].security_control_id == "S3.1"
            assert controls[0].title == "S3 buckets should have public access blocked"
            assert controls[0].severity_rating == "HIGH"

    @pytest.mark.asyncio
    async def test_list_security_control_definitions_with_standard_arn(self, mock_context):
        """Test listing security control definitions with standard ARN filter."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            mock_client.return_value.list_security_control_definitions.return_value = {"SecurityControlDefinitions": []}
            
            await list_security_control_definitions(mock_context, standard_arn="arn:aws:securityhub:::standard/aws-foundational-security-standard/v/1.0.0")
            
            call_args = mock_client.return_value.list_security_control_definitions.call_args
            assert call_args[1]["StandardsArn"] == "arn:aws:securityhub:::standard/aws-foundational-security-standard/v/1.0.0"

    # Test get_finding_history function
    @pytest.mark.asyncio
    async def test_get_finding_history_success(self, mock_context):
        """Test successful retrieval of finding history."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            mock_history = [
                {
                    "FindingIdentifier": {
                        "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/test-finding-1",
                        "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default"
                    },
                    "UpdateTime": datetime.utcnow(),
                    "FindingCreated": True,
                    "UpdateSource": {
                        "Type": "BATCH_UPDATE_FINDINGS",
                        "Identity": "arn:aws:iam::123456789012:user/test-user"
                    },
                    "Updates": [
                        {
                            "UpdatedField": "Workflow/Status",
                            "OldValue": "NEW",
                            "NewValue": "RESOLVED"
                        }
                    ]
                }
            ]
            mock_client.return_value.get_finding_history.return_value = {"Records": mock_history}
            
            history = await get_finding_history(mock_context, "arn:aws:securityhub:us-east-1:123456789012:finding/test-finding-1")
            
            assert len(history) == 1
            assert history[0]["finding_identifier"]["Id"] == "arn:aws:securityhub:us-east-1:123456789012:finding/test-finding-1"
            assert history[0]["finding_created"] is True

    @pytest.mark.asyncio
    async def test_get_finding_history_with_dates(self, mock_context):
        """Test get_finding_history with start and end times."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            mock_client.return_value.get_finding_history.return_value = {"Records": []}
            
            start_time = "2024-01-01T00:00:00Z"
            end_time = "2024-01-31T23:59:59Z"
            
            await get_finding_history(mock_context, "test-finding-id", start_time=start_time, end_time=end_time)
            
            call_args = mock_client.return_value.get_finding_history.call_args
            assert "StartTime" in call_args[1]
            assert "EndTime" in call_args[1]

    # Test describe_standards_controls function
    @pytest.mark.asyncio
    async def test_describe_standards_controls_success(self, mock_context):
        """Test successful description of standards controls."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            mock_controls = [
                {
                    "StandardsControlArn": "arn:aws:securityhub:us-east-1:123456789012:control/aws-foundational-security-standard/v/1.0.0/S3.1",
                    "ControlStatus": "ENABLED",
                    "DisabledReason": None,
                    "ControlStatusUpdatedAt": datetime.utcnow(),
                    "ControlId": "S3.1",
                    "Title": "S3 buckets should have public access blocked",
                    "Description": "This control checks whether S3 buckets have public access blocked.",
                    "RemediationUrl": "https://docs.aws.amazon.com/console/securityhub/S3.1/remediation",
                    "SeverityRating": "HIGH",
                    "RelatedRequirements": ["NIST.800-53.r5 AC-3", "NIST.800-53.r5 AC-6"]
                }
            ]
            mock_client.return_value.describe_standards_controls.return_value = {"Controls": mock_controls}
            
            controls = await describe_standards_controls(mock_context, "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-standard/v/1.0.0")
            
            assert len(controls) == 1
            assert controls[0]["control_id"] == "S3.1"
            assert controls[0]["control_status"] == "ENABLED"
            assert controls[0]["severity_rating"] == "HIGH"

    # Test report generation functions
    @pytest.mark.asyncio
    async def test_generate_security_report_success(self, mock_context, sample_finding):
        """Test successful generation of security report."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            mock_client.return_value.get_findings.return_value = {"Findings": [sample_finding]}
            mock_client.return_value.get_enabled_standards.return_value = {"StandardsSubscriptions": []}
            
            report = await generate_security_report(mock_context)
            
            assert "executive_summary" in report
            assert "security_score" in report["executive_summary"]
            assert "detailed_findings" in report
            assert "recommendations" in report
            assert "enabled_standards" in report

    @pytest.mark.asyncio
    async def test_generate_compliance_report_success(self, mock_context, sample_finding):
        """Test successful generation of compliance report."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            mock_client.return_value.get_findings.return_value = {"Findings": [sample_finding]}
            mock_client.return_value.get_enabled_standards.return_value = {"StandardsSubscriptions": []}
            
            report = await generate_compliance_report(mock_context)
            
            assert "executive_summary" in report
            assert "overall_compliance_percentage" in report["executive_summary"]
            assert "standards_compliance" in report
            assert "compliance_findings_by_category" in report
            assert "recommendations" in report

    @pytest.mark.asyncio
    async def test_generate_security_trends_report_success(self, mock_context, sample_finding):
        """Test successful generation of security trends report."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            mock_client.return_value.get_findings.return_value = {"Findings": [sample_finding]}
            
            report = await generate_security_trends_report(mock_context)
            
            assert "trend_analysis" in report
            assert "severity_trends" in report["trend_analysis"]
            assert "insights_and_recommendations" in report
            assert "historical_data_points" in report

    # Test trend analysis helper functions
    def test_analyze_severity_trends(self):
        """Test severity trends analysis."""
        trend_data = {
            "7_days": {"severity_breakdown": {"HIGH": 1, "MEDIUM": 1}, "data_available": True},
            "14_days": {"severity_breakdown": {"HIGH": 2, "LOW": 1}, "data_available": True}
        }
        periods = [7, 14]
        
        result = analyze_severity_trends(trend_data, periods)
        
        assert "severity_data_points" in result
        assert "trend_directions" in result
        assert "HIGH" in result["severity_data_points"]
        assert "MEDIUM" in result["severity_data_points"]
        assert "LOW" in result["severity_data_points"]
        assert len(result["severity_data_points"]["HIGH"]) == 2
        assert result["severity_data_points"]["HIGH"][0]["count"] == 1  # 7-day period
        assert result["severity_data_points"]["HIGH"][1]["count"] == 2  # 14-day period

    def test_analyze_compliance_trends(self):
        """Test compliance trends analysis."""
        trend_data = {
            "7_days": {"compliance_breakdown": {"FAILED": 1, "PASSED": 1}, "data_available": True},
            "14_days": {"compliance_breakdown": {"FAILED": 2, "PASSED": 0}, "data_available": True}
        }
        periods = [7, 14]
        
        result = analyze_compliance_trends(trend_data, periods)
        
        assert "compliance_data_points" in result
        assert "compliance_score_trend" in result
        assert "FAILED" in result["compliance_data_points"]
        assert "PASSED" in result["compliance_data_points"]
        assert len(result["compliance_data_points"]["FAILED"]) == 2
        assert result["compliance_data_points"]["FAILED"][0]["count"] == 1  # 7-day period
        assert result["compliance_data_points"]["FAILED"][1]["count"] == 2  # 14-day period

    def test_analyze_resource_type_trends(self):
        """Test resource type trends analysis."""
        trend_data = {
            "7_days": {"top_resource_types": {"AwsEc2Instance": 1, "AwsS3Bucket": 1}, "data_available": True},
            "14_days": {"top_resource_types": {"AwsEc2Instance": 2, "AwsS3Bucket": 0}, "data_available": True}
        }
        periods = [7, 14]
        
        result = analyze_resource_type_trends(trend_data, periods)
        
        assert "resource_type_data_points" in result
        assert "most_affected_resources" in result
        assert "AwsEc2Instance" in result["resource_type_data_points"]
        assert "AwsS3Bucket" in result["resource_type_data_points"]
        assert len(result["resource_type_data_points"]["AwsEc2Instance"]) == 2
        assert result["resource_type_data_points"]["AwsEc2Instance"][0]["findings_count"] == 1  # 7-day period
        assert result["resource_type_data_points"]["AwsEc2Instance"][1]["findings_count"] == 2  # 14-day period

    def test_calculate_compliance_score_trend(self):
        """Test compliance score trend calculation."""
        compliance_trends = {
            "PASSED": [
                {"period_days": 7, "count": 10},
                {"period_days": 14, "count": 15}
            ],
            "FAILED": [
                {"period_days": 7, "count": 5},
                {"period_days": 14, "count": 3}
            ],
            "WARNING": [
                {"period_days": 7, "count": 2},
                {"period_days": 14, "count": 1}
            ],
            "NOT_AVAILABLE": [
                {"period_days": 7, "count": 0},
                {"period_days": 14, "count": 0}
            ]
        }
        
        result = calculate_compliance_score_trend(compliance_trends)
        
        assert len(result) == 2
        assert 0 <= result[0]["compliance_score"] <= 100
        assert 0 <= result[1]["compliance_score"] <= 100
        # Second period should have higher score (more passed, fewer failed)
        assert result[1]["compliance_score"] > result[0]["compliance_score"]

    def test_identify_most_affected_resources(self):
        """Test identification of most affected resources."""
        resource_trends = {
            "AwsEc2Instance": [
                {"period_days": 7, "findings_count": 5},
                {"period_days": 14, "findings_count": 8}
            ],
            "AwsS3Bucket": [
                {"period_days": 7, "findings_count": 2},
                {"period_days": 14, "findings_count": 3}
            ],
            "AwsRdsDbInstance": [
                {"period_days": 7, "findings_count": 1},
                {"period_days": 14, "findings_count": 1}
            ]
        }
        
        result = identify_most_affected_resources(resource_trends)
        
        assert len(result) <= 5  # Should return top 5
        assert result[0]["resource_type"] == "AwsEc2Instance"  # Most affected
        assert result[0]["findings_count"] == 5  # Most recent count (7-day period)

    def test_determine_overall_trend_direction(self):
        """Test overall trend direction determination."""
        # Improving trend
        improving_scores = {"7_days": 80.0, "14_days": 70.0, "30_days": 60.0}
        result = determine_overall_trend_direction(improving_scores, [7, 14, 30])
        assert result == "improving"
        
        # Declining trend
        declining_scores = {"7_days": 60.0, "14_days": 70.0, "30_days": 80.0}
        result = determine_overall_trend_direction(declining_scores, [7, 14, 30])
        assert result == "declining"
        
        # Stable trend
        stable_scores = {"7_days": 70.0, "14_days": 71.0, "30_days": 69.0}
        result = determine_overall_trend_direction(stable_scores, [7, 14, 30])
        assert result == "stable"

    def test_generate_trend_insights(self):
        """Test trend insights generation."""
        trend_data = {
            "7_days": {
                "severity_breakdown": {"HIGH": 1},
                "top_resource_types": {"AwsEc2Instance": 1},
                "data_available": True
            },
            "14_days": {
                "severity_breakdown": {"MEDIUM": 1},
                "top_resource_types": {"AwsS3Bucket": 1},
                "data_available": True
            }
        }
        security_scores = {"7_days": 70.0, "14_days": 75.0}
        periods = [7, 14]
        
        result = generate_trend_insights(trend_data, security_scores, periods)
        
        assert "key_insights" in result
        assert "recommendations" in result
        assert "trend_summary" in result
        assert isinstance(result["key_insights"], list)
        assert isinstance(result["recommendations"], list)

    def test_generate_detailed_trend_analysis(self):
        """Test detailed trend analysis generation."""
        trend_data = {
            "7_days": {
                "severity_breakdown": {"HIGH": 1, "MEDIUM": 1},
                "total_findings": 2,
                "data_available": True
            },
            "14_days": {
                "severity_breakdown": {"HIGH": 1, "LOW": 1},
                "total_findings": 2,
                "data_available": True
            }
        }
        periods = [7, 14]
        
        result = generate_detailed_trend_analysis(trend_data, periods)
        
        assert "statistical_summary" in result
        assert "period_comparisons" in result
        assert "data_quality_assessment" in result
        assert "findings_volume_stats" in result["statistical_summary"]

    # Test error handling for all functions
    @pytest.mark.asyncio
    async def test_get_finding_statistics_client_error(self, mock_context):
        """Test get_finding_statistics with client error."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            mock_client.return_value.get_findings.side_effect = ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Access denied"}}, 
                "GetFindings"
            )
            
            with pytest.raises(Exception) as exc_info:
                await get_finding_statistics(mock_context)
            
            assert "Security Hub API error" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_get_security_score_client_error(self, mock_context):
        """Test get_security_score with client error."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            mock_client.return_value.get_findings.side_effect = ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Access denied"}}, 
                "GetFindings"
            )
            
            with pytest.raises(Exception) as exc_info:
                await get_security_score(mock_context)
            
            assert "Security Hub API error" in str(exc_info.value)

    # Test edge cases
    @pytest.mark.asyncio
    async def test_get_finding_statistics_empty_group_by(self, mock_context):
        """Test get_finding_statistics with empty results."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            mock_client.return_value.get_findings.return_value = {"Findings": []}
            
            stats = await get_finding_statistics(mock_context, group_by="SeverityLabel")
            
            assert len(stats) == 0

    @pytest.mark.asyncio
    async def test_get_security_score_no_findings(self, mock_context):
        """Test get_security_score with no findings."""
        with patch("awslabs.aws_security_hub_mcp_server.server.get_security_hub_client") as mock_client:
            mock_client.return_value.get_findings.return_value = {"Findings": []}
            
            score = await get_security_score(mock_context)
            
            assert score.current_score == 100.0  # Perfect score when no findings
            assert score.security_score_percentage == 100.0

    def test_parse_finding_missing_fields(self):
        """Test parse_finding with missing optional fields."""
        minimal_finding = {
            "Id": "test-id",
            "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default",
            "GeneratorId": "test-generator",
            "AwsAccountId": "123456789012",
            "Region": "us-east-1",
            "Title": "Test Finding",
            "Description": "Test description",
            "Severity": {"Label": "MEDIUM"},
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE",
            "CreatedAt": datetime.utcnow(),
            "UpdatedAt": datetime.utcnow(),
            "Resources": [{"Type": "AwsEc2Instance"}]
        }
        
        finding = parse_finding(minimal_finding)
        
        assert finding.id == "test-id"
        assert finding.title == "Test Finding"
        assert finding.severity_label == SeverityLabel.MEDIUM
        assert finding.compliance_status is None  # Default when missing

    def test_parse_finding_invalid_severity(self):
        """Test parse_finding with invalid severity label."""
        finding_data = {
            "Id": "test-id",
            "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default",
            "GeneratorId": "test-generator",
            "AwsAccountId": "123456789012",
            "Region": "us-east-1",
            "Title": "Test Finding",
            "Description": "Test description",
            "Severity": {"Label": "INVALID_SEVERITY"},
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE",
            "CreatedAt": datetime.utcnow(),
            "UpdatedAt": datetime.utcnow(),
            "Resources": [{"Type": "AwsEc2Instance"}]
        }
        
        finding = parse_finding(finding_data)
        
        assert finding.severity_label == SeverityLabel.INFORMATIONAL  # Default fallback