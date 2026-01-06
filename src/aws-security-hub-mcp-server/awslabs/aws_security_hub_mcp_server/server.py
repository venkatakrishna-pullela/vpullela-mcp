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
"""AWS Security Hub MCP Server implementation."""

import os
import sys
from datetime import datetime
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from loguru import logger
from mcp.server.fastmcp import Context, FastMCP

from awslabs.aws_security_hub_mcp_server.consts import (
    DEFAULT_AWS_REGION,
    DEFAULT_LOG_LEVEL,
    DEFAULT_MAX_RESULTS,
    ENV_AWS_PROFILE,
    ENV_AWS_REGION,
    ENV_LOG_LEVEL,
    SEVERITY_WEIGHTS,
)
from awslabs.aws_security_hub_mcp_server.models import (
    ComplianceStatus,
    EnabledStandard,
    FindingStatistics,
    RecordState,
    SecurityControlDefinition,
    SecurityFinding,
    SecurityScore,
    SeverityLabel,
    WorkflowStatus,
)

# Set up logging
logger.remove()
logger.add(sys.stderr, level=os.getenv(ENV_LOG_LEVEL, DEFAULT_LOG_LEVEL))

# Configuration
AWS_PROFILE = os.getenv(ENV_AWS_PROFILE)
AWS_REGION = os.getenv(ENV_AWS_REGION, DEFAULT_AWS_REGION)
MAX_RESULTS = int(os.getenv("SECURITY_HUB_MAX_RESULTS", str(DEFAULT_MAX_RESULTS)))

mcp = FastMCP(
    "aws-security-hub",
    instructions="""
    # AWS Security Hub MCP Server

    This server provides tools to interact with AWS Security Hub for security findings analysis,
    standards management, and security posture monitoring using official AWS APIs.

    ## Best Practices

    - Use specific filters when querying findings to get relevant results
    - For large result sets, pagination is handled automatically
    - All tools use official AWS Security Hub APIs with verified data
    - Monitor security scores to track overall security improvements

    ## Tool Selection Guide

    - Use `get_security_findings` when: You need to retrieve and analyze specific security findings
    - Use `get_finding_statistics` when: You want aggregated data about security findings
    - Use `get_security_score` when: You need to track overall security posture
    - Use `get_enabled_standards` when: You want to see which security standards are enabled
    - Use `list_security_control_definitions` when: You need information about available security controls
    - Use `get_finding_history` when: You want to track changes to a specific finding over time
    - Use `describe_standards_controls` when: You need details about controls within a specific standard
    """,
    dependencies=[
        "boto3",
        "pydantic",
        "loguru",
    ],
)


def get_security_hub_client():
    """Get a configured Security Hub client."""
    try:
        session = boto3.Session(profile_name=AWS_PROFILE, region_name=AWS_REGION)
        return session.client("securityhub")
    except NoCredentialsError:
        logger.error("AWS credentials not found. Please configure your credentials.")
        raise
    except Exception as e:
        logger.error(f"Error creating Security Hub client: {e}")
        raise


def parse_finding(finding_data: dict[str, Any]) -> SecurityFinding:
    """Parse AWS Security Hub finding data into our model."""
    severity = finding_data.get("Severity", {})
    severity_label = severity.get("Label", "INFORMATIONAL")
    severity_score = severity.get("Normalized")

    workflow = finding_data.get("Workflow", {})
    workflow_status = workflow.get("Status", "NEW")

    compliance = finding_data.get("Compliance", {})
    compliance_status = compliance.get("Status") if compliance else None

    resources = finding_data.get("Resources", [])
    resource_type = resources[0].get("Type") if resources else None
    resource_id = resources[0].get("Id") if resources else None

    remediation = finding_data.get("Remediation", {})
    remediation_url = remediation.get("Recommendation", {}).get("Url") if remediation else None

    return SecurityFinding(
        id=finding_data["Id"],
        product_arn=finding_data["ProductArn"],
        generator_id=finding_data["GeneratorId"],
        aws_account_id=finding_data["AwsAccountId"],
        region=finding_data["Region"],
        title=finding_data["Title"],
        description=finding_data["Description"],
        severity_label=SeverityLabel(severity_label),
        severity_score=severity_score,
        workflow_status=WorkflowStatus(workflow_status),
        record_state=RecordState(finding_data.get("RecordState", "ACTIVE")),
        compliance_status=ComplianceStatus(compliance_status) if compliance_status else None,
        created_at=finding_data["CreatedAt"],
        updated_at=finding_data["UpdatedAt"],
        resource_type=resource_type,
        resource_id=resource_id,
        remediation_url=remediation_url,
        source_url=finding_data.get("SourceUrl"),
    )


@mcp.tool(name="get-security-findings")
async def get_security_findings(
    ctx: Context,
    severity_labels: list[SeverityLabel] | None = None,
    workflow_status: list[WorkflowStatus] | None = None,
    compliance_status: list[ComplianceStatus] | None = None,
    record_state: list[RecordState] | None = None,
    product_name: str | None = None,
    resource_type: str | None = None,
    days_back: int | None = 7,
    max_results: int | None = 50,
) -> list[SecurityFinding]:
    """Retrieve security findings from AWS Security Hub with filtering options.

    This tool allows you to query Security Hub findings with various filters to focus on
    specific security issues. You can filter by severity, workflow status, compliance status,
    and other attributes.

    Args:
        ctx: MCP context for logging and error handling
        severity_labels: Filter by severity levels
        workflow_status: Filter by workflow status
        compliance_status: Filter by compliance status
        record_state: Filter by record state
        product_name: Filter by product name
        resource_type: Filter by AWS resource type
        days_back: Number of days back to search
        max_results: Maximum number of findings to return

    Returns:
        List of SecurityFinding objects matching the filters
    """
    try:
        client = get_security_hub_client()

        # Build filters
        filters = {}

        if severity_labels:
            filters["SeverityLabel"] = [{"Value": label.value, "Comparison": "EQUALS"} for label in severity_labels]

        if workflow_status:
            filters["WorkflowStatus"] = [{"Value": status.value, "Comparison": "EQUALS"} for status in workflow_status]

        if compliance_status:
            filters["ComplianceStatus"] = [
                {"Value": status.value, "Comparison": "EQUALS"} for status in compliance_status
            ]

        if record_state:
            filters["RecordState"] = [{"Value": state.value, "Comparison": "EQUALS"} for state in record_state]

        if product_name:
            filters["ProductName"] = [{"Value": product_name, "Comparison": "EQUALS"}]

        if resource_type:
            filters["ResourceType"] = [{"Value": resource_type, "Comparison": "EQUALS"}]

        # Add time filter using DateRange format
        if days_back and days_back <= 365:  # Reasonable limit
            try:
                filters["UpdatedAt"] = [{"DateRange": {"Value": days_back, "Unit": "DAYS"}}]
            except Exception as e:
                logger.warning(f"Could not add time filter: {e}")
                # Continue without time filter

        logger.info(f"Querying Security Hub findings with filters: {filters}")

        # Handle pagination to get all findings up to max_results
        all_findings = []
        next_token = None
        page_count = 0
        max_pages = 50  # Safety limit
        requested_max = max_results or 50

        while page_count < max_pages and len(all_findings) < requested_max:
            page_count += 1

            # Calculate how many results to request for this page
            remaining_needed = requested_max - len(all_findings)
            page_size = min(100, remaining_needed)  # AWS max is 100 per page

            # Prepare request parameters
            request_params = {"Filters": filters, "MaxResults": page_size}

            if next_token:
                request_params["NextToken"] = next_token

            logger.debug(f"Fetching page {page_count} of findings (requesting {page_size} results)...")
            response = client.get_findings(**request_params)

            page_findings = response.get("Findings", [])

            # Parse findings and add to results
            for finding_data in page_findings:
                if len(all_findings) >= requested_max:
                    break
                try:
                    finding = parse_finding(finding_data)
                    all_findings.append(finding)
                except Exception as e:
                    logger.warning(f"Error parsing finding {finding_data.get('Id', 'unknown')}: {e}")
                    continue

            # Check if there are more pages and if we need more results
            next_token = response.get("NextToken")
            if not next_token or len(all_findings) >= requested_max:
                break

            logger.debug(f"Page {page_count}: Got {len(page_findings)} findings, total so far: {len(all_findings)}")

        logger.info(f"Retrieved {len(all_findings)} security findings across {page_count} pages")
        return all_findings

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        logger.error(f"AWS Security Hub error ({error_code}): {error_message}")
        raise Exception(f"Security Hub API error: {error_message}") from e
    except Exception as e:
        logger.error(f"Error retrieving security findings: {e}")
        raise


@mcp.tool(name="get-finding-statistics")
async def get_finding_statistics(
    ctx: Context,
    group_by: str = "SeverityLabel",
    days_back: int | None = 30,
) -> list[FindingStatistics]:
    """Get aggregated statistics about security findings grouped by specified attribute.

    This tool provides statistical analysis of your security findings, helping you understand
    the distribution and trends in your security posture.

    Args:
        ctx: MCP context for logging and error handling
        group_by: Attribute to group findings by
        days_back: Number of days back to analyze

    Returns:
        List of FindingStatistics objects with aggregated data
    """
    try:
        client = get_security_hub_client()

        # Build filters - simplified to avoid API parameter issues
        filters: dict[str, Any] = {
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
        }

        # Only add time filter if days_back is reasonable and we can format it correctly
        if days_back and days_back <= 365:  # Reasonable limit
            try:
                # Use DateRange format which is more reliable
                filters["UpdatedAt"] = [
                    {"DateRange": {"Value": str(days_back), "Unit": "DAYS"}}
                ]
            except Exception as e:
                logger.warning(f"Could not add time filter: {e}")
                # Continue without time filter

        logger.info(f"Getting finding statistics grouped by {group_by}")

        # Get ALL findings using pagination to ensure accurate statistics
        all_findings = []
        next_token = None
        page_count = 0
        max_pages = 20  # Safety limit to prevent infinite loops

        while page_count < max_pages:
            page_count += 1

            # Prepare request parameters
            request_params = {
                "Filters": filters,
                "MaxResults": 100,  # AWS maximum per page
            }

            if next_token:
                request_params["NextToken"] = next_token

            logger.debug(f"Fetching page {page_count} of findings...")
            response = client.get_findings(**request_params)

            page_findings = response.get("Findings", [])
            all_findings.extend(page_findings)

            # Check if there are more pages
            next_token = response.get("NextToken")
            if not next_token:
                break

            logger.debug(f"Page {page_count}: Got {len(page_findings)} findings, total so far: {len(all_findings)}")

        logger.info(f"Retrieved {len(all_findings)} total findings across {page_count} pages")

        # Group findings by the specified attribute
        groups = {}
        total_count = len(all_findings)

        for finding in all_findings:
            group_key = None

            if group_by == "SeverityLabel":
                group_key = finding.get("Severity", {}).get("Label", "UNKNOWN")
            elif group_by == "WorkflowStatus":
                group_key = finding.get("Workflow", {}).get("Status", "UNKNOWN")
            elif group_by == "ProductName":
                group_key = finding.get("ProductName", "UNKNOWN")
            elif group_by == "ResourceType":
                resources = finding.get("Resources", [])
                group_key = resources[0].get("Type", "UNKNOWN") if resources else "UNKNOWN"
            else:
                group_key = "UNKNOWN"

            groups[group_key] = groups.get(group_key, 0) + 1

        # Convert to statistics objects
        statistics = []
        for group_key, count in groups.items():
            percentage = (count / total_count * 100) if total_count > 0 else 0
            stat = FindingStatistics(group_key=group_key, count=count, percentage=round(percentage, 2))
            statistics.append(stat)

        # Sort by count descending
        statistics.sort(key=lambda x: x.count, reverse=True)

        logger.info(f"Generated statistics for {len(statistics)} groups from {total_count} findings")
        return statistics

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        logger.error(f"AWS Security Hub error ({error_code}): {error_message}")
        raise Exception(f"Security Hub API error: {error_message}") from e
    except Exception as e:
        logger.error(f"Error retrieving finding statistics: {e}")
        raise


@mcp.tool(name="get-security-score")
async def get_security_score(
    ctx: Context,
) -> SecurityScore:
    """Retrieve the overall security score and security posture information.

    This tool provides an overview of your overall security posture based on
    Security Hub's security score calculation.

    Args:
        ctx: MCP context for logging and error handling

    Returns:
        SecurityScore object with current score and metrics
    """
    try:
        client = get_security_hub_client()

        logger.info("Calculating security score from findings data")

        # Get ALL active findings using pagination
        filters = {"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]}

        all_findings = []
        next_token = None
        page_count = 0
        max_pages = 20  # Safety limit to prevent infinite loops

        while page_count < max_pages:
            page_count += 1

            # Prepare request parameters
            request_params = {
                "Filters": filters,
                "MaxResults": 100,  # AWS maximum per page
            }

            if next_token:
                request_params["NextToken"] = next_token

            logger.debug(f"Fetching page {page_count} of findings for security score...")
            response = client.get_findings(**request_params)

            page_findings = response.get("Findings", [])
            all_findings.extend(page_findings)

            # Check if there are more pages
            next_token = response.get("NextToken")
            if not next_token:
                break

            logger.debug(f"Page {page_count}: Got {len(page_findings)} findings, total so far: {len(all_findings)}")

        total_findings = len(all_findings)
        logger.info(f"Retrieved {total_findings} total findings for security score calculation")

        # Count findings by severity
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}

        control_findings = 0

        for finding in all_findings:
            severity = finding.get("Severity", {}).get("Label", "INFORMATIONAL")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            # Count control findings (findings from security standards)
            generator_id = finding.get("GeneratorId", "")
            if any(
                std in generator_id
                for std in ["aws-foundational-security-standard", "cis-aws-foundations-benchmark", "pci-dss"]
            ):
                control_findings += 1

        # Calculate a simple security score based on severity weights
        # This is a simplified calculation - AWS Security Hub uses a more complex algorithm
        total_weight = sum(severity_counts[sev] * weight for sev, weight in SEVERITY_WEIGHTS.items())
        max_possible_weight = total_findings * SEVERITY_WEIGHTS["CRITICAL"] if total_findings > 0 else 1

        # Invert the score so higher is better (fewer high-severity findings = higher score)
        current_score = max(0, 100 - (total_weight / max_possible_weight * 100)) if total_findings > 0 else 100

        security_score = SecurityScore(
            current_score=round(current_score, 2),
            max_score=100.0,
            score_date=datetime.utcnow().isoformat() + "Z",
            control_findings_count=control_findings,
            security_score_percentage=round(current_score, 2),
        )

        logger.info(f"Calculated security score: {current_score:.2f}/100 based on {total_findings} findings")
        return security_score

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        logger.error(f"AWS Security Hub error ({error_code}): {error_message}")
        raise Exception(f"Security Hub API error: {error_message}") from e
    except Exception as e:
        logger.error(f"Error calculating security score: {e}")
        raise


@mcp.tool(name="get-enabled-standards")
async def get_enabled_standards(
    ctx: Context,
) -> list[EnabledStandard]:
    """Retrieve all enabled security standards in Security Hub.

    This tool provides information about which security standards are currently enabled
    in your Security Hub configuration, using the official GetEnabledStandards API.

    Args:
        ctx: MCP context for logging and error handling

    Returns:
        List of EnabledStandard objects with official standard information
    """
    try:
        client = get_security_hub_client()

        logger.info("Retrieving enabled security standards")

        # Get enabled standards using official API
        all_standards = []
        next_token = None
        page_count = 0
        max_pages = 10  # Safety limit

        while page_count < max_pages:
            page_count += 1

            # Prepare request parameters
            request_params = {"MaxResults": 100}

            if next_token:
                request_params["NextToken"] = next_token

            logger.debug(f"Fetching page {page_count} of enabled standards...")
            standards_response = client.get_enabled_standards(**request_params)

            # Get standard details for names and descriptions
            standards_details_response = client.describe_standards()
            standards_details = {std["StandardsArn"]: std for std in standards_details_response["Standards"]}

            page_standards = standards_response.get("StandardsSubscriptions", [])

            for standard in page_standards:
                standard_detail = standards_details.get(standard["StandardsArn"], {})

                enabled_standard = EnabledStandard(
                    standards_arn=standard["StandardsArn"],
                    standards_subscription_arn=standard["StandardsSubscriptionArn"],
                    standards_status=standard["StandardsStatus"],
                    standards_status_reason=str(standard.get("StandardsStatusReason", "")),
                    name=standard_detail.get("Name", "Unknown Standard"),
                    description=standard_detail.get("Description"),
                )
                all_standards.append(enabled_standard)

            # Check if there are more pages
            next_token = standards_response.get("NextToken")
            if not next_token:
                break

            logger.debug(f"Page {page_count}: Got {len(page_standards)} standards, total so far: {len(all_standards)}")

        logger.info(f"Retrieved {len(all_standards)} enabled standards")
        return all_standards

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        logger.error(f"AWS Security Hub error ({error_code}): {error_message}")
        raise Exception(f"Security Hub API error: {error_message}") from e
    except Exception as e:
        logger.error(f"Error retrieving enabled standards: {e}")
        raise


@mcp.tool(name="list-security-control-definitions")
async def list_security_control_definitions(
    ctx: Context,
    standard_arn: str | None = None,
    max_results: int | None = 100,
) -> list[SecurityControlDefinition]:
    """List security control definitions available in Security Hub.

    This tool provides information about security controls using the official
    ListSecurityControlDefinitions API. Controls define the security checks
    that Security Hub performs.

    Args:
        ctx: MCP context for logging and error handling
        standard_arn: Optional filter for controls from a specific standard
        max_results: Maximum number of control definitions to return

    Returns:
        List of SecurityControlDefinition objects with official control information
    """
    try:
        client = get_security_hub_client()

        logger.info("Retrieving security control definitions")

        # Get control definitions using official API
        all_controls = []
        next_token = None
        page_count = 0
        max_pages = 20  # Safety limit
        requested_max = max_results or 100

        while page_count < max_pages and len(all_controls) < requested_max:
            page_count += 1

            # Calculate how many results to request for this page
            remaining_needed = requested_max - len(all_controls)
            page_size = min(100, remaining_needed)  # AWS max is 100 per page

            # Prepare request parameters
            request_params: dict[str, Any] = {"MaxResults": page_size}

            if next_token:
                request_params["NextToken"] = next_token

            if standard_arn:
                request_params["StandardsArn"] = standard_arn

            logger.debug(f"Fetching page {page_count} of control definitions...")
            response = client.list_security_control_definitions(**request_params)

            page_controls = response.get("SecurityControlDefinitions", [])

            for control in page_controls:
                if len(all_controls) >= requested_max:
                    break

                control_def = SecurityControlDefinition(
                    security_control_id=control["SecurityControlId"],
                    title=control["Title"],
                    description=control["Description"],
                    remediation_url=control.get("RemediationUrl"),
                    severity_rating=SeverityLabel(control["SeverityRating"]),
                    current_region_availability=control["CurrentRegionAvailability"],
                )
                all_controls.append(control_def)

            # Check if there are more pages and if we need more results
            next_token = response.get("NextToken")
            if not next_token or len(all_controls) >= requested_max:
                break

            logger.debug(f"Page {page_count}: Got {len(page_controls)} controls, total so far: {len(all_controls)}")

        logger.info(f"Retrieved {len(all_controls)} security control definitions")
        return all_controls

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        logger.error(f"AWS Security Hub error ({error_code}): {error_message}")
        raise Exception(f"Security Hub API error: {error_message}") from e
    except Exception as e:
        logger.error(f"Error retrieving security control definitions: {e}")
        raise


@mcp.tool(name="get-finding-history")
async def get_finding_history(
    ctx: Context,
    finding_identifier: str,
    start_time: str | None = None,
    end_time: str | None = None,
    max_results: int | None = 100,
) -> list[dict]:
    """Get the history of changes for a specific security finding.

    This tool provides the change history for a finding using the official
    GetFindingHistory API, showing how the finding has evolved over time.

    Args:
        ctx: MCP context for logging and error handling
        finding_identifier: The finding ID to get history for
        start_time: Start time for history (ISO format, e.g., '2024-01-01T00:00:00Z')
        end_time: End time for history (ISO format, e.g., '2024-12-31T23:59:59Z')
        max_results: Maximum number of history records to return

    Returns:
        List of finding history records with timestamps and changes
    """
    try:
        client = get_security_hub_client()

        logger.info(f"Retrieving finding history for {finding_identifier}")

        # Get finding history using official API
        all_history = []
        next_token = None
        page_count = 0
        max_pages = 10  # Safety limit
        requested_max = max_results or 100

        while page_count < max_pages and len(all_history) < requested_max:
            page_count += 1

            # Calculate how many results to request for this page
            remaining_needed = requested_max - len(all_history)
            page_size = min(100, remaining_needed)  # AWS max is 100 per page

            # Prepare request parameters
            request_params = {
                "FindingIdentifier": {
                    "Id": finding_identifier,
                    "ProductArn": f"arn:aws:securityhub:{AWS_REGION}::product/aws/securityhub",
                },
                "MaxResults": page_size,
            }

            if next_token:
                request_params["NextToken"] = next_token

            if start_time:
                request_params["StartTime"] = start_time

            if end_time:
                request_params["EndTime"] = end_time

            logger.debug(f"Fetching page {page_count} of finding history...")
            response = client.get_finding_history(**request_params)

            page_history = response.get("Records", [])

            for record in page_history:
                if len(all_history) >= requested_max:
                    break

                # Convert datetime objects to strings for JSON serialization
                history_record = {
                    "finding_identifier": record.get("FindingIdentifier", {}),
                    "update_time": record.get("UpdateTime").isoformat() if record.get("UpdateTime") else None,
                    "finding_created": record.get("FindingCreated", False),
                    "update_source": record.get("UpdateSource", {}),
                    "updates": record.get("Updates", {}),
                }
                all_history.append(history_record)

            # Check if there are more pages and if we need more results
            next_token = response.get("NextToken")
            if not next_token or len(all_history) >= requested_max:
                break

            logger.debug(
                f"Page {page_count}: Got {len(page_history)} history records, total so far: {len(all_history)}"
            )

        logger.info(f"Retrieved {len(all_history)} finding history records")
        return all_history

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        logger.error(f"AWS Security Hub error ({error_code}): {error_message}")
        raise Exception(f"Security Hub API error: {error_message}") from e
    except Exception as e:
        logger.error(f"Error retrieving finding history: {e}")
        raise


@mcp.tool(name="describe-standards-controls")
async def describe_standards_controls(
    ctx: Context,
    standards_subscription_arn: str,
    max_results: int | None = 100,
) -> list[dict]:
    """Describe the controls for a specific security standard subscription.

    This tool provides detailed information about the controls within a security
    standard using the official DescribeStandardsControls API.

    Args:
        ctx: MCP context for logging and error handling
        standards_subscription_arn: ARN of the standards subscription
        max_results: Maximum number of controls to return

    Returns:
        List of control information with status, severity, and details
    """
    try:
        client = get_security_hub_client()

        logger.info(f"Describing controls for standard: {standards_subscription_arn}")

        # Get controls using official API
        all_controls = []
        next_token = None
        page_count = 0
        max_pages = 10  # Safety limit
        requested_max = max_results or 100

        while page_count < max_pages and len(all_controls) < requested_max:
            page_count += 1

            # Calculate how many results to request for this page
            remaining_needed = requested_max - len(all_controls)
            page_size = min(100, remaining_needed)  # AWS max is 100 per page

            # Prepare request parameters
            request_params = {"StandardsSubscriptionArn": standards_subscription_arn, "MaxResults": page_size}

            if next_token:
                request_params["NextToken"] = next_token

            logger.debug(f"Fetching page {page_count} of controls...")
            response = client.describe_standards_controls(**request_params)

            page_controls = response.get("Controls", [])

            for control in page_controls:
                if len(all_controls) >= requested_max:
                    break

                # Convert datetime objects to strings for JSON serialization
                control_info = {
                    "standards_control_arn": control.get("StandardsControlArn"),
                    "control_id": control.get("ControlId"),
                    "title": control.get("Title"),
                    "description": control.get("Description"),
                    "remediation_url": control.get("RemediationUrl"),
                    "severity_rating": control.get("SeverityRating"),
                    "control_status": control.get("ControlStatus"),
                    "control_status_updated_at": control.get("ControlStatusUpdatedAt").isoformat()
                    if control.get("ControlStatusUpdatedAt")
                    else None,
                    "disabled_reason": control.get("DisabledReason"),
                    "related_requirements": control.get("RelatedRequirements", []),
                }
                all_controls.append(control_info)

            # Check if there are more pages and if we need more results
            next_token = response.get("NextToken")
            if not next_token or len(all_controls) >= requested_max:
                break

            logger.debug(f"Page {page_count}: Got {len(page_controls)} controls, total so far: {len(all_controls)}")

        logger.info(f"Retrieved {len(all_controls)} controls for standard")
        return all_controls

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        logger.error(f"AWS Security Hub error ({error_code}): {error_message}")
        raise Exception(f"Security Hub API error: {error_message}") from e
    except Exception as e:
        logger.error(f"Error describing standards controls: {e}")
        raise


def main():
    """Run the MCP server with CLI argument support."""
    mcp.run()


if __name__ == "__main__":
    main()
