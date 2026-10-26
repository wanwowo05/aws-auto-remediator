import os
from datetime import UTC, datetime

import boto3

ec2 = boto3.client("ec2")
dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")

AUDIT_TABLE = os.environ["AUDIT_TABLE"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
ALLOWED_TYPES = ["t2.micro", "t3.micro"]


def lambda_handler(event, context):
    detail = event.get("detail", {})
    event_name = detail.get("eventName")
    user = detail.get("userIdentity", {}).get("arn", "Unknown")

    if event_name == "AuthorizeSecurityGroupIngress":
        handle_security_group(detail, user)
    elif event_name == "RunInstances":
        handle_ec2_launch(detail, user)


def handle_security_group(detail, user):
    sg_id = detail.get("requestParameters", {}).get("groupId")
    ip_permissions = (
        detail.get("requestParameters", {}).get("ipPermissions", {}).get("items", [])
    )

    for perm in ip_permissions:
        from_port = perm.get("fromPort")
        to_port = perm.get("toPort")
        protocol = perm.get("ipProtocol", "tcp")

        if from_port == 22 or to_port == 22:
            for ip_range in perm.get("ipRanges", {}).get("items", []):
                if ip_range.get("cidrIp") == "0.0.0.0/0":
                    ec2.revoke_security_group_ingress(
                        GroupId=sg_id,
                        IpProtocol=protocol,
                        FromPort=from_port,
                        ToPort=to_port,
                        CidrIp="0.0.0.0/0",
                    )
                    log_and_notify(
                        resource_id=sg_id,
                        user=user,
                        violation="Open SSH (Port 22) to 0.0.0.0/0",
                        action="Revoked ingress rule",
                    )


def handle_ec2_launch(detail, user):
    items = detail.get("responseElements", {}).get("instancesSet", {}).get("items", [])
    for instance in items:
        instance_id = instance.get("instanceId")
        instance_type = instance.get("instanceType")
        tags = instance.get("tagSet", {}).get("items", [])

        has_cost_center = any(t.get("key") == "CostCenter" for t in tags)

        reasons = []
        if instance_type not in ALLOWED_TYPES:
            reasons.append(f"Unapproved instance type ({instance_type})")
        if not has_cost_center:
            reasons.append("Missing mandatory CostCenter tag")

        if reasons:
            ec2.terminate_instances(InstanceIds=[instance_id])
            log_and_notify(
                resource_id=instance_id,
                user=user,
                violation=", ".join(reasons),
                action="Terminated non-compliant EC2 instance",
            )


def log_and_notify(resource_id, user, violation, action):
    table = dynamodb.Table(AUDIT_TABLE)
    timestamp = datetime.now(UTC).isoformat()

    table.put_item(
        Item={
            "ResourceId": resource_id,
            "Timestamp": timestamp,
            "ViolatingUser": user,
            "Violation": violation,
            "ActionTaken": action,
        }
    )

    message = (
        f"AWS Auto-Remediation Executed\n"
        f"-----------------------------\n"
        f"Resource:  {resource_id}\n"
        f"User:      {user}\n"
        f"Violation: {violation}\n"
        f"Action:    {action}\n"
        f"Timestamp: {timestamp}"
    )

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"[AUTO-REMEDIATED] {resource_id}",
        Message=message,
    )
