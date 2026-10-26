# AWS Event-Driven Cloud Security & FinOps Auto-Remediator

Serverless self-healing cloud pipeline built with **Amazon EventBridge**, **AWS Lambda (Python 3.12 / Boto3)**, **Amazon DynamoDB**, **Amazon SNS**, **Terraform**, and **GitHub Actions**.

## Architecture & Capabilities
- **Automated Security Remediation:** Intercepts `AuthorizeSecurityGroupIngress` API calls via CloudTrail & EventBridge. If Port 22 (SSH) is exposed to `0.0.0.0/0`, Lambda immediately revokes the rule.
- **Automated FinOps Cost Control:** Intercepts `RunInstances` API calls and terminates EC2 instances launched without a mandatory `CostCenter` tag or outside approved Free Tier instance types (`t2.micro` / `t3.micro`).
- **Audit Logging & Terminal Dashboard:** Records every violation and automated action in DynamoDB (`PAY_PER_REQUEST`) and sends instant email notifications via SNS. Includes a local `rich` CLI viewer (`src/view_logs.py`).
- **Infrastructure as Code & CI/CD:** 100% provisioned via Terraform and validated automatically on every push via GitHub Actions (`ruff` + `terraform validate`).
