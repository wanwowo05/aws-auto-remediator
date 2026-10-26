terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  default = "ap-southeast-1"
}

variable "alert_email" {
  description = "Email address for SNS alerts"
  default     = "wanhalimwowo@gmail.com"
}

resource "aws_dynamodb_table" "audit_log" {
  name         = "CloudAutoRemediatorAudit"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "ResourceId"
  range_key    = "Timestamp"

  attribute {
    name = "ResourceId"
    type = "S"
  }

  attribute {
    name = "Timestamp"
    type = "S"
  }
}

resource "aws_sns_topic" "alerts" {
  name = "cloud-auto-remediator-alerts"
}

resource "aws_sns_topic_subscription" "email_target" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_iam_role" "lambda_exec" {
  name = "auto_remediator_lambda_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "auto_remediator_least_privilege"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ec2:RevokeSecurityGroupIngress", "ec2:TerminateInstances"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = aws_dynamodb_table.audit_log.arn
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../src/remediate.py"
  output_path = "${path.module}/remediate.zip"
}

resource "aws_lambda_function" "remediator" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "CloudSecurityCostRemediator"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "remediate.lambda_handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "python3.12"
  timeout          = 15

  environment {
    variables = {
      AUDIT_TABLE   = aws_dynamodb_table.audit_log.name
      SNS_TOPIC_ARN = aws_sns_topic.alerts.arn
    }
  }
}

resource "aws_cloudwatch_event_rule" "ec2_compliance_rule" {
  name        = "capture-risky-ec2-events"
  description = "Triggers on open SSH rules or EC2 launches"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = ["AuthorizeSecurityGroupIngress", "RunInstances"]
    }
  })
}

resource "aws_cloudwatch_event_target" "trigger_lambda" {
  rule      = aws_cloudwatch_event_rule.ec2_compliance_rule.name
  target_id = "SendToRemediatorLambda"
  arn       = aws_lambda_function.remediator.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ec2_compliance_rule.arn
}