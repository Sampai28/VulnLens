# VulnLens — AWS Resources

This file tracks all AWS resources created for VulnLens.
Networking and new resources are managed via Terraform — see `terraform/` folder.

## Region
`us-east-1`

## Account ID
`103887852337`

---

## IAM Roles

| Role | Used by |
|------|---------|
| `LabRole` | ECS Fargate tasks |
| `RoleForLambdaModLabRole` | Lambda functions |

---

## ECR

| Resource | Value |
|----------|-------|
| Repository | `vulnlens-sast` |
| Image URI | `103887852337.dkr.ecr.us-east-1.amazonaws.com/vulnlens-sast:latest` |

---

## S3

| Bucket | Purpose |
|--------|---------|
| `vulnlens-uploads` | Source code uploads from GHA |

---

## DynamoDB

| Table | Partition key | Purpose |
|-------|--------------|---------|
| `vulnlens-scans` | `scanId` (String) | Scan results storage |

---

## ECS Fargate

| Resource | Value |
|----------|-------|
| Cluster | `vulnlens-cluster` |
| Service | `vulnlens-sast-service` |
| Task definition | `vulnlens-sast-task:1` |

### Spin up
```bash
aws ecs update-service --cluster vulnlens-cluster --service vulnlens-sast-service --desired-count 1
```

### Spin down (stop charges)
```bash
aws ecs update-service --cluster vulnlens-cluster --service vulnlens-sast-service --desired-count 0
```

### Get public IP (after spinning up)
```bash
TASK_ARN=$(aws ecs list-tasks --cluster vulnlens-cluster --query 'taskArns[0]' --output text)
ENI=$(aws ecs describe-tasks --cluster vulnlens-cluster --tasks $TASK_ARN --query 'tasks[0].attachments[0].details[?name==`networkInterfaceId`].value' --output text)
aws ec2 describe-network-interfaces --network-interface-ids $ENI --query 'NetworkInterfaces[0].Association.PublicIp' --output text
```

---

## SQS

| Resource | Name | Purpose |
|----------|------|---------|
| Main queue | `vulnlens-scan-queue` | Scanner → analytics pipeline |
| Dead letter queue | `vulnlens-scan-dlq` | Failed messages after 3 retries |

Set `SQS_QUEUE_URL` env var in ECS task definition to enable publishing.

---

## Lambda

| Function | Trigger | Purpose |
|----------|---------|---------|
| `vulnlens-analytics` | SQS `vulnlens-scan-queue` | Reads `scanId`, runs analytics (CWE enrichment, risk scoring, DBSCAN clustering, trends), writes the `analysis` block back to DynamoDB, then async-invokes `vulnlens-status`. |
| `vulnlens-status` | Async invoke from analytics | Evaluates the security gate (fail on HIGH), posts a GitHub commit status + PR comment, writes the `status` block back to DynamoDB. |

Both use the `LabRole` IAM role (override via the `lambda_role_name` Terraform variable). Handler for both: `src.handler.lambda_handler`, runtime `python3.11`. Pure Python + boto3 (provided by the runtime) — no vendored dependencies.

---

## Secrets Manager

| Secret | Purpose |
|--------|---------|
| `vulnlens/github-token` | GitHub token (`repo:status` + `pull_request` scope) the status Lambda uses to post commit statuses and PR comments. |

Stored as JSON `{"token": "ghp_..."}`. Set the value via the `github_token` Terraform variable, or leave it empty and set it in the AWS console (**Secrets Manager → vulnlens/github-token → Retrieve/Edit**).

---

## SNS

| Resource | Name | Purpose |
|----------|------|---------|
| Topic | `vulnlens-scan-alerts` | Email notifications for DLQ depth and ECS task failures |

### Subscribe your email (one-time manual step after `terraform apply`)
1. AWS Console → **SNS** → **Topics** → `vulnlens-scan-alerts`
2. **Create subscription** → Protocol: **Email** → enter your email
3. Click the confirmation link in the email

---

## CloudWatch Alarms

| Alarm | Trigger | Action |
|-------|---------|--------|
| `vulnlens-dlq-messages` | Any message in DLQ | Email via SNS |
| `vulnlens-ecs-task-failures` | Fargate task stops unexpectedly | Email via SNS |

---

## VPC (managed via Terraform)

All networking is defined in `terraform/vpc.tf`. Fargate tasks run in the private subnet.

| Resource | Purpose |
|----------|---------|
| VPC `10.0.0.0/16` | Private network |
| Private subnet `10.0.2.0/24` | Fargate tasks — not internet-facing |
| Public subnet `10.0.1.0/24` | NAT Gateway |
| VPC Endpoints | S3 + DynamoDB traffic stays within AWS |
| Security group `vulnlens-fargate-sg` | Outbound only, no inbound |

---

## Notes
- VPC and SQS are managed via Terraform — run `terraform apply` to provision
- Stop the Fargate service when not testing to avoid charges (~$0.025/hr)
- `SQS_QUEUE_URL` must be set as an env var in the ECS task definition for SQS publishing to work
