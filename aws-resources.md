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
