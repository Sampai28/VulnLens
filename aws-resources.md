# VulnLens — AWS Resources

This file tracks all AWS resources created for VulnLens.
Until Terraform is set up, use this as the source of truth for resource names and IDs.

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
| Subnet | `subnet-046c37e9dc81a7048` |
| Security group | `sg-035fa426d423737ae` (port 3000 open) |

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

## Networking

| Resource | Value |
|----------|-------|
| Default VPC | used for all resources |
| Subnet | `subnet-046c37e9dc81a7048` |
| Security group | `sg-035fa426d423737ae` |

---

## Notes
- All resources are in the default VPC for now — VPC ticket will move Fargate to a private subnet
- Terraform ticket will replace this file with proper IaC
- Stop the Fargate service when not testing to avoid charges (~$0.025/hr)
