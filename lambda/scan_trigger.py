import boto3
import os


def handler(event, context):
    record = event["Records"][0]["s3"]
    bucket = record["bucket"]["name"]
    key = record["object"]["key"]

    region = os.environ.get("AWS_REGION", "us-east-1")
    s3 = boto3.client("s3", region_name=region)
    head = s3.head_object(Bucket=bucket, Key=key)
    meta = head.get("Metadata", {})

    ecs = boto3.client("ecs", region_name=region)
    ecs.run_task(
        cluster=os.environ["ECS_CLUSTER"],
        taskDefinition=os.environ["ECS_TASK_DEFINITION"],
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": [os.environ["SUBNET_ID"]],
                "securityGroups": [os.environ["SECURITY_GROUP_ID"]],
                "assignPublicIp": "DISABLED",
            }
        },
        overrides={
            "containerOverrides": [
                {
                    "name": "vulnlens-sast",
                    "environment": [
                        {"name": "BUCKET_NAME", "value": bucket},
                        {"name": "FILE_KEY", "value": key},
                        {"name": "OWNER", "value": meta.get("owner", "")},
                        {"name": "REPO", "value": meta.get("repo", "")},
                        {"name": "PR_NUMBER", "value": meta.get("pr_number", "")},
                        {"name": "COMMIT_SHA", "value": meta.get("commit_sha", "")},
                    ],
                }
            ]
        },
    )

    return {"statusCode": 200, "body": f"Task launched for {key}"}
