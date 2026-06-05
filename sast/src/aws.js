import { S3Client, GetObjectCommand } from '@aws-sdk/client-s3';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand, GetCommand } from '@aws-sdk/lib-dynamodb';
import { SQSClient, SendMessageCommand } from '@aws-sdk/client-sqs';
import crypto from 'crypto';

const REGION = process.env.AWS_REGION || 'us-east-1';
const SCAN_TABLE = process.env.DYNAMO_TABLE || 'vulnlens-scans';
const SQS_QUEUE_URL = process.env.SQS_QUEUE_URL || '';

// S3 client
const s3 = new S3Client({ region: REGION });

// DynamoDB client (document client for simpler API)
const dynamoClient = new DynamoDBClient({ region: REGION });
const dynamo = DynamoDBDocumentClient.from(dynamoClient);

// SQS client
const sqs = new SQSClient({ region: REGION });

// Download source code from S3
export const downloadFromS3 = async (bucket, key) => {
  const command = new GetObjectCommand({ Bucket: bucket, Key: key });
  const response = await s3.send(command);
  return await response.Body.transformToString('utf-8');
};

// Save scan results to DynamoDB
export const saveResultsToDynamo = async (scanId, filename, results) => {
  const item = {
    scanId,
    filename,
    scannedAt: new Date().toISOString(),
    summary: {
      total: results.length,
      high: results.filter(v => v.severity === 'HIGH').length,
      medium: results.filter(v => v.severity === 'MEDIUM').length,
      low: results.filter(v => v.severity === 'LOW').length,
    },
    findings: results,
  };

  const command = new PutCommand({
    TableName: SCAN_TABLE,
    Item: item,
  });

  await dynamo.send(command);
  return item;
};

// Publish scan_id to SQS so analytics Lambda picks it up.
// Message includes enough context for analytics to fetch the full scan from DynamoDB.
// If SQS_QUEUE_URL is not set (local dev), skip silently.
export const publishToSQS = async (scanId, filename) => {
  if (!SQS_QUEUE_URL) {
    console.log(`[SQS] SQS_QUEUE_URL not set — skipping publish for scanId: ${scanId}`);
    return;
  }

  const message = {
    scanId,
    filename,
    publishedAt: new Date().toISOString(),
  };

  const command = new SendMessageCommand({
    QueueUrl: SQS_QUEUE_URL,
    MessageBody: JSON.stringify(message),
    MessageGroupId: 'scan-results', // for FIFO queues (not used here but good practice)
  });

  await sqs.send(command);
  console.log(`[SQS] Published scanId: ${scanId} to queue`);
};

// Get scan results from DynamoDB
export const getResultsFromDynamo = async (scanId) => {
  const command = new GetCommand({
    TableName: SCAN_TABLE,
    Key: { scanId },
  });

  const response = await dynamo.send(command);
  return response.Item || null;
};

// Generate a unique scan ID
export const generateScanId = () => {
  return crypto.randomUUID();
};
