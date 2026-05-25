import { S3Client, GetObjectCommand } from '@aws-sdk/client-s3';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand, GetCommand } from '@aws-sdk/lib-dynamodb';
import crypto from 'crypto';

const REGION = process.env.AWS_REGION || 'us-east-1';
const SCAN_TABLE = process.env.DYNAMO_TABLE || 'vulnlens-scans';

// S3 client
const s3 = new S3Client({ region: REGION });

// DynamoDB client (document client for simpler API)
const dynamoClient = new DynamoDBClient({ region: REGION });
const dynamo = DynamoDBDocumentClient.from(dynamoClient);

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
