# BASTION Deployment Guide

Hướng dẫn deploy BASTION lên AWS với tất cả ML components.

---

## Deployment Strategies

### Strategy 1: Pure LLM (Simplest)

**Pros**: No training required, works immediately
**Cons**: High cost ($80/month for 10k alerts), slow (2-5s per analysis)

```bash
# .env
BASTION_USE_ML_CLASSIFIER=false
BASTION_USE_SEMANTIC_EMBEDDINGS=false
BASTION_USE_LSTM_UBA=false
BASTION_USE_SEMANTIC_ANALYZER=false
```

**Lambda Config**:
- Memory: 512MB
- Timeout: 5 minutes
- No model downloads needed

---

### Strategy 2: Tier 1 ML Only (Recommended for Start)

**Pros**: 60% false positive reduction, minimal training
**Cons**: Still uses LLM for Tier 2 (moderate cost)

```bash
# .env
BASTION_USE_ML_CLASSIFIER=true          # BERT phishing (pre-trained)
BASTION_USE_SEMANTIC_EMBEDDINGS=true    # Sentence-BERT (pre-trained)
BASTION_USE_LSTM_UBA=true               # Requires training
BASTION_USE_SEMANTIC_ANALYZER=false     # Not yet trained
```

**Lambda Config**:
- Memory: 1536MB
- Timeout: 5 minutes
- Provisioned concurrency: 2-5 (avoid cold starts)

**Training Required**:
```bash
# Train LSTM UBA on historical CloudTrail logs
python scripts/train_lstm_uba.py --data cloudtrail_logs.json --epochs 100
```

**Cost**: ~$40/month (50% reduction vs pure LLM)

---

### Strategy 3: Full ML Stack (Recommended for Production)

**Pros**: 95% cost reduction, 10-20x faster, privacy-preserving
**Cons**: Requires 1-2 months data collection + training

```bash
# .env
BASTION_USE_ML_CLASSIFIER=true
BASTION_USE_SEMANTIC_EMBEDDINGS=true
BASTION_USE_LSTM_UBA=true
BASTION_USE_SEMANTIC_ANALYZER=true
BASTION_SEMANTIC_ANALYZER_THRESHOLD=0.8
```

**Lambda Config**:
- Memory: 2048MB
- Timeout: 5 minutes
- Provisioned concurrency: 5-10
- EFS mount: Pre-load models (optional)

**Training Workflow**:

1. **Phase 1** (Month 1-2): Run with LLM, collect data
   ```bash
   BASTION_USE_SEMANTIC_ANALYZER=false
   # Let system run, collect LLM outputs
   ```

2. **Phase 2**: Export training data
   ```bash
   python scripts/export_training_data.py --output training_data.json
   ```

3. **Phase 3**: Train semantic analyzer
   ```bash
   python scripts/train_semantic_analyzer.py \
       --data training_data.json \
       --epochs 20 \
       --batch-size 32
   ```

4. **Phase 4**: Enable semantic analyzer
   ```bash
   BASTION_USE_SEMANTIC_ANALYZER=true
   BASTION_SEMANTIC_ANALYZER_THRESHOLD=0.8
   ```

**Cost**: ~$4-17/month (79-95% reduction vs pure LLM)

---

## AWS Infrastructure Setup

### 1. S3 Buckets

```bash
# Data lake (input)
aws s3 mb s3://bastion-data-lake

# Athena results
aws s3 mb s3://bastion-athena-results

# Model storage (optional)
aws s3 mb s3://bastion-models
```

### 2. DynamoDB Table

```bash
aws dynamodb create-table \
    --table-name bastion-results \
    --attribute-definitions \
        AttributeName=report_id,AttributeType=S \
    --key-schema \
        AttributeName=report_id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST
```

### 3. SQS Queue

```bash
# Main queue
aws sqs create-queue --queue-name bastion-analysis-queue

# Dead letter queue (for failed messages)
aws sqs create-queue --queue-name bastion-analysis-dlq

# Configure DLQ on main queue
aws sqs set-queue-attributes \
    --queue-url https://sqs.us-east-1.amazonaws.com/123456789012/bastion-analysis-queue \
    --attributes '{
        "RedrivePolicy": "{\"deadLetterTargetArn\":\"arn:aws:sqs:us-east-1:123456789012:bastion-analysis-dlq\",\"maxReceiveCount\":\"3\"}"
    }'
```

### 4. EventBridge Rule

```bash
# Trigger on CloudTrail events
aws events put-rule \
    --name bastion-cloudtrail-trigger \
    --event-pattern '{
        "source": ["aws.cloudtrail"],
        "detail-type": ["AWS API Call via CloudTrail"]
    }'

# Add Lambda target
aws events put-targets \
    --rule bastion-cloudtrail-trigger \
    --targets "Id"="1","Arn"="arn:aws:lambda:us-east-1:123456789012:function:bastion-tier1-filter"
```

### 5. Lambda Functions

#### Lambda 1: Tier 1 Filter

```bash
# Package code
cd lambda_handlers
zip -r tier1_filter.zip tier1_filter_handler.py ../bastion

# Create function
aws lambda create-function \
    --function-name bastion-tier1-filter \
    --runtime python3.11 \
    --handler tier1_filter_handler.handler \
    --role arn:aws:iam::123456789012:role/bastion-lambda-role \
    --zip-file fileb://tier1_filter.zip \
    --memory-size 1536 \
    --timeout 300 \
    --environment Variables="{
        BASTION_USE_ML_CLASSIFIER=true,
        BASTION_SQS_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/123456789012/bastion-analysis-queue
    }"
```

#### Lambda 2: Analysis Handler

```bash
# Package code (includes all ML models)
zip -r trigger_handler.zip trigger_handler.py ../bastion

# Create function
aws lambda create-function \
    --function-name bastion-analysis-handler \
    --runtime python3.11 \
    --handler trigger_handler.handler \
    --role arn:aws:iam::123456789012:role/bastion-lambda-role \
    --zip-file fileb://trigger_handler.zip \
    --memory-size 2048 \
    --timeout 900 \
    --environment Variables="{
        BASTION_USE_ML_CLASSIFIER=true,
        BASTION_USE_SEMANTIC_EMBEDDINGS=true,
        BASTION_USE_LSTM_UBA=true,
        BASTION_USE_SEMANTIC_ANALYZER=true,
        BASTION_SEMANTIC_ANALYZER_THRESHOLD=0.8,
        GEMINI_API_KEY=your-key-here
    }"

# Add SQS trigger
aws lambda create-event-source-mapping \
    --function-name bastion-analysis-handler \
    --event-source-arn arn:aws:sqs:us-east-1:123456789012:bastion-analysis-queue \
    --batch-size 5
```

### 6. Lambda Layers (Optional, for faster cold starts)

Package PyTorch + transformers as Lambda layer:

```bash
# Create layer directory
mkdir -p python/lib/python3.11/site-packages

# Install dependencies
pip install torch transformers sentence-transformers -t python/lib/python3.11/site-packages

# Zip layer
zip -r ml-layer.zip python

# Create layer
aws lambda publish-layer-version \
    --layer-name bastion-ml-layer \
    --zip-file fileb://ml-layer.zip \
    --compatible-runtimes python3.11

# Attach to Lambda
aws lambda update-function-configuration \
    --function-name bastion-analysis-handler \
    --layers arn:aws:lambda:us-east-1:123456789012:layer:bastion-ml-layer:1
```

### 7. EFS Mount (Optional, for model caching)

Pre-load trained models to EFS for faster cold starts:

```bash
# Create EFS
aws efs create-file-system --tags Key=Name,Value=bastion-models

# Mount to Lambda
aws lambda update-function-configuration \
    --function-name bastion-analysis-handler \
    --file-system-configs Arn=arn:aws:elasticfilesystem:us-east-1:123456789012:access-point/fsap-xxx,LocalMountPath=/mnt/models

# Copy models to EFS
# (from EC2 instance with EFS mounted)
cp ~/.cache/bastion/models/* /mnt/efs/bastion/models/
```

---

## Alternative: ECS Fargate Deployment

For production workloads without Lambda timeout limits:

### 1. Create Docker Image

```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy code
COPY bastion/ ./bastion/
COPY lambda_handlers/ ./lambda_handlers/
COPY scripts/ ./scripts/

# Pre-download models (optional)
RUN python -c "from bastion.models.ml_models import get_phishing_classifier; get_phishing_classifier()"
RUN python -c "from bastion.vector_store.embeddings import get_text_embedding; get_text_embedding('test')"

# Entry point
CMD ["python", "lambda_handlers/trigger_handler.py"]
```

### 2. Build & Push to ECR

```bash
# Build image
docker build -t bastion-analyzer .

# Tag for ECR
docker tag bastion-analyzer:latest 123456789012.dkr.ecr.us-east-1.amazonaws.com/bastion-analyzer:latest

# Push to ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 123456789012.dkr.ecr.us-east-1.amazonaws.com
docker push 123456789012.dkr.ecr.us-east-1.amazonaws.com/bastion-analyzer:latest
```

### 3. Create ECS Task Definition

```json
{
  "family": "bastion-analyzer",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "4096",
  "containerDefinitions": [
    {
      "name": "bastion-analyzer",
      "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/bastion-analyzer:latest",
      "environment": [
        {"name": "BASTION_USE_ML_CLASSIFIER", "value": "true"},
        {"name": "BASTION_USE_SEMANTIC_ANALYZER", "value": "true"},
        {"name": "GEMINI_API_KEY", "value": "your-key-here"}
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/bastion-analyzer",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

### 4. Trigger from SQS

Use EventBridge Pipes or Lambda to trigger ECS tasks from SQS:

```python
# Lambda trigger for ECS
import boto3

ecs = boto3.client("ecs")

def handler(event, context):
    for record in event["Records"]:
        body = json.loads(record["body"])
        
        # Launch ECS task
        ecs.run_task(
            cluster="bastion-cluster",
            taskDefinition="bastion-analyzer",
            launchType="FARGATE",
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": ["subnet-xxx"],
                    "securityGroups": ["sg-xxx"],
                    "assignPublicIp": "ENABLED",
                }
            },
            overrides={
                "containerOverrides": [{
                    "name": "bastion-analyzer",
                    "environment": [
                        {"name": "EVENT_PAYLOAD", "value": json.dumps(body)}
                    ]
                }]
            }
        )
```

---

## Monitoring & Alerts

### CloudWatch Metrics

```bash
# Lambda invocations
aws cloudwatch get-metric-statistics \
    --namespace AWS/Lambda \
    --metric-name Invocations \
    --dimensions Name=FunctionName,Value=bastion-analysis-handler \
    --start-time 2024-03-17T00:00:00Z \
    --end-time 2024-03-17T23:59:59Z \
    --period 3600 \
    --statistics Sum

# Lambda errors
aws cloudwatch get-metric-statistics \
    --namespace AWS/Lambda \
    --metric-name Errors \
    --dimensions Name=FunctionName,Value=bastion-analysis-handler \
    --start-time 2024-03-17T00:00:00Z \
    --end-time 2024-03-17T23:59:59Z \
    --period 3600 \
    --statistics Sum
```

### Custom Metrics (via CloudWatch Logs Insights)

```sql
-- ML model usage distribution
fields @timestamp, agent, model_type, inference_time
| filter @message like /semantic_analyzer|bert_classifier|lstm_uba/
| stats count() by model_type

-- Semantic analyzer confidence distribution
fields @timestamp, confidence, fallback_to_llm
| filter @message like /semantic_complete/
| stats avg(confidence), count() by bin(5m)

-- Cost analysis (LLM vs Semantic)
fields @timestamp, agent, used_llm
| filter agent in ["email_analyst", "forensic_analyst"]
| stats count() by used_llm
```

### Alarms

```bash
# High error rate
aws cloudwatch put-metric-alarm \
    --alarm-name bastion-high-error-rate \
    --alarm-description "BASTION Lambda error rate > 5%" \
    --metric-name Errors \
    --namespace AWS/Lambda \
    --statistic Average \
    --period 300 \
    --threshold 0.05 \
    --comparison-operator GreaterThanThreshold \
    --evaluation-periods 2

# DLQ messages (failed processing)
aws cloudwatch put-metric-alarm \
    --alarm-name bastion-dlq-messages \
    --alarm-description "Messages in DLQ" \
    --metric-name ApproximateNumberOfMessagesVisible \
    --namespace AWS/SQS \
    --statistic Sum \
    --period 300 \
    --threshold 1 \
    --comparison-operator GreaterThanThreshold \
    --evaluation-periods 1
```

---

## Cost Optimization

### Tier 1 Optimization (Immediate)

**Enable ML classifiers** to reduce Tier 2 escalations:

```bash
BASTION_USE_ML_CLASSIFIER=true      # 60% false positive reduction
BASTION_USE_LSTM_UBA=true           # Better anomaly detection
```

**Impact**: 
- 40-50% fewer events reach Tier 2 (LLM)
- Cost reduction: ~30-40%

### Tier 2 Optimization (After Training)

**Enable semantic analyzer** to replace LLM:

```bash
BASTION_USE_SEMANTIC_ANALYZER=true
BASTION_SEMANTIC_ANALYZER_THRESHOLD=0.8
```

**Impact**:
- 70-80% of Tier 2 analyses use semantic analyzer (no LLM)
- 20-30% fallback to LLM (complex cases)
- Cost reduction: 70-80% on Tier 2
- **Total cost reduction: 85-90% vs pure LLM**

### Provisioned Concurrency vs On-Demand

| Configuration | Cold Start | Cost | Use Case |
|---------------|------------|------|----------|
| On-demand | 2-5s (model load) | Low | Development, low traffic |
| Provisioned (2-5 instances) | 0ms | Medium | Production, consistent traffic |
| EFS mount | 500ms (model load from EFS) | Medium | Production, high traffic |

**Recommendation**: Provisioned concurrency for production (better UX, predictable latency)

---

## Security Considerations

### IAM Roles

**Lambda Execution Role** needs:
- `s3:GetObject` on data lake bucket
- `dynamodb:PutItem`, `dynamodb:GetItem` on results table
- `sqs:SendMessage`, `sqs:ReceiveMessage` on analysis queue
- `athena:StartQueryExecution`, `athena:GetQueryResults` on CloudTrail database
- `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::bastion-data-lake/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:PutItem",
        "dynamodb:GetItem",
        "dynamodb:Query"
      ],
      "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/bastion-results"
    },
    {
      "Effect": "Allow",
      "Action": [
        "sqs:SendMessage",
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage"
      ],
      "Resource": "arn:aws:sqs:us-east-1:123456789012:bastion-analysis-queue"
    },
    {
      "Effect": "Allow",
      "Action": [
        "athena:StartQueryExecution",
        "athena:GetQueryResults",
        "athena:GetQueryExecution"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

### Secrets Management

**DO NOT** hardcode API keys in Lambda environment variables.

Use **AWS Secrets Manager**:

```bash
# Store Gemini API key
aws secretsmanager create-secret \
    --name bastion/gemini-api-key \
    --secret-string "your-gemini-api-key-here"

# Store Pinecone API key
aws secretsmanager create-secret \
    --name bastion/pinecone-api-key \
    --secret-string "your-pinecone-api-key-here"

# Store VirusTotal API key (optional, for Threat Intel)
aws secretsmanager create-secret \
    --name bastion/virustotal-api-key \
    --secret-string "your-vt-api-key-here"

# Store AbuseIPDB API key (optional, for Threat Intel)
aws secretsmanager create-secret \
    --name bastion/abuseipdb-api-key \
    --secret-string "your-abuseipdb-api-key-here"
```

Update Lambda code to fetch from Secrets Manager:

```python
import boto3
import json

secrets = boto3.client("secretsmanager")

def get_secret(secret_name: str) -> str:
    response = secrets.get_secret_value(SecretId=secret_name)
    return response["SecretString"]

# In config.py or Lambda handler
gemini_api_key = get_secret("bastion/gemini-api-key")
pinecone_api_key = get_secret("bastion/pinecone-api-key")
```

**Gemini API Key**:
- Get your key: https://aistudio.google.com/app/apikey
- Free tier: 15 requests/minute, 1500 requests/day
- Paid tier: Higher rate limits, production usage
- Model: `gemini-2.5-flash` (fast, cost-effective) or `gemini-2.5-pro` (more capable)

---

## Rollback Plan

If ML models cause issues in production:

### Quick Rollback (Feature Flags)

```bash
# Disable all ML features
aws lambda update-function-configuration \
    --function-name bastion-analysis-handler \
    --environment Variables="{
        BASTION_USE_ML_CLASSIFIER=false,
        BASTION_USE_SEMANTIC_EMBEDDINGS=false,
        BASTION_USE_LSTM_UBA=false,
        BASTION_USE_SEMANTIC_ANALYZER=false
    }"
```

System will automatically fallback to:
- Pure regex rules (Email Tier 1)
- Hash-based embeddings (Vector Store)
- Isolation Forest only (Forensic Tier 1)
- Pure LLM ReAct (Tier 2)

### Gradual Rollback

Disable one component at a time to isolate issues:

```bash
# Test 1: Disable semantic analyzer only
BASTION_USE_SEMANTIC_ANALYZER=false

# Test 2: Disable LSTM UBA only
BASTION_USE_LSTM_UBA=false

# Test 3: Disable all Tier 2 ML
BASTION_USE_SEMANTIC_ANALYZER=false
```

---

## Performance Tuning

### Lambda Memory Optimization

Test different memory configurations:

```bash
# Test with 1024MB
aws lambda update-function-configuration \
    --function-name bastion-analysis-handler \
    --memory-size 1024

# Monitor duration and cost
aws cloudwatch get-metric-statistics \
    --namespace AWS/Lambda \
    --metric-name Duration \
    --dimensions Name=FunctionName,Value=bastion-analysis-handler \
    --start-time 2024-03-17T00:00:00Z \
    --end-time 2024-03-17T23:59:59Z \
    --period 3600 \
    --statistics Average,Maximum
```

**Recommendation**: 
- 1536MB: Minimum for full ML stack
- 2048MB: Recommended (better performance)
- 3008MB: If using large BERT models

### Semantic Analyzer Threshold Tuning

Adjust confidence threshold based on cost/accuracy tradeoff:

| Threshold | Semantic Usage | LLM Fallback | Cost | Accuracy |
|-----------|----------------|--------------|------|----------|
| 0.9 | 50-60% | 40-50% | Medium | High |
| 0.8 | 70-80% | 20-30% | Low | Good |
| 0.7 | 85-90% | 10-15% | Very Low | Moderate |

**Recommendation**: Start with 0.8, monitor false negatives, adjust as needed

---

## Checklist

### Pre-Deployment

- [ ] Train LSTM UBA model on historical CloudTrail logs
- [ ] Test all ML components with `scripts/test_ml_integration.py`
- [ ] Configure AWS infrastructure (S3, DynamoDB, SQS, EventBridge)
- [ ] Store API keys in Secrets Manager
- [ ] Set up CloudWatch alarms
- [ ] Configure DLQ for failed messages

### Post-Deployment

- [ ] Monitor Lambda cold start times
- [ ] Monitor ML model inference latency
- [ ] Track semantic analyzer confidence distribution
- [ ] Monitor LLM fallback rate
- [ ] Review DLQ for failed messages
- [ ] Collect LLM outputs for semantic analyzer training

### After 1-2 Months

- [ ] Export training data: `python scripts/export_training_data.py`
- [ ] Train semantic analyzer: `python scripts/train_semantic_analyzer.py`
- [ ] Evaluate model performance: `python scripts/visualize_semantic_analyzer.py`
- [ ] Enable semantic analyzer: `BASTION_USE_SEMANTIC_ANALYZER=true`
- [ ] Monitor cost reduction (should see 70-90% reduction)

---

## Troubleshooting

### Lambda Timeout Issues

**Symptom**: Lambda times out after 15 minutes

**Solutions**:
1. **Increase timeout** (max 15 minutes):
   ```bash
   aws lambda update-function-configuration \
       --function-name bastion-analysis-handler \
       --timeout 900
   ```

2. **Switch to ECS Fargate** (no timeout limit):
   - See "Alternative: ECS Fargate Deployment" section above
   - Recommended for production workloads

3. **Enable LangGraph checkpointing** (suspend/resume):
   ```python
   from langgraph.checkpoint.dynamodb import DynamoDBSaver
   checkpointer = DynamoDBSaver(table_name="bastion-checkpoints")
   graph.compile(checkpointer=checkpointer)
   ```

### Out of Memory Errors

**Symptom**: Lambda crashes with "MemoryError" or "Killed"

**Solutions**:
1. **Increase Lambda memory**:
   ```bash
   aws lambda update-function-configuration \
       --function-name bastion-analysis-handler \
       --memory-size 3008  # Maximum
   ```

2. **Disable ML features** to reduce memory footprint:
   ```bash
   # Disable semantic analyzer (saves ~420MB)
   BASTION_USE_SEMANTIC_ANALYZER=false
   
   # Disable BERT classifier (saves ~250MB)
   BASTION_USE_ML_CLASSIFIER=false
   ```

3. **Use Lambda layers** for dependencies:
   - Package PyTorch + transformers as layer
   - Reduces deployment package size
   - See "Lambda Layers" section above

### Cold Start Performance

**Symptom**: First invocation takes 5-10 seconds

**Solutions**:
1. **Enable provisioned concurrency**:
   ```bash
   aws lambda put-provisioned-concurrency-config \
       --function-name bastion-analysis-handler \
       --provisioned-concurrent-executions 5
   ```

2. **Use EFS mount** for model caching:
   - Pre-load models to EFS
   - Lambda reads from EFS (faster than downloading)
   - See "EFS Mount" section above

3. **Lazy loading** (already implemented):
   - Models only load when needed
   - Cached across warm invocations

### ML Model Issues

**Symptom**: "Model not found" or "Failed to load model"

**Solutions**:
1. **Check model cache**:
   ```bash
   # In Lambda, check /tmp/.cache/
   ls -lh /tmp/.cache/bastion/models/
   
   # Locally, check ~/.cache/
   ls -lh ~/.cache/bastion/models/
   ```

2. **Re-download models**:
   ```bash
   rm -rf ~/.cache/bastion/models/
   python -c "from bastion.models.ml_models import get_phishing_classifier; get_phishing_classifier()"
   ```

3. **Train LSTM model** (if not found):
   ```bash
   python scripts/generate_synthetic_cloudtrail.py --output logs.json --events 5000
   python scripts/train_lstm_uba.py --data logs.json --epochs 50
   ```

**Symptom**: Semantic analyzer gives random predictions

**Reason**: Models not trained yet (random initialization)

**Fix**: Collect LLM outputs for 1-2 months, then train:
```bash
python scripts/export_training_data.py --output training_data.json
python scripts/train_semantic_analyzer.py --data training_data.json --epochs 20
python scripts/visualize_semantic_analyzer.py  # Verify accuracy
```

### Pinecone Issues

**Symptom**: "Dimension mismatch: expected 128, got 384"

**Reason**: Semantic embeddings use 384 dimensions, old index uses 128

**Solutions**:
1. **Create new Pinecone index** with dimension=384:
   ```python
   import pinecone
   pinecone.create_index("bastion-phishing", dimension=384, metric="cosine")
   ```

2. **Disable semantic embeddings** (use hash-based):
   ```bash
   export BASTION_USE_SEMANTIC_EMBEDDINGS=false
   ```

**Symptom**: "Pinecone API rate limit exceeded"

**Solutions**:
- Upgrade Pinecone plan (free tier: 100 queries/day)
- Cache vector search results in DynamoDB
- Reduce vector search calls (only for high-confidence cases)

### Athena Query Timeout

**Symptom**: Athena queries take too long, Lambda times out

**Solutions**:
1. **Partition CloudTrail data** by date:
   ```sql
   CREATE EXTERNAL TABLE cloudtrail_partitioned (...)
   PARTITIONED BY (year STRING, month STRING, day STRING)
   ```

2. **Reduce query time range**:
   ```python
   # In forensic_analyst/tools.py
   time_range_hours = 6  # Instead of 24
   ```

3. **Use CloudTrail Insights** (pre-aggregated anomalies):
   - Enable CloudTrail Insights in AWS Console
   - Query Insights table instead of raw logs

### SQS Dead Letter Queue Messages

**Symptom**: Messages accumulating in DLQ

**Investigation**:
```bash
# Check DLQ messages
aws sqs receive-message \
    --queue-url https://sqs.us-east-1.amazonaws.com/123456789012/bastion-analysis-dlq \
    --max-number-of-messages 10

# Check Lambda error logs
aws logs tail /aws/lambda/bastion-analysis-handler --follow
```

**Common causes**:
- Malformed event payload
- Missing required fields
- Lambda timeout (increase timeout or switch to ECS)
- Unhandled exceptions (check CloudWatch Logs)

**Fix**:
1. Fix root cause (code bug, timeout, etc.)
2. Redrive messages from DLQ:
   ```bash
   aws sqs start-message-move-task \
       --source-arn arn:aws:sqs:us-east-1:123456789012:bastion-analysis-dlq \
       --destination-arn arn:aws:sqs:us-east-1:123456789012:bastion-analysis-queue
   ```

### Gemini API Issues

**Symptom**: "API key not valid" or "403 Forbidden"

**Solutions**:
1. **Verify API key**:
   ```bash
   # Test API key
   curl -H "Content-Type: application/json" \
        -H "x-goog-api-key: YOUR_API_KEY" \
        -d '{"contents":[{"parts":[{"text":"Hello"}]}]}' \
        https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent
   ```

2. **Check API key permissions**:
   - Visit: https://aistudio.google.com/app/apikey
   - Ensure key is not restricted to specific IPs/domains
   - Regenerate key if needed

3. **Verify environment variable**:
   ```bash
   echo $GEMINI_API_KEY
   # Should print your API key
   ```

**Symptom**: "Rate limit exceeded" or "429 Too Many Requests"

**Solutions**:
1. **Free tier limits**:
   - 15 requests/minute
   - 1500 requests/day
   - 1 million tokens/day

2. **Upgrade to paid tier**:
   - Visit: https://ai.google.dev/pricing
   - Enable billing in Google Cloud Console
   - Higher rate limits (60 req/min, 10k req/day)

3. **Implement rate limiting**:
   ```python
   import time
   from functools import wraps

   def rate_limit(calls_per_minute=15):
       min_interval = 60.0 / calls_per_minute
       last_called = [0.0]

       def decorator(func):
           @wraps(func)
           def wrapper(*args, **kwargs):
               elapsed = time.time() - last_called[0]
               left_to_wait = min_interval - elapsed
               if left_to_wait > 0:
                   time.sleep(left_to_wait)
               ret = func(*args, **kwargs)
               last_called[0] = time.time()
               return ret
           return wrapper
       return decorator
   ```

4. **Use SQS batching** (already implemented):
   - Tier 1 filters 90% events
   - SQS controls throughput
   - Reduces API calls significantly

**Symptom**: "Model not found" or "Invalid model name"

**Solutions**:
1. **Check model name** in `.env`:
   ```bash
   GEMINI_MODEL=gemini-2.5-flash  # Correct
   # NOT: gemini-pro, gemini-1.5-pro (old names)
   ```

2. **Available models**:
   - `gemini-2.5-flash`: Fast, cost-effective (recommended)
   - `gemini-2.5-pro`: More capable, slower, more expensive
   - `gemini-1.5-flash`: Legacy (still works)
   - `gemini-1.5-pro`: Legacy (still works)

**Symptom**: Slow response times (>10 seconds)

**Solutions**:
1. **Use gemini-2.5-flash** (faster than pro):
   ```bash
   GEMINI_MODEL=gemini-2.5-flash
   ```

2. **Reduce max_tokens**:
   ```bash
   GEMINI_MAX_TOKENS=4096  # Instead of 8192
   ```

3. **Enable semantic analyzer** (bypass LLM):
   ```bash
   BASTION_USE_SEMANTIC_ANALYZER=true
   # 10-20x faster (100-200ms vs 2-5s)
   ```

### High LLM Costs

**Symptom**: Monthly LLM bill higher than expected

**Investigation**:
```sql
-- Check LLM usage in CloudWatch Logs Insights
fields @timestamp, agent, used_semantic, used_llm
| filter agent in ["email_analyst", "forensic_analyst"]
| stats count() by agent, used_semantic, used_llm
```

**Solutions**:
1. **Enable semantic analyzer** (if not already):
   ```bash
   BASTION_USE_SEMANTIC_ANALYZER=true
   BASTION_SEMANTIC_ANALYZER_THRESHOLD=0.8
   ```

2. **Lower confidence threshold** (more semantic, less LLM):
   ```bash
   BASTION_SEMANTIC_ANALYZER_THRESHOLD=0.7  # 85-90% semantic usage
   ```

3. **Improve Tier 1 filtering** (drop more clean events):
   ```bash
   BASTION_USE_ML_CLASSIFIER=true
   BASTION_USE_LSTM_UBA=true
   ```

4. **Monitor false negatives** after changes:
   - Review sample of dropped events
   - Adjust thresholds if missing real threats

### False Positives/Negatives

**False Positives** (benign events flagged as threats):
- **Tier 1**: Adjust rule thresholds in `tier1_filter.py`
- **Tier 2**: Lower semantic analyzer threshold (more LLM fallback)
- **Retrain models** with corrected labels

**False Negatives** (real threats missed):
- **Tier 1**: Lower anomaly thresholds (more escalations)
- **Tier 2**: Raise semantic analyzer threshold (more LLM fallback)
- **Retrain models** with missed samples

**Feedback loop**:
```bash
# Export false positives/negatives
python scripts/export_training_data.py --include-corrections

# Retrain with corrected data
python scripts/train_semantic_analyzer.py --data corrected_data.json --epochs 10
```

---

## Support

For issues or questions:
- Check logs in CloudWatch Logs
- Review "Troubleshooting" section above
- See `Design.md` section 14 for testing guide
- See agent READMEs for component-specific details
