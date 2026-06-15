import os
import time
import boto3
from src.lambda_worker import lambda_handler
from src.config import get_settings

def run_continuous_worker():
    settings = get_settings()
    aws_region = os.environ.get("AWS_REGION", "us-east-1")
    sqs = boto3.client('sqs', region_name=aws_region)
    
    print("🚀 Rate limit run worker active. Processing SQS Queue...")
    
    empty_polls = 0
    while True:
        response = sqs.receive_message(
            QueueUrl=settings.sqs_queue_url,
            MaxNumberOfMessages=5,  # Slightly lower batch size to ease concurrency spikes
            WaitTimeSeconds=10       
        )
        
        messages = response.get('Messages', [])
        if not messages:
            empty_polls += 1
            print(f"😴 Queue appears empty. Waiting... (Poll count: {empty_polls})")
            if empty_polls >= 3:
                print("🏁 Queue fully drained. All items normalized!")
                break
            continue
            
        empty_polls = 0
        print(f"\n📥 Found {len(messages)} threat records. Processing...")
        
        for msg in messages:
            mock_event = {"Records": [{"body": msg['Body'], "receiptHandle": msg['ReceiptHandle']}]}
            
            retry_count = 0
            max_retries = 4
            backoff_delay = 4  # Start with a 4-second delay if throttled
            
            while retry_count < max_retries:
                try:
                    lambda_handler(mock_event, None)
                    sqs.delete_message(QueueUrl=settings.sqs_queue_url, ReceiptHandle=msg['ReceiptHandle'])
                    
                    # 💡 Crucial: Add a minor 1-second breathing room pause between successful model calls
                    time.sleep(1) 
                    break  # Success! Break out of the retry loop for this message
                    
                except Exception as e:
                    error_str = str(e)
                    if "ThrottlingException" in error_str or "Too many requests" in error_str:
                        retry_count += 1
                        print(f"⏳ Bedrock is rate-limiting. Backing off for {backoff_delay}s (Retry {retry_count}/{max_retries})...")
                        time.sleep(backoff_delay)
                        backoff_delay *= 2  # Double the wait time for the next attempt
                    else:
                        print(f"⚠️ Skipping message due to non-throttling node error: {e}")
                        break  # Don't retry unique code errors
                
if __name__ == "__main__":
    run_continuous_worker()