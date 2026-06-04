import json
import boto3
from src.lambda_worker import lambda_handler
from src.config import get_settings

def test_local_queue_consumption():
    settings = get_settings()
    
    # Initialize AWS SQS client using your local credentials profile
    sqs = boto3.client('sqs', region_name=settings.aws_region)
    
    print("📥 Polling a test message from your AWS SQS Queue...")
    response = sqs.receive_message(
        QueueUrl=settings.sqs_queue_url,
        MaxNumberOfMessages=1,
        WaitTimeSeconds=5
    )
    
    messages = response.get('Messages', [])
    if not messages:
        print("❌ The queue is empty. Make sure ingest_to_sqs completed successfully.")
        return
        
    msg = messages[0]
    print(f"✅ Found message! MessageID: {msg['MessageId']}")
    
    # Re-wrap the SQS text payload into a simulated AWS Lambda trigger event envelope
    mock_event = {
        "Records": [{
            "body": msg['Body'],
            "receiptHandle": msg['ReceiptHandle']
        }]
    }
    
    print("\n⚙️ Invoking Bedrock Specialist and Central Normalizer...")
    try:
        result = lambda_handler(mock_event, None)
        print(f"✨ Status Code: {result['statusCode']} | Record processed successfully!")
        
        # Delete the message from SQS so it isn't processed again
        sqs.delete_message(QueueUrl=settings.sqs_queue_url, ReceiptHandle=msg['ReceiptHandle'])
        print("🗑️ Message successfully removed from SQS Queue.")
        
    except Exception as e:
        print(f"❌ Worker Execution Failed: {str(e)}")

if __name__ == "__main__":
    test_local_queue_consumption()