import boto3
from botocore.exceptions import NoCredentialsError, ClientError
from dotenv import load_dotenv
import os
import sys

# Load .env variables
load_dotenv()

# AWS credentials
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")

def download_url_dataset():
    # Configuration from your link
    bucket_name = 'urlshield-data-lake'
    s3_key = 'cleaned_data/part-00000-fb32e62b-1795-4bd3-9080-9fb139d0fdd9-c000.snappy.parquet'
    local_filename = 'url_dataset.parquet'
    
    # Initialize S3 client for the specific region
    s3 = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name='eu-north-1'
    )
    
    try:
        print(f"Attempting to download from {bucket_name}...")
        s3.download_file(bucket_name, s3_key, local_filename)
        print(f"Successfully downloaded to: {local_filename}")
        
    except NoCredentialsError:
        print("Credentials not found. Please run 'aws configure'.")
    except ClientError as e:
        if e.response['Error']['Code'] == "403":
            print("Access Denied: You don't have permission to this bucket.")
        else:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    download_url_dataset()