from pyspark.sql import SparkSession
from dotenv import load_dotenv
import os
import sys

# Load .env variables
load_dotenv()

# AWS credentials
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")

# RDS credentials
RDS_HOST = os.getenv("RDS_HOST")
RDS_PORT = os.getenv("RDS_PORT")
RDS_DB = os.getenv("RDS_DB")
RDS_USER = os.getenv("RDS_USER")
RDS_PASSWORD = os.getenv("RDS_PASSWORD")

jdbc_url = f"jdbc:postgresql://{RDS_HOST}:{RDS_PORT}/{RDS_DB}"

# Initialize Spark
spark = SparkSession.builder \
    .appName("URLShield-ETL-FreeTier") \
    .config("spark.driver.memory", "500m") \
    .config("spark.sql.shuffle.partitions", "1") \
    .config("spark.ui.enabled", "false") \
    .config("spark.hadoop.fs.s3a.access.key", AWS_ACCESS_KEY) \
    .config("spark.hadoop.fs.s3a.secret.key", AWS_SECRET_KEY) \
    .config("spark.hadoop.fs.s3a.impl", "org.apache.hadoop.fs.s3a.S3AFileSystem") \
    .config("spark.hadoop.fs.s3a.endpoint", "s3.eu-north-1.amazonaws.com") \
    .config("spark.hadoop.fs.s3a.path.style.access", "true") \
    .getOrCreate()

try:
    print("Connecting to RDS...")
    df = spark.read.format("jdbc") \
        .option("url", jdbc_url) \
        .option("dbtable", "phishing_data") \
        .option("user", RDS_USER) \
        .option("password", RDS_PASSWORD) \
        .option("driver", "org.postgresql.Driver") \
        .option("fetchsize", "10000") \
        .load()

    # Transform
    df_clean = df.dropna().dropDuplicates()

    # Load to S3
    s3_destination = "s3a://urlshield-data-lake/cleaned_data/"
    print("Starting write to S3...")
    df_clean.write.mode("overwrite").parquet(s3_destination)

    print("ETL complete! Data saved to S3.")

except Exception as e:
    print(f"Error occurred: {e}")
    sys.exit(1)

finally:
    spark.stop()
