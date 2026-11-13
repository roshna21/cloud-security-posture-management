"""Drift trigger (AWS Lambda).

EventBridge invokes this function when AWS Config records a configuration
change, or when CloudTrail logs one of the watched API calls. It reduces the
event to the few fields the drift engine needs and puts it on an SQS queue.
The core engine (`python -m cspm drift watch`) reads the queue and runs a scan
straight away, so drift is detected in near real time instead of on a timer.

Environment: QUEUE_URL
"""
import json
import os

import boto3

sqs = boto3.client("sqs")


def handler(event, context):
    detail = event.get("detail", {})
    if event.get("source") == "aws.config":
        item = detail.get("configurationItem", {})
        message = {
            "kind": "config_change",
            "resource_type": item.get("resourceType") or detail.get("resourceType"),
            "resource_id": item.get("resourceId") or detail.get("resourceId"),
            "change_type": detail.get("messageType"),
            "time": event.get("time"),
        }
    else:  # CloudTrail API call delivered through EventBridge
        identity = detail.get("userIdentity", {})
        message = {
            "kind": "api_call",
            "event_name": detail.get("eventName"),
            "user": identity.get("userName") or identity.get("arn"),
            "source_ip": detail.get("sourceIPAddress"),
            "time": detail.get("eventTime") or event.get("time"),
        }
    sqs.send_message(QueueUrl=os.environ["QUEUE_URL"], MessageBody=json.dumps(message))
    return {"forwarded": True, "kind": message["kind"]}
