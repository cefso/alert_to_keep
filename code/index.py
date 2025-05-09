# -*- coding: utf-8 -*-
import os
import base64
import datetime
import json
import logging
from urllib.parse import parse_qs

import requests
import pytz

logger = logging.getLogger()


def handler(event, context):
    logger.info("接收到的event: %s", event)

    # event为bytes转换为dict
    try:
        event_json = json.loads(event)
    except:
        return "The request did not come from an HTTP Trigger because the event is not a json string, event: {}".format(
            event)

    # 判断是否有body
    if "body" not in event_json:
        return "The request did not come from an HTTP Trigger because the event does not include the 'body' field, event: {}".format(
            event)

    result = process_event(event_json)

    return result


def process_event(event):
    logger.info("开始事件处理...")

    req_header = event['headers']
    logger.info("接收到的headers: %s", req_header)

    # 判断body是否为空
    req_body = event['body']

    if not req_body:
        logger.info("本次接收到的body为空")
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'text/plain'},
            'isBase64Encoded': False,
            'body': {
                'message': 'body is empty'
            }
        }

    # 判断body是否为base64编码数据
    if 'isBase64Encoded' in event and event['isBase64Encoded']:
        logger.info("开始解码Base64内容")
        req_body = base64.b64decode(req_body).decode("utf-8")

    params = parse_qs(req_body)

    logger.info("接收到的body: %s", params)

    params = cover_to_keep(params)

    logger.info("完成事件处理...")

    response = send_to_keep(params)

    return {
        'statusCode': 200,
        'headers': {'Content-Type': 'text/plain'},
        'isBase64Encoded': False,
        'body': json.dumps(response)
    }


def cover_to_keep(message):
    status = 'firing' if message['alertState'][0] == 'ALERT' else 'resolved'
    logger.info("cms告警的状态为: %s", status)
    last_received = cms_timestamp_to_formatted_time(message['timestamp'][0])
    source = 'cms-' + message['userId'][0]
    desc = message['metricName'][0] + '大于' + message['curValue'][0]
    msg = {
        "id": message['ruleId'][0],
        "name": message['alertName'][0],
        "status": status,
        "lastReceived": last_received,
        "environment": message['metricProject'],
        "duplicateReason": "null",
        "service": "backend",
        "source": [source],
        "message": desc,
        "description": desc,
        "severity": message['preTriggerLevel'][0],
        "pushed": True,
        "url": "https://www.keephq.dev?alertId=1234",
        "labels": {
            "regionId": message['regionId'][0],
            "regionName": message['regionName'][0],
            "rawMetricName": message['rawMetricName'][0],
            "metricName": message['metricName'][0],
            "curValue": message['curValue'][0],
            "instanceName": message['instanceName'][0],
            "metricProject": message['metricProject'][0],
        },
        "ticket_url": "https://www.keephq.dev?enrichedTicketId=456",
        "fingerprint": message["signature"],
    }
    logger.info("转换后的数据为: %s", msg)
    return msg


def cms_timestamp_to_formatted_time(timestamp):
    # 时间戳（毫秒）
    timestamp_ms = int(timestamp)

    # 转换为秒
    timestamp_s = timestamp_ms / 1000

    # 转换为 UTC 时间的 datetime 对象
    dt = datetime.datetime.fromtimestamp(timestamp_s, tz=pytz.UTC)

    # 格式化：年-月-日T时:分:秒.毫秒Z
    formatted_time = dt.strftime('%Y-%m-%dT%H:%M:%S') + f'.{dt.microsecond // 1000:03d}Z'

    logger.info("cms告警的时间为: %s", formatted_time)

    return formatted_time


def send_to_keep(message):
    keep_url = os.environ.get('KEEPURL')
    keep_api_key = os.environ.get('KEEPAPIKEY')

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-API-KEY": keep_api_key
    }
    data = message

    response = requests.post(keep_url, headers=headers, data=data)

    logger.info("消息转发到keep成功")

    return response
