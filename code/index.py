# -*- coding: utf-8 -*-
import base64
import datetime
import hashlib
import json
import logging
import os
from urllib.parse import parse_qs

import pytz
import requests

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

    url_path = event_json.get('rawPath', "")

    # 根据url path判断是那种类型告警
    match url_path:
        case "/alert/cms":
            logger.info("告警类型为cms")
            return process_event_cms(event_json)
        case "/alert/arms":
            logger.info("告警类型为arms")
            return process_event_cms(event_json)
        case _:
            logger.info("未知告警类型")
            return {
                'statusCode': 200,
                'headers': {'Content-Type': 'text/plain'},
                'isBase64Encoded': False,
                'body': {'message': '未知的告警类型'}
            }


def process_event_cms(event):
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
    else:
        params = req_body

    logger.info("接收到的body: %s", params)

    if 'eventTime' in params:
        # 处理cms事件告警
        params = cover_to_keep_cms_event(params)
    else:
        # 处理cms时序指标告警
        params = cover_to_keep_cms(params)

    logger.info("完成事件处理...")

    # 发送消息到keep
    response = send_to_keep(params)

    return {
        'statusCode': 200,
        'headers': {'Content-Type': 'text/plain'},
        'isBase64Encoded': False,
        'body': response
    }


# cms时序指标告警消息转换为keep
def cover_to_keep_cms(message):
    status = 'firing' if message['alertState'][0] == 'ALERT' else 'resolved'
    logger.info("cms告警的状态为: %s", status)
    last_received = cms_timestamp_to_formatted_time(message['timestamp'][0])
    source = 'cms-' + message['userId'][0]
    desc = message['instanceName'][0] + ',' + message['metricName'][0] + '大于' + message['curValue'][0]
    fingerprint = calculate_hash(message['metricName'][0] + message['instanceName'][0] + message['metricProject'][0])
    msg = {
        "id": message['ruleId'][0],
        "name": message['alertName'][0],
        "status": status,
        "lastReceived": last_received,
        "environment": message['metricProject'][0],
        "duplicateReason": "null",
        "service": message['metricProject'][0],
        "source": [source],
        "message": desc,
        "description": desc,
        "severity": message['preTriggerLevel'][0],
        "pushed": True,
        "url": "https://keephq.cefso.online",
        "labels": {
            "regionId": message['regionId'][0],
            "regionName": message['regionName'][0],
            "rawMetricName": message['rawMetricName'][0],
            "metricName": message['metricName'][0],
            "curValue": message['curValue'][0],
            "instanceName": message['instanceName'][0],
            "metricProject": message['metricProject'][0],
        },
        "ticket_url": "https://keephq.cefso.online",
        "fingerprint": fingerprint,
    }
    logger.info("转换后的数据为: %s", msg)
    return msg

# cms事件告警消息转换为keep
def cover_to_keep_cms_event(message):
    source = 'cms-' + message['userId'][0]
    desc = message['instanceName'] + ',' + message['name']
    fingerprint = calculate_hash(message['name'] + message['product'])
    msg = {
        "id": message['ruleId'],
        "name": message['name'],
        "status": 'firing',
        "lastReceived": message['eventTime'],
        "environment": message['metricProject'][0],
        "duplicateReason": "null",
        "service": message['metricProject'][0],
        "source": [source],
        "message": desc,
        "description": desc,
        "severity": message['preTriggerLevel'][0],
        "pushed": True,
        "url": "https://keephq.cefso.online",
        "labels": {
            message['content']
        },
        "ticket_url": "https://keephq.cefso.online",
        "fingerprint": fingerprint,
    }
    logger.info("转换后的数据为: %s", msg)
    return msg


# cms时间戳转换为keep格式
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


# 发送消息到keep
def send_to_keep(message):
    keep_url = os.environ.get('KEEPURL')
    keep_api_key = os.environ.get('KEEPAPIKEY')

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-API-KEY": keep_api_key
    }

    response = requests.post(keep_url, headers=headers, json=message)

    logger.info("消息转发到keep成功")

    logger.info(response.json())

    return response.json()


# 计算告警指纹
def calculate_hash(text: str, algorithm: str = 'sha256'):
    """
    计算字符串的哈希值
    :param text: 原始字符串
    :param algorithm: 哈希算法（支持: md5, sha1, sha224, sha256, sha384, sha512）
    :return: 十六进制哈希值
    """
    # 创建哈希对象
    hasher = hashlib.new(algorithm)

    # 更新哈希值（必须将字符串编码为字节）
    hasher.update(text.encode('utf-8'))

    # 返回十六进制结果
    return hasher.hexdigest()
