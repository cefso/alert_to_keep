# -*- coding: utf-8 -*-
import logging
import json
import base64

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
    print(dir(event))

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

    logger.info("接收到的body: %s", req_body)

    # 判断body是否为base64编码数据
    if 'isBase64Encoded' in event and event['isBase64Encoded']:
        req_body = base64.b64decode(req_body).decode("utf-8")

    logger.info("完成事件处理...")

    return {
        'statusCode': 200,
        'headers': {'Content-Type': 'text/plain'},
        'isBase64Encoded': False,
        'body': req_body
    }
