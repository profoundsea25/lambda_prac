import json

from pymongo import MongoClient
import boto3
import hashlib
from datetime import datetime, timedelta
import jwt


def get_secret():
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name="ap-northeast-2"
    )
    get_secret_value_response = client.get_secret_value(
        SecretId='cnvrt-mongoDB'
    )
    print(1)
    token = get_secret_value_response['SecretString']
    print(1)
    return eval(token)


def db_ops():
    secrets = get_secret()
    print(1)
    client = MongoClient("mongodb://{0}:{1}@{2}".format(secrets['user'], secrets['password'], secrets['host']))
    print(2)
    return client


def lambda_handler(event, context):
    secrets = get_secret()
    client = db_ops()
    db = client.dbrecipe
    secret = secrets['secret']
    body = json.loads(event['body'])
    email = body['email']
    password = body['password']
    pw_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    result = db.users.find_one({'EMAIL': email, 'PASSWORD': pw_hash})

    if event['httpMethod'] == 'OPTIONS':
        return {
            "statusCode": 200,
            'headers': {
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST'
            },
        }

    if result is not None:
        _id = str(result['_id'])
        payload = {
            'user_id': _id,
            'exp': datetime.utcnow() + timedelta(seconds=60 * 60 * 24)  # 로그인 24시간 유지
        }
        token = jwt.encode(payload, secret, "HS256")
        return {
            "statusCode": 200,
            'headers': {
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST'
            },
            "body": json.dumps({
                "result": "success",
                "token" : token
            }),
        }
    else:
        return {
            "statusCode": 401,
            'headers': {
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST'
            },
            "body": json.dumps({
                "result": "fail",
                "msg": '아이디/비밀번호가 일치하지 않습니다.'
            }),
        }
