import json
import boto3
from pymongo import MongoClient
from datetime import datetime, timedelta
import hashlib
import jwt  # pip install PyJWT
import os

def get_secret():
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name="ap-northeast-2"
    )
    get_secret_value_response = client.get_secret_value(
        SecretId='pymongo-secret-01'
    )
    token = get_secret_value_response['SecretString']
    return eval(token)

# MongoDB
secrets = get_secret()

client = MongoClient("mongodb://{0}:{1}@{2}".format(secrets['user'],secrets['password'],secrets['host']))
db = client.dbrecipe

def lambda_handler(event, context):
    try:
        if event['httpMethod'] == 'OPTIONS':
            body = json.dumps({
                "message": "success",
            })
        else:
            data = json.loads(event['body'])

            email = data['email']
            password = data['password']

            pw_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
            result = db.users.find_one({'EMAIL': email, 'PASSWORD': pw_hash})

            if result is not None:
                _id = str(result['_id'])
                payload = {
                    'user_id': _id,
                    'exp': datetime.utcnow() + timedelta(seconds=60 * 60 * 24)  # 로그인 24시간 유지
                }
                token = jwt.encode(payload, os.environ["JWT_SECRET_KEY"], algorithm='HS256')

                return {
                    "statusCode": 200,
                    'headers': {
                        'Access-Control-Allow-Headers': 'Content-Type',
                        'Access-Control-Allow-Origin': '*',
                        'Access-Control-Allow-Methods': 'OPTIONS,POST'
                    },
                    "body": json.dumps({
                        "result": "success",
                        "token": token
                    })
                }

            else:
                return {
                    "body": json.dumps({
                        "result": "fail",
                        "msg": "아이디/비밀번호가 일치하지 않습니다."
                    })
                }

        return {
            "statusCode": 200,
            # Cross Origin처리
            'headers': {
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST'
            },
            "body": body,
        }
    except Exception as e:
        print(e)
        return {
            "statusCode": 500,
            # Cross Origin처리
            'headers': {
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST'
            },
            "body": json.dumps({
                "message": "fail",
            }),
        }