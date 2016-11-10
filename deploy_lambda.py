#standart packages
import sys
import json
import base64
import time
import random
import datetime
import calendar
import hashlib
import time
import zipfile
import os

#non standart packages
import boto3

AWS_ID = "123123123"
ROLE_NAME = "Test_Approove"
DEFAULT_ROLE = "arn:aws:iam::%s:role/%s"%(AWS_ID,ROLE_NAME)
DEFAULT_NAME = "exampleApprooveGateway"
REGION="eu-west-1"
LAMBDA_DIR="./customauthorizer/"
LAMBDA_SOURCE="%slambda.zip"%(LAMBDA_DIR)

def zip_dir(path):
	os.system("cd %s; zip -r lambda.zip ./"%(LAMBDA_DIR))	

def sid_gen(): #simple sid generator
	r = random.randint(1,1000000000)
	ut = calendar.timegm(time.gmtime())
	s256 = hashlib.sha256()
	s256.update(str(r).encode("utf-8")+str(ut).encode("utf-8"))
	return s256.hexdigest()

#Some tips how to use python and aws
#https://aws.amazon.com/sdk-for-python/

s3 = boto3.resource('s3')
for bucket in s3.buckets.all():
	print(bucket.name)

awslambda = boto3.client('lambda')
apigateway = boto3.client('apigateway')

zip_dir(LAMBDA_DIR)
f = open(LAMBDA_SOURCE,"rb")
f_data = f.read()
f.close()

#Create/upload lambda function
response_lambda = awslambda.create_function(
	FunctionName = DEFAULT_NAME,
	Runtime = 'python2.7',
	Handler = 'lambda_function.lambda_handler',
	Role = DEFAULT_ROLE,
	Code = {
		'ZipFile': f_data
	},
	MemorySize = 128,
	Publish = True,
	Description = 'Approove authorizer gateway',
	Timeout = 300
)
print(response_lambda)

#create rest api
response_restapi = apigateway.create_rest_api(
	name = 'approoveApi'
)
print(response_restapi)

#create api gateway
response_auth = apigateway.create_authorizer(
	restApiId = response_restapi["id"],
	name = "exampleApprooveAuthorizer",
	type = "TOKEN",
	identitySource = 'method.request.header.Authorization',
	authorizerUri='arn:aws:apigateway:%s:lambda:path/2015-03-31/functions/arn:aws:lambda:%s:%s:function:%s/invocations'%(REGION,REGION,AWS_ID,DEFAULT_NAME),
	authorizerResultTtlInSeconds = 300
)

#create new lambda policy for apigateway
response_policy = awslambda.add_permission(
	FunctionName = DEFAULT_NAME,
	StatementId = sid_gen(),
	Action = 'lambda:InvokeFunction',
	Principal = 'apigateway.amazonaws.com',
	SourceArn = 'arn:aws:execute-api:%s:%s:%s/authorizers/%s'%(REGION,AWS_ID,response_restapi["id"],
		response_auth["id"])
)


