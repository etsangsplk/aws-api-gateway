# Deploying Approov on AWS

## Setting up user

## AWS Shell

### Download aws-shell

```
pip install aws-shell
```

### Getting access keys

Get access key for AWS-CLI

[More Docs](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-set-up.html)

Key will look something like

```
Access Key ID: EXAMPLESFODNN7EXAMPLE
Secret Access Key: EXAMPLEtnFEMI/EXAMPLE/EXAMPLEiCYEXAMPLEKEY
```

### Setup access keys trought cli interface

Run:

```
aws configure
```

Setting up keys inside aws shell. Dont settup correct region name and format (json)

```
AWS Access Key ID [****************AAAA]: 
AWS Secret Access Key [****************BBB]: 
Default region name [eu-west-1]: 
Default output format [json]: 
```

Ok now we are ready to mess around AWS. 

### Check lambdas

Check lambdas that are allready there

```
aws lambda list-functions | grep FunctionName
```

### Create new lambda

If you need create lambda lets create one with Approov default lambda.
Choose your lambda name, get rolle permission ARN string, and choose lambda.zip
from example repository

```
aws lambda create-function 
--function-name [LAMBDA_NAME] --runtime python2.7 --description "Lambda for API Gateway" --role [ARN_ROLE] --handler lambda_function.lambda_handler --zip-file fileb://./lambda.zip
```

ARN role could look like

```
arn:aws:iam::[AWSID]:role/[ROLE_NAME] 
```
If everything when ok then you will get as output this kind of json

Output:
```
aws lambda create-function --function-name awsomeApprooveGateway --runtime python2.7 --description "Lambda for API Gateway" --role [ARN_ROLE] --handler lambda_function.lambda_handler --zip-file fileb://./lambda.zip
{
    "Version": "$LATEST",
    "Timeout": 3,
    "CodeSha256": "lR7q14ecVMw/2iXLJ7qU7HIBwF32ROUVDa/VfGiDLBw=",
    "Description": "Lambda for API Gateway",
    "Runtime": "python2.7",
    "Handler": "lambda_function.lambda_handler",
    "CodeSize": 57591,
    "FunctionName": "awsomeApprooveGateway",
    "MemorySize": 128,
    "LastModified": "2011-11-11T11:11:11.111+0000",
    "Role": "arn:aws:iam::[AWS_ID]:role/[ROLE]",
    "FunctionArn": "arn:aws:lambda:eu-west-1:[AWS_ID]:function:awsomeApprooveGateway"
}
```

### Create Api for API Gateway

List API's

``
aws apigateway get-rest-apis | grep name`
```

Check if one excists

## Adding access permissions for Lambda

```
aws lambda add-permission --function-name awsomeApprooveGateway --statment-id 123456789 --action 'lambda:InvokeFunction' --principial 'apigateway.amazonaws.com' --source-arn 'arn:aws:execute-api:eu-west-1:123123123123:wy45u234231/authorizers/authorizer_id'
```

