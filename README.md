Delivering graphs of realtime activity to customers should be fairly [[graphs_for_customers | simple]].

# Running Deploy Script

Replace variables in deploy_lambda.py with your own

```python
AWS_ID = "123123123"
ROLE_NAME = "Test_Approove"
DEFAULT_ROLE = "arn:aws:iam::%s:role/%s"%(AWS_ID,ROLE_NAME)
DEFAULT_NAME = "exampleApprooveGateway"
REGION="eu-west-1"
```

# Using AWS shell

[SETUP_AWS_SHELL.md](SETUP_AWS_SHELL.md)

# AWS settup from web interface
## Requirements
### Services
To make everything work in AWS you need to have This Amazon services

```
CloudWatch
Lambda
ApiGateway
```

### Permissions
User Should have access to CloudWatch and should have permissions to create/delete/modify logs. Here is example of permissions
for Logging that are suggested for CloudWatch and Logging. Initial user where created with default Amazon predefined permissions

```
AWSLambdaFullAccess
CloudWatchFullAccess
AmazonAPIGatewayAdministrator
AWSLambdaExecute
```

```
ARN
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
                "logs:PutLogEvents",
                "logs:GetLogEvents",
                "logs:FilterLogEvents"
            ],
            "Resource": "*"
        }
    ]
}
```

The IAM role must also contain the following trust relationship statement:

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "apigateway.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

http://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-stage-settings.html

# Setup
## CloudWatch 
**Create Log** stream and attach to it **Lamda**

## ApiGateway ###
Allow ApiGateway to log inside CloudWatch

**ApiGateway->Settings->CloudWatch log role ARN** copy inside ARN with sufficient permissions.

## Lambda 
Setup lambda to log to CloudWatch

## Configuring realtime dashboard
Filters are used to search for patterns in log files. And **Filters** are applied 
to **Dashboard** where you can see results of Filtering.

### Filters
Go to **CloudWatch->Logs** select appropriate **LogGroup** connected to Lambda and choose "0 filters".

Then Click on "Add Metric Filter". Inside filter values define patter that 
matches FAILED/PASSED logs. Don't forget to check with "Test Pattern" button.

As there where added line to python lambda script

```
logger.info("Authorization DONE")
logger.error("Authorization FAILED")
```

Patterns for logging messages that you add to **Filter Pattern** field is
```
ERROR Authorization FAILED
```
or
```
INFO  Authorization DONE
```

There is 2 filters in total for failing and passing.


https://blog.opsgenie.com/2014/08/how-to-use-cloudwatch-to-generate-alerts-from-logs

### Dashboard
You can create Dashboard and it will show in realtime when filters match.

**CloudWatch->Metrics->LogMetrics**

Then choose in Log groups

Change **Log** to **LogMetrics** and select **Metric Groups** Where is located previously defined filters.
Select Filters that matches successful authentication/attestation and 
non-successful attestation/authentication.
After filters are selected press **"Add to Dashboard"** and new dashboard will 
appear in **CloudWatch->Dashboard**

## Testing trough Lambda

Open Page with **Lambda->Functions** select lambda function.

Near **Test** button click on **Action** selector and choose **Configure test event**.

In windows that popups in **Sample event template** select **API Gateway Authorizer**

In JSON change **"authorization field"** to Test token that is in **Test token**
section of this readme. Then press "Save and Test".

If everything OK you will see **Execution result: succeeded**

### Alternative test trought ApiGateway

Goto **API Gateway** select appropriate rest API (if its where created with deploy_lambda.py 
then its **approoveAPI**).

Select **Authorizers->exampleApproovAuthorizer**. Copy token from **Test token**
section to **Identity token** Input. Press **Test**.

Check log messages if everything when okey.

### Test token 1

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZCI6Ilczc2lhMlY1SWpvaVJFbEVJaXdpZG1Gc2RXVWlPaUpxUW1wd1FXcExZa0o2ZW1sVFUzSjNXV3BrZG1ScFFtZzBhV0pNYm5OdFFtTlVWbTgzTTFsd1JFbzBQU0o5TEhzaWEyVjVJam9pUVZJaUxDSjJZV3gxWlNJNkltZ2lmVjA9IiwiZXhwIjoyNDcxNDE5OTI2LCJpcCI6IkFBQUFBQUFBQUFBQUFQLy9WRnhDS0E9PSIsInVpIjo3MjU1MDI5MjIzNDczNjY5MDAwfQ.ieDCvsWqF7DyDd7ShII1X1xK392NkIuO6m2oBpic8zg
```
**Note:** copy as single line

### Test token 2

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZCI6Ilczc2lhMlY1SWpvaVJFbEVJaXdpZG1Gc2RXVWlPaUpxUW1wd1FXcExZa0o2ZW1sVFUzSjNXV3BrZG1ScFFtZzBhV0pNYm5OdFFtTlVWbTgzTTFsd1JFbzBQU0o5TEhzaWEyVjVJam9pUVZJaUxDSjJZV3gxWlNJNkltZ2lmVjA9IiwiZXhwIjoyNDcxNDE5OTI2LCJpcCI6IkFBQUFBQUFBQUFBQUFQLy9WRnhDS0E9PSIsInVpIjo3MjU1MDI5MjIzNDczNjY5MDAwfQ.1xLvS4RIfY2JX6ZlqckOaxLneWqmNtoyyoCN4hNjWWM
```
**Note:** copy as single line
