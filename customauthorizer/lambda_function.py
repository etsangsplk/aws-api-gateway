from __future__ import print_function

import re
import time
import pprint
import json
import datetime
import ipaddress
import base64
import socket
import logging

# Made available through upload in the .zip file along with this handler
import jwt

# Set the token secret from the admin portal as a constant
# Set apitest token secrtet for testing purposes
TEST_SECRET={"approov":"secret","apitest":None}

# Logging passed authorisations
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Handler called whenever custom authorization is required
def lambda_handler(event, context):

    # Authorization token is passed in via a custom http header
    # The header is configurable in the API Gateway admin interface
    if 'authorizationToken' not in event:
        logger.error("Authorization FAILED")
        raise Exception('Unknown event')
    token = event['authorizationToken']
    print('Client token: ' + token)
    print('Method ARN: ' + event['methodArn'])

    # Use the entire token as the Principal ID, this could also contain
    # an API key
    principalId = event['authorizationToken']

    # Decode the token using the per-customer secret downloaded from the
    # Approov admin portal
    tryapi_token = False
    try:
        tokenContents = jwt.decode(token, TEST_SECRET["approov"], algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        # Signature has expired, token is bad
        logger.error("Authorization FAILED")
        raise Exception('Unauthorized')
    except:
        #if first token is failed and there is no apitest token then rise exception
        if TEST_SECRET["apitest"] == None:
            logger.error("Authorization FAILED")
            raise Exception('Unauthorized')
        # token approve is not valid set tryapi_test to decode apitest token
        else:
            tryapi_token = True

    if tryapi_token:
        #if first token failed lets try to use apitest token if api is in test mode
        try:
            tokenContents = jwt.decode(token, TEST_SECRET["apitest"], algorithms=['HS256'])
            logger.info("APITEST token is used")
        except:
            # Token could not be decoded, token is bad
            logger.error("Authorization FAILED")
            raise Exception('Unauthorized')


    ##### Boilerplate code from AWS ######
    tmp = event['methodArn'].split(':')
    apiGatewayArnTmp = tmp[5].split('/')
    awsAccountId = tmp[4]

    policy = AuthPolicy(principalId, awsAccountId)
    policy.restApiId = apiGatewayArnTmp[0]
    policy.region = tmp[3]
    policy.stage = apiGatewayArnTmp[1]
    #####################################

    # conditions for allowed methods
    conditions = {}
    # Retrieve the time from the token this is mandatory field
    if 'exp' in tokenContents:
        expiration = (tokenContents['exp'])
         # Convert to the appropriate format for the condition in the policy
        expirationTime = datetime.datetime.utcfromtimestamp(expiration).strftime('%Y-%m-%dT%H:%M:%SZ')

        # Set up a condition based on expiration time stored in the JWT
        conditions["DateLessThanEquals"] = {
            "aws:CurrentTime": expirationTime
        }
    else:
        logger.error("Authorization FAILED")
        raise Exception('Unauthorized')

   
    # Get IP Hash from token contents - ip field is optional
    if 'ip' in tokenContents:
        base64IP = (tokenContents['ip'])
        # Base64 encoded ip address, so decode it here
        try:
            decodedIP = base64.b64decode(base64IP)
        except TypeError:
            # Not a Base64 encoded value
            logger.error("Authorization FAILED")
            raise Exception('Unauthorized')

        issuedIP = socket.inet_ntop(socket.AF_INET6, bytes(decodedIP))
        # If it is ipv4, convert from ipv6 format
        mappedIP = ipaddress.IPv6Address(issuedIP.decode("utf-8"))
        if mappedIP.ipv4_mapped is not None:
            issuedIP = mappedIP.ipv4_mapped

        # Set up a condition based on the ip address
        conditions["IpAddress"] = {
            "aws:SourceIp": str(issuedIP)
        }

    # Allow all methods, restricted to those which match condition
    policy.allowMethodWithConditions(HttpVerb.ALL, '*', conditions)

    '''finally, build the policy and exit the function using return'''
    logger.info("Authorization DONE")
    return policy.build()


# boilerplate from aws for creating the policy
class HttpVerb:
    GET     = 'GET'
    POST    = 'POST'
    PUT     = 'PUT'
    PATCH   = 'PATCH'
    HEAD    = 'HEAD'
    DELETE  = 'DELETE'
    OPTIONS = 'OPTIONS'
    ALL     = '*'


class AuthPolicy(object):
    awsAccountId = ''
    '''The AWS account id the policy will be generated for. This is used to create the method ARNs.'''
    principalId = ''
    '''The principal used for the policy, this should be a unique identifier for the end user.'''
    version = '2012-10-17'
    '''The policy version used for the evaluation. This should always be '2012-10-17' '''
    pathRegex = '^[/.a-zA-Z0-9-\*]+$'
    '''The regular expression used to validate resource paths for the policy'''

    '''these are the internal lists of allowed and denied methods. These are lists
    of objects and each object has 2 properties: A resource ARN and a nullable
    conditions statement.
    the build method processes these lists and generates the approriate
    statements for the final policy'''
    allowMethods = []
    denyMethods = []

    restApiId = '*'
    '''The API Gateway API id. By default this is set to '*' '''
    region = '*'
    '''The region where the API is deployed. By default this is set to '*' '''
    stage = '*'
    '''The name of the stage used in the policy. By default this is set to '*' '''

    def __init__(self, principal, awsAccountId):
        self.awsAccountId = awsAccountId
        self.principalId = principal
        self.allowMethods = []
        self.denyMethods = []

    def _addMethod(self, effect, verb, resource, conditions):
        '''Adds a method to the internal lists of allowed or denied methods. Each object in
        the internal list contains a resource ARN and a condition statement. The condition
        statement can be null.'''
        if verb != '*' and not hasattr(HttpVerb, verb):
            raise NameError('Invalid HTTP verb ' + verb + '. Allowed verbs in HttpVerb class')
        resourcePattern = re.compile(self.pathRegex)
        if not resourcePattern.match(resource):
            raise NameError('Invalid resource path: ' + resource + '. Path should match ' + self.pathRegex)

        if resource[:1] == '/':
            resource = resource[1:]

        resourceArn = (
            'arn:aws:execute-api:' +
            self.region + ':' +
            self.awsAccountId + ':' +
            self.restApiId + '/' +
            self.stage + '/' +
            verb + '/' +
            resource)

        if effect.lower() == 'allow':
            self.allowMethods.append({
                'resourceArn' : resourceArn,
                'conditions' : conditions
            })
        elif effect.lower() == 'deny':
            self.denyMethods.append({
                'resourceArn' : resourceArn,
                'conditions' : conditions
            })

    def _getEmptyStatement(self, effect):
        '''Returns an empty statement object prepopulated with the correct action and the
        desired effect.'''
        statement = {
            'Action': 'execute-api:Invoke',
            'Effect': effect[:1].upper() + effect[1:].lower(),
            'Resource': []
        }

        return statement

    def _getStatementForEffect(self, effect, methods):
        '''This function loops over an array of objects containing a resourceArn and
        conditions statement and generates the array of statements for the policy.'''
        statements = []

        if len(methods) > 0:
            statement = self._getEmptyStatement(effect)

            for curMethod in methods:
                if curMethod['conditions'] is None or len(curMethod['conditions']) == 0:
                    statement['Resource'].append(curMethod['resourceArn'])
                else:
                    conditionalStatement = self._getEmptyStatement(effect)
                    conditionalStatement['Resource'].append(curMethod['resourceArn'])
                    conditionalStatement['Condition'] = curMethod['conditions']
                    statements.append(conditionalStatement)

            if statement['Resource']:
                statements.append(statement)

        return statements

    def allowAllMethods(self):
        '''Adds a '*' allow to the policy to authorize access to all methods of an API'''
        self._addMethod('Allow', HttpVerb.ALL, '*', [])

    def denyAllMethods(self):
        '''Adds a '*' allow to the policy to deny access to all methods of an API'''
        self._addMethod('Deny', HttpVerb.ALL, '*', [])

    def allowMethod(self, verb, resource):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods for the policy'''
        self._addMethod('Allow', verb, resource, [])

    def denyMethod(self, verb, resource):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods for the policy'''
        self._addMethod('Deny', verb, resource, [])

    def allowMethodWithConditions(self, verb, resource, conditions):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition'''
        self._addMethod('Allow', verb, resource, conditions)

    def denyMethodWithConditions(self, verb, resource, conditions):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition'''
        self._addMethod('Deny', verb, resource, conditions)

    def build(self):
        '''Generates the policy document based on the internal lists of allowed and denied
        conditions. This will generate a policy with two main statements for the effect:
        one statement for Allow and one statement for Deny.
        Methods that includes conditions will have their own statement in the policy.'''
        if ((self.allowMethods is None or len(self.allowMethods) == 0) and
            (self.denyMethods is None or len(self.denyMethods) == 0)):
            raise NameError('No statements defined for the policy')

        policy = {
            'principalId' : self.principalId,
            'policyDocument' : {
                'Version' : self.version,
                'Statement' : []
            }
        }

        policy['policyDocument']['Statement'].extend(self._getStatementForEffect('Allow', self.allowMethods))
        policy['policyDocument']['Statement'].extend(self._getStatementForEffect('Deny', self.denyMethods))

        return policy
