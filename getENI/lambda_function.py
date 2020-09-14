from crhelper import CfnResource
import boto3

helper = CfnResource()
ec2 = boto3.client('ec2')

@helper.create
@helper.update
def getENI(event, _):    
    response = ec2.describe_instances(
        Filters = [
            {
                'Name': 'instance-id',
                'Values': [
                    event['ResourceProperties']['InstanceId'],
                    ]
            }
        ]
    )
    ENI = response['Reservations'][0]['Instances'][0]['NetworkInterfaces'][0]['NetworkInterfaceId']
    
    helper.Data['ENI'] = ENI
    
@helper.delete
def no_op(_, __):
    pass

def lambda_handler(event, context):
    helper(event, context)
