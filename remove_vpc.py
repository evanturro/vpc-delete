"""

Remove those pesky AWS default VPCs.

Python Version: 3.7.0
Boto3 Version: 1.7.50

"""
import argparse
import boto3
from botocore.exceptions import ClientError


def delete_igw(ec2, vpc_id):
    """
    Detach and delete the internet gateway
    """

    args = {
        'Filters': [
            {
                'Name': 'attachment.vpc-id',
                'Values': [vpc_id]
            }
        ]
    }

    try:
        igw = ec2.describe_internet_gateways(**args)['InternetGateways']
    except ClientError as e:
        print(e.response['Error']['Message'])

    if igw:
        igw_id = igw[0]['InternetGatewayId']

        try:
            result = ec2.detach_internet_gateway(
                InternetGatewayId=igw_id, VpcId=vpc_id)
        except ClientError as e:
            print(e.response['Error']['Message'])

        try:
            result = ec2.delete_internet_gateway(InternetGatewayId=igw_id)
        except ClientError as e:
            print(e.response['Error']['Message'])

    return


def delete_subs(ec2, args):
    """
    Delete the subnets
    """

    try:
        subs = ec2.describe_subnets(**args)['Subnets']
    except ClientError as e:
        print(e.response['Error']['Message'])

    if subs:
        for sub in subs:
            sub_id = sub['SubnetId']

            try:
                result = ec2.delete_subnet(SubnetId=sub_id)
            except ClientError as e:
                print(e.response['Error']['Message'])

    return


def delete_rtbs(ec2, args):
    """
    Delete the route tables
    """

    try:
        rtbs = ec2.describe_route_tables(**args)['RouteTables']
    except ClientError as e:
        print(e.response['Error']['Message'])

    if rtbs:
        for rtb in rtbs:
            main = 'false'
            for assoc in rtb['Associations']:
                main = assoc['Main']
            if main == True:
                continue
            rtb_id = rtb['RouteTableId']

            try:
                result = ec2.delete_route_table(RouteTableId=rtb_id)
            except ClientError as e:
                print(e.response['Error']['Message'])

    return


def delete_acls(ec2, args):
    """
    Delete the network access lists (NACLs)
    """

    try:
        acls = ec2.describe_network_acls(**args)['NetworkAcls']
    except ClientError as e:
        print(e.response['Error']['Message'])

    if acls:
        for acl in acls:
            default = acl['IsDefault']
            if default == True:
                continue
            acl_id = acl['NetworkAclId']

            try:
                result = ec2.delete_network_acl(NetworkAclId=acl_id)
            except ClientError as e:
                print(e.response['Error']['Message'])

    return


def delete_sgps(ec2, args):
    """
    Delete any security groups
    """

    try:
        sgps = ec2.describe_security_groups(**args)['SecurityGroups']
    except ClientError as e:
        print(e.response['Error']['Message'])

    if sgps:
        for sgp in sgps:
            default = sgp['GroupName']
            if default == 'default':
                continue
            sg_id = sgp['GroupId']

            try:
                result = ec2.delete_security_group(GroupId=sg_id)
            except ClientError as e:
                print(e.response['Error']['Message'])

    return


def delete_vpc(ec2, vpc_id, region):
    """
    Delete the VPC
    """

    try:
        result = ec2.delete_vpc(VpcId=vpc_id)
    except ClientError as e:
        print(e.response['Error']['Message'])

    else:
        print(f"VPC {vpc_id} has been deleted from the {region} region in {account}.")

    return


def get_regions(ec2):
    """
    Return all AWS regions
    """

    regions = []

    try:
        aws_regions = ec2.describe_regions()['Regions']
    except ClientError as e:
        print(e.response['Error']['Message'])

    else:
        for region in aws_regions:
            regions.append(region['RegionName'])

    return regions


def assume_role(account, role_name):
    """
    Assume a role and return the Credentials
    """

    client = boto3.client('sts')
    arn = f"arn:aws:iam::{account}:role/{role_name}"

    response = client.assume_role(
        RoleArn=arn, RoleSessionName="Delete-Default-VPCs")

    credentials = response['Credentials']

    return credentials


def main():
    """
    Do the work..

    Order of operation:

    1.) Delete the internet gateway
    2.) Delete subnets
    3.) Delete route tables
    4.) Delete network access lists
    5.) Delete security groups
    6.) Delete the VPC
    """

    # AWS Credentials
    # https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html
    parser = argparse.ArgumentParser(
        description="Provide a list of IDs for accounts you'd like to delete Default VPCs from.")

    parser.add_argument('-profile',
                        type=str,
                        default="Default",
                        help='Provide the AWS CLI profile you will use')

    parser.add_argument('ids',
                        type=str,
                        nargs='+',
                        help='Provide one or more account IDs separated by spaces')

    parser.add_argument('-role',
                        type=str,
                        default="OrganizationAccountAccessRole",
                        help='Provide the name of the role that you will assume within the provided accounts')

    args = parser.parse_args()
    print(args.ids)
    for account in args.ids:
        credentials = assume_role(account, args.role)
        ec2 = boto3.client('ec2',
                            region_name='us-east-1',
                            aws_access_key_id=credentials['AccessKeyId'],
                            aws_secret_access_key=credentials['SecretAccessKey'],
                            aws_session_token=credentials['SessionToken'],)

        regions = get_regions(ec2)

        for region in regions:

            try:
                attribs = ec2.describe_account_attributes(
                    AttributeNames=['default-vpc'])['AccountAttributes']
            except ClientError as e:
                print(e.response['Error']['Message'])
                return

            else:
                vpc_id = attribs[0]['AttributeValues'][0]['AttributeValue']

            if vpc_id == 'none':
                print(f"VPC (default) was not found in the {region} region in {account}.")
                continue

            # Are there any existing resources?  Since most resources attach an ENI, let's check..

            args = {
                'Filters': [
                    {
                        'Name': 'vpc-id',
                        'Values': [vpc_id]
                    }
                ]
            }

            try:
                eni = ec2.describe_network_interfaces(
                    **args)['NetworkInterfaces']
            except ClientError as e:
                print(e.response['Error']['Message'])
                return

            if eni:
                print('VPC {vpc_id} has existing resources in the {region} region in {account}.')
                continue

            result = delete_igw(ec2, vpc_id)
            result = delete_subs(ec2, args)
            result = delete_rtbs(ec2, args)
            result = delete_acls(ec2, args)
            result = delete_sgps(ec2, args)
            result = delete_vpc(ec2, vpc_id, region)



if __name__ == "__main__":

    main()
