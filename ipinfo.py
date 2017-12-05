#!/usr/bin/env python

from __future__ import print_function
import boto3
import sys
import socket
import time
import threading
import argparse
import botocore


class Spinner:
    busy = False
    delay = 0.1

    @staticmethod
    def spinning_cursor():
        while 1: 
            for cursor in '|/-\\': yield cursor

    def __init__(self, delay=None):
        self.spinner_generator = self.spinning_cursor()
        if delay and float(delay): self.delay = delay

    def spinner_task(self):
        while self.busy:
            sys.stdout.write(next(self.spinner_generator))
            sys.stdout.flush()
            time.sleep(self.delay)
            sys.stdout.write('\b')
            sys.stdout.flush()

    def start(self):
        self.busy = True
        threading.Thread(target=self.spinner_task).start()

    def stop(self):
        self.busy = False
        time.sleep(self.delay)


def validIP(address):
    parts = address.split(".")
    if len(parts) != 4:
        return False
    for item in parts:
        if not 0 <= int(item) <= 255:
            return False
    return True


def get_ip_info(ipaddr, region):
    try:
        client = boto3.client('ec2', region_name=region)
        resp = client.describe_network_interfaces(
            Filters=[{'Name':'private-ip-address', 'Values': [ipaddr]}]
        )
        ipinfo = resp['NetworkInterfaces']

        if ipinfo:
            return ipinfo
        else:
            return False
    except botocore.exceptions.NoCredentialsError as CredError:
        print("Could not locate valid aws credentials. Please configure as per guide http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html")
        return "NoCreds"


def get_ip_by_endpoint(endpoint):
    try:
        ip = socket.gethostbyname(endpoint)
    except socket.gaierror:
        ip = None
    return ip


def get_elasticache_cluster_info(ipaddr, region):
    cluster_info = {}
    try:
        ec = boto3.client('elasticache', region_name=region)
        cc = ec.describe_cache_clusters(ShowCacheNodeInfo=True)
        for cluster in cc.get('CacheClusters'):
            for node in cluster.get('CacheNodes'):
                endpoint_addr = node.get('Endpoint')['Address']
                if get_ip_by_endpoint(endpoint_addr) == ipaddr:
                    cluster_info['Service'] = "Amazon Elasticache"
                    cluster_info['Endpoint DNS'] = endpoint_addr
                    cluster_info['Engine'] = cluster['Engine']
                    cluster_info['CacheClusterId'] = cluster['CacheClusterId']
                    cluster_info['NumCacheNodes'] = cluster['NumCacheNodes']
                    cluster_info['PreferredAvailabilityZone'] = cluster['PreferredAvailabilityZone']
                    cluster_info['SecurityGroups'] = cluster['SecurityGroups'][0]['SecurityGroupId']
                    break
            if(cluster_info):
                break
    except Exception as error:
        print(error)
    return cluster_info


def get_rds_info(ipaddr, region):
    rds_info = {}
    rds = boto3.client('rds', region_name=region)
    try:
        dbs = rds.describe_db_instances()
        for db in dbs['DBInstances']:
            if get_ip_by_endpoint(db['Endpoint']['Address']) == ipaddr:
                rds_info['Service'] = "Amazon RDS"
                rds_info['Engine'] = db['Engine']
                rds_info['EngineVersion'] = db['EngineVersion']
                rds_info['DBInstanceIdentifier'] = db['DBInstanceIdentifier']
                rds_info['Endpoint DNS'] = db['Endpoint']['Address']
                rds_info['Endpoint Port'] = db['Endpoint']['Port']
                rds_info['AvailabilityZone'] = db['AvailabilityZone']
                rds_info['DBInstanceClass'] = db['DBInstanceClass']
                rds_info['DBInstanceStatus'] = db['DBInstanceStatus']
                rds_info['DBParameterGroups'] = db['DBParameterGroups'][0]['DBParameterGroupName']
                rds_info['VPC ID'] = db['DBSubnetGroup']['VpcId']
                rds_info['MultiAZ'] = db['MultiAZ']
                rds_info['VpcSecurityGroups'] = db['VpcSecurityGroups'][0]['VpcSecurityGroupId']
                break
            if(rds_info):
                break
    except Exception as error:
        print(error)
    return rds_info


def get_ec2_info(ipaddr, region):
    ec2_info = {}
    ec2 = boto3.client('ec2', region_name=region)
    try:
        response = ec2.describe_instances(Filters=[{'Name': 'network-interface.addresses.private-ip-address','Values': [ipaddr]}])
        data = response['Reservations'][0]['Instances']

        ec2_info['Service'] = "Amazon EC2"
        ec2_info['InstanceId'] = data[0]['InstanceId']
        ec2_info['InstanceType'] = data[0]['InstanceType']
        ec2_info['ImageId'] = data[0]['ImageId']
        if 'KeyName' in data[0].keys():
            ec2_info['KeyName'] = data[0]['KeyName']
        ec2_info['AvailabilityZone'] = data[0]['Placement']['AvailabilityZone']
        ec2_info['MacAddress'] = data[0]['NetworkInterfaces'][0]['MacAddress']
        ec2_info['NetworkInterfaceId'] = data[0]['NetworkInterfaces'][0]['NetworkInterfaceId']
        ec2_info['PrivateDnsName'] = data[0]['PrivateDnsName']
        ec2_info['SubnetId'] = data[0]['SubnetId']
        ec2_info['VpcId'] = data[0]['VpcId']
        ec2_info['Security Groups'] = []
        if 'Tags' in data[0].keys():
            ec2_info['Tags'] = data[0]['Tags']
        else:
            ec2_info['Tags'] = "Instance does not have tags"
        for group in data[0]['SecurityGroups'][:]:
            ec2_info['Security Groups'].append(group['GroupId'])
    except Exception as error:
        print(error)

    return ec2_info


def get_classic_elb_info(ipaddr, region):
    elb_info = {}
    try:
        elbList = boto3.client('elb', region_name=region)
        ec2 = boto3.resource('ec2')
        bals = elbList.describe_load_balancers()
        for elb in bals['LoadBalancerDescriptions']:
            if get_ip_by_endpoint(elb['DNSName']) == ipaddr:
                elb_info['Service'] = "Amazon ELB"
                elb_info['LoadBalancerName'] = elb['LoadBalancerName']
                elb_info['DNSName'] = elb['DNSName']
                elb_info['VPCId'] = elb['VPCId']
                elb_info['Instances'] = elb['Instances']
                elb_info['SecurityGroups'] = elb['SecurityGroups']
                elb_info['Subnets'] = elb['Subnets']
                elb_info['Scheme'] = elb['Scheme']
                elb_info['AvailabilityZones'] = elb['AvailabilityZones']
                break
    except Exception as error:
        print(error)
    return elb_info


def get_app_elb_info(ipaddr, region):
    alb_info = {}
    try:
        client = boto3.client('elbv2', region_name=region)
        response = client.describe_load_balancers()
        bals = response['LoadBalancers']
        for alb in bals:
            if (get_ip_by_endpoint(alb['DNSName']) == ipaddr) or (get_ip_by_endpoint(alb['DNSName']) == ipaddr):
                alb_info['Service'] = "Amazon ALB"
                alb_info['LoadBalancerName'] = alb['LoadBalancerName']
                alb_info['LoadBalancerArn'] = alb['LoadBalancerArn']
                alb_info['DNSName'] = alb['DNSName']
                alb_info['Type'] = alb['Type']
                alb_info['Scheme'] = alb['Scheme']
                alb_info['State'] = alb['State']
                alb_info['VpcId'] = alb['VpcId']
                alb_info['SecurityGroups'] = alb['SecurityGroups']
                alb_info['AvailabilityZones'] = alb['AvailabilityZones']
    except Exception as error:
        print(error)
    return alb_info


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('ip', action='store', type=str, help='IP address')
    parser.add_argument('--region', '-r', action='store', type=str, default='us-west-1', help='AWS Region',
                         choices=['us-west-1',
                                  'us-west-2',
                                  'us-east-1',
                                  'us-east-2',
                                  'ap-south-1',
                                  'ap-northeast-1',
                                  'ap-northeast-2',
                                  'ap-southeast-1',
                                  'ap-southeast-2',
                                  'ca-central-1',
                                  'eu-central-1',
                                  'sa-east-1',
                                  'eu-west-1',
                                  'eu-west-2'
                                 ]
                       )
    
    ip = parser.parse_args().ip
    region = parser.parse_args().region

    if not validIP(ip):
        print("IP address %s is not valid. Please enter correct one" % ip)
        sys.exit()

    spinner = Spinner()

    print("Looking info about IP %s in AWS region %s..." % (ip, region))
    spinner.start()
    ipinfo = get_ip_info(ip, region)
    spinner.stop()

    if ipinfo == 'NoCreds':
        sys.exit()

    if ipinfo:
        if ipinfo[0]['Attachment']['InstanceOwnerId'] == 'amazon-elasticache':
            print("IP address %s comes from Amazon Elasticache. Looking for detailed info..." % ip)
            spinner.start()
            ip_info = get_elasticache_cluster_info(ip, region)
            spinner.stop()
        elif ipinfo[0]['Attachment']['InstanceOwnerId'] == 'amazon-rds':
            print("IP address %s comes from Amazon RDS. Looking for detailed info..." % ip)
            spinner.start()
            ip_info = get_rds_info(ip, region)
            spinner.stop()
        elif ipinfo[0]['Attachment']['InstanceOwnerId'] == 'amazon-elb':
            print("IP address %s comes from Amazon ELB. Looking for detailed info..." % ip)
            spinner.start()
            ip_info = get_classic_elb_info(ip, region)
            spinner.stop()
            if not ip_info:
                print("Could not find Classic Load Balancer with IP %s" % ip)
                print("Looking among Application Load Balancers...")
                spinner.start()
                ip_info = get_app_elb_info(ip, region)
                spinner.stop()
            if not ip_info:
                print("Could not find additional details among ELB/ALB balancers. Probably IP address was changed.")
                sys.exit()
        elif ipinfo[0]['Attachment']['InstanceId'].startswith('i-'):
            print("IP address %s comes from Amazon EC2. Looking for detailed info..." % ip)
            spinner.start()
            ip_info = get_ec2_info(ip, region)
            spinner.stop()
        else:
            print("Could not find additional details or IP comes from unknown service")
            sys.exit()
    else:
        print("Could not find IP address %s in current AWS account/region" % ip)
        sys.exit()

    print("---------------------- DETAILED INFO FOR %s ------------------------" % ip)
    print("Service: %s" % ip_info['Service'])
    for info, data in ip_info.items():
        print("%s: " % info, end='')
        if type(data) is list:
            print("")
            for item in data:
                if (type(item) is dict) and (info == 'Tags'):
                    print("\t Key: %s, Value: %s" % (item['Key'], item['Value']))
                else:
                    print("\t - ", item)
        else:
            print(" %s" % data)
    print("--------------------------------------------------------------------------------")
