#!/usr/bin/env python
from __future__ import print_function
import argparse
import logging
import ConfigParser
import os
import sys
import boto3
import botocore.exceptions
import subprocess
from time import sleep
from Crypto.PublicKey import RSA

user_config = os.environ['HOME']+"/.grabcloud/grabcloud.cfg" 
user_key = os.environ['HOME']+"/.grabcloud/keys" 
config_files = [ user_config, '/etc/grabcloud.cfg' ]

def ssh_keygen():
    # build ssh keys in grabcloud
    global user_key
    logging.debug("generating ssh keys in .grabcloud")
    if os.path.isfile(user_key):
        logging.error("ssh keys already exist in %s", user_key)
        return
    key = RSA.generate( 2048 )
    with open( user_key, 'w' ) as keyfile:
        os.chmod( user_key, 0600 )
        keyfile.write( key.exportKey('PEM'))

    pubkey = key.publickey()
    with open( user_key + ".pub", 'w') as keyfile:
        keyfile.write( pubkey.exportKey('OpenSSH'))

    return

def _to_parameter_list( d ):
    # convert parameters dictionary to list format for boto3
    return _d_to_l( d, 'ParameterKey', 'ParameterValue' )

def _to_tag_list( d ):
    # convert list dictionary to list format for boto3
    return _d_to_l( d, 'Key', 'Value' )

def _d_to_l( d, keyname, valuename ):
    l = []
    for k, v in d.items():
        l.append( { keyname : k, valuename : v['value'] } )
    return l

def _get_node( cf ):
    # takes boto3 cloudformation resource as an argument
    resource = cf.StackResource( stackname, 'EC2Instance' )
    ec2 = boto3.resource('ec2')
    node = ec2.Instance( resource.physical_resource_id )
    return node

def _node_state( cf ):
    # takes boto3 cloudformation resource as an argument
    resource = cf.StackResource( stackname, 'EC2Instance' )
    logger.debug( "resource state is %s", resource.resource_status )
    logger.debug( "resource id is %s", resource.physical_resource_id )
    ec2 = boto3.resource('ec2')
    node = ec2.Instance( resource.physical_resource_id )
    logger.debug( "instance state is", node.state['Name'] )
    return node.state['Name']


def inputdefault( prompt, default ):
    newval = raw_input( prompt + " [" + default + "]: " )
    return( newval or default )

def add_common_args( p ):
    p.add_argument(
        '--debug', dest = "debug",
        action = 'store_true', help = "turn on debugging" )
    p.add_argument(
        '--debug-boto', dest = "debug_boto",
        action = 'store_true', help = "turn on debugging" )

def get_config( ):
    global config_files
    global user_key
    cdict = {
        "tags": {
            "Name":
                {"help": "name for this instance", "value": ""},
            "description":
                {"help": "description tag for instances", "value": ""},
            "owner": 
                {"help": "department of the instance owner", "value": ""},
            "technical_contact": 
                {"help": "email of instance contact", "value": ""},
            "billing_contact": 
                {"help": "email of instance billing contact", "value": ""},
            "sle": 
                {"help": "service level expectation", "value": ""}
        },
        "aws": {
            "AMI": {"help": "AMI ID", "value": "" },
            "KeyName": { "help": "Name of rootkey", "value": "noisycricket"},
            "InstanceType": { "help": "Instance Type", "value": "t2.micro" },
            "SSHLocation": {
                "help": "Subnet to use", "value": "172.20.160.126/24"},
            "User": {
                "help": "username to create on instance", "value": "mrg"},
            "UID": {
                "help": "UID of user to create on instance", "value": "34152"},
            "UserPubKey": {"help": "SSH key for user access", "value": "" },
            "Disk": {"help": "size of disk in GB", "value": "" },
            "Policy": {"help": "control behavior when idle", "value": "" },
        }
    }
    c = ConfigParser.ConfigParser()
    c.optionxform = str
    for cfgfile in config_files:
        c.read( cfgfile )
        logger.debug( "read config file %s", cfgfile )

    for section in cdict.keys():
        logger.debug( "evaluating section %s", section )
        for parameter in cdict[section].keys():
            logger.debug( "evaluating parameter %s", parameter )
            try:
                cdict[section][parameter]['value'] = c.get( section, parameter )
            except ConfigParser.NoOptionError:
                logger.debug( "No option set for %s", parameter )

    # read in grabcloud key

    if not os.path.isfile(user_key):
        logging.debug( "generating user key" )
        ssh_keygen()

    with open( user_key + ".pub", 'r' ) as pubkey:
        cdict['aws']['UserPubKey']['value'] = pubkey.read()
        logging.debug( "read user key from %s", user_key + ".pub" )
        
    # set instance name
    cdict['tags']['Name']['value'] = "grabnode_" + os.getlogin()
    
    return cdict

def write_config( cdict ):
    global user_config
    logger.debug( "writing config to file %s", user_config )
    c = ConfigParser.ConfigParser()
    c.optionxform = str
    for section in cdict.keys():
        logger.debug( "writing section %s", section )
        c.add_section( section )
        for parameter in cdict[section].keys():
            c.set( section, parameter, cdict[section][parameter]['value'] )

    with open( user_config, 'w' ) as file:
        c.write(file)
        logger.debug( "wrote file" )

def configure_app( ):
    cfg = get_config( )

    for section in cfg.keys():
        logger.debug( "in section %s", section )
        for parameter in cfg[section].keys():
            logger.debug( "getting response for parameter %s", parameter )
            t = cfg[section][parameter]
            t['value'] = inputdefault( t['help'],t['value'] )

    write_config( cfg )
    
def destroy(stackname):
    logger.debug("Destroying instance %s", stackname)

    cf = boto3.client('cloudformation')
    response = cf.delete_stack( StackName=stackname )
    
def connect( stackname ):
    global user_key
    stack_outputs = get_outputs( stackname )

    print( "opening shell session to grabcloud instance" )
    logging.debug( "opening ssh to", stack_outputs['SSHTarget'] )

    ssh_cmd = " ".join(
        ["/usr/bin/ssh",
         "-i", user_key,
         stack_outputs['SSHTarget']]
    )

    result = subprocess.call( ssh_cmd, shell=True )

    logging.debug("shell session complete")

def status( stackname ):
    logger.debug( "checking grabcloud status" )
    cf = boto3.resource('cloudformation')
    stack = cf.Stack( stackname )
    try:
        if ( stack.stack_status == "CREATE_COMPLETE" or
            stack.stack_status == "UPDATE_COMPLETE"):
            print( "cloudformation is ready" )
            print( "node state is", _get_node(cf).state['Name'] )
        else:
            print( "cloudformation is not ready" )
    except botocore.exceptions.ClientError:
        print( "no grabcloud sessions configured" )
        return

def stop( stackname ):
    cf = boto3.resource('cloudformation')
    n = _get_node(cf)
    logger.debug( "stopping instance %s", n.instance_id )
    n.stop()
    while n.state['Name'] != "stopped":
        logger.debug("wating for instance to stop (%s)", n.state['Name'] )
        sleep(15)
        n.load()
    logger.info( "Instance stopped" )

def start(stackname, template, cdict ):
    logger.debug("Starting Instance")
    tags = _to_tag_list(cdict['tags'])
    parameters = _to_parameter_list(cdict['aws'])
    logger.debug("got config")

    cf = boto3.resource('cloudformation')

    try:
        #FIXME: this try block doesn't seem to catch many exceptions
        response = cf.create_stack( StackName = stackname,
            TemplateBody = template, Parameters = parameters,
            Tags = tags
        )
        stack = cf.Stack('grabnodemrg')
        logger.debug( "stack %s created", stackname )
        logger.info( "Waiting for node to start" )
        while stack.stack_status == 'CREATE_IN_PROGRESS':
            logger.debug( "waiting for stack to complete ( current is %s)",
                          stack.stack_status )
            sleep(15)
            stack.load()
    except botocore.exceptions.ClientError, e:
        if e.response['Error']['Code'] == 'AlreadyExistsException':
            logger.info( "cloudformation configured, checking instance")
            logger.debug("got message %s", e.response['Error']['Message'])

            n = _get_node(cf)
            stack = cf.Stack('grabnodemrg')
            # Attempt to start node
            if n.state['Name'] != 'running':
                logger.debug( "node state is %s", n.state['Name'] )
                logger.info( "restarting instance" )
                response = n.start()

                if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                    logger.info( "waiting for instance to start" )

                    while n.state['Name'] != 'running':
                        logger.debug( "node state is %s", n.state['Name'] )
                        sleep(15)
                        n.load()
                else:
                    logger.error(
                        "received http error %s trying to start the node",
                        response['ResponseMetadata']['HTTPStatusCode']
                    )

            else:
                logger.info( "instance is running, use connect to use it" )
    except:
        logger.debug( "got unhandled error:", sys.exc_info()[0] )
        raise

    # Check stack state to make sure it's running:
    if stack.stack_status != 'CREATE_COMPLETE':
        logger.error( "Stack did not get created properly, state is %s",
                     stack.stack_status )

def update( stackname, template, parameters ):
    client = boto3.client('cloudformation')
    response = client.update_stack( StackName = stackname,
        TemplateBody = template, Parameters = parameters,
    )

def get_outputs( stackname ):

    cf = boto3.resource('cloudformation')
    stack = cf.Stack( stackname )

    outputs = {}
    for output in stack.outputs:
        logger.debug(
            "got output %s with value %s",
            output['OutputKey'], output['OutputValue'],
        )
        outputs[output['OutputKey']] =  output['OutputValue']
    return outputs

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers( dest="action", help="action" )

    configure_opts = subparser.add_parser(
        'configure', help = "configure grabcloud")
    add_common_args( configure_opts )

    start_opts = subparser.add_parser(
        'start', help = "start an instance")
    add_common_args(start_opts)

    status_opts = subparser.add_parser(
        'status', help = "current state of grabcloud resources")
    add_common_args(status_opts)

    connect_opts = subparser.add_parser(
        'connect', help = "connect to a running instance")
    add_common_args(connect_opts)

    stop_opts = subparser.add_parser(
        'stop', help = "stop a running instance")
    add_common_args(stop_opts)
    stop_opts.add_argument ( '-y', dest = "confirm", action = "store_true" )

    destroy_opts = subparser.add_parser(
        'destroy', help = "destroy an instance (may result in data loss)")
    add_common_args(destroy_opts)
    destroy_opts.add_argument ( '-y', dest = "confirm", action = "store_true" )

    put_opts = subparser.add_parser(
        'put', help = "copy data to a running instance")
    add_common_args(put_opts)
    put_opts.add_argument( 'src', help = "source file" )
    put_opts.add_argument( 'dest', help = "destination on instance" )

    get_opts = subparser.add_parser(
        'get', help = "copy data from a running instance")
    add_common_args(get_opts)
    get_opts.add_argument( 'src', help = "source file on instance" )
    get_opts.add_argument( 'dest', help = "local destination" )

    #FIXME: this sucks.
    stackname = 'grabnode'
    #/FIXME

    args = parser.parse_args()

    logger = logging.getLogger('grabcloud')
    format = logging.Formatter('%(name)s:  %(message)s')

    loglvl = logging.INFO
    bloglvl = logging.ERROR

    if args.debug:
        loglvl = logging.DEBUG
        bloglvl = logging.ERROR

    if args.debug_boto:
        loglvl = logging.DEBUG
        bloglvl = logging.INFO

    logger.setLevel(loglvl)

    conslog = logging.StreamHandler()
    conslog.setFormatter(format)
    conslog.setLevel(loglvl)
    logger.addHandler(conslog)
    boto3.set_stream_logger('boto3.resources', bloglvl)

    #FIXME: need to figure out where to store template
    template = open('/usr/share/grabcloud/template.json').read()
    logger.debug( "read template from cloudformation/template.json")

    if args.action == 'configure':
        logger.debug( "starting configuration process" )
        configure_app()

    if args.action == 'start':
        logger.debug( "starting instance" )

        c = get_config()
        start(
            stackname = stackname,
            template = template,
            cdict = c
        )

    if args.action == 'connect':
        logger.debug( "connecting to instance" )
        connect( stackname = stackname )
        #logger.error( "connect is not yet implemented- yell at michael more" )

    if args.action == 'status':
        logger.debug( "getting status of resources" )
        status( stackname = stackname )

    if args.action == 'stop':
        logger.debug( "stopping instance" )
        stop( stackname = stackname )

    if args.action == 'destroy':
        logger.debug( "destroy instance" )
        destroy( stackname = stackname )

    if args.action == 'put':
        logger.debug( "putting up files" )
        logger.error( "put is not yet implemented- yell at michael more" )

    if args.action == 'get':
        logger.debug( "getting files" )
        logger.error( "get is not yet implemented- yell at michael more" )


