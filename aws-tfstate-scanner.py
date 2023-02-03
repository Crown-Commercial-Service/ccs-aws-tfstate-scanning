import boto3
import botocore
import time
import json
import csv

# open file in write mode
f = open('aws-tfscan-output.csv', 'w')

# create csv writer
writer = csv.writer(f)
header_1 = "AccountID"
header_2 = "BucketName"
header_3 = "ObjectName"
header_4 = "SensitiveKey"

# generate file headers
headers = []
headers.append(header_1)
headers.append(header_2)
headers.append(header_3)
headers.append(header_4)
# write a row to the csv file
writer.writerow(headers)

# define sensitive search strings
sensitive_strings = ['access_token','ACCESS_TOKEN','Access_token','Access_Token',\
    'client_secret','CLIENT_SECRET','Client_secret','Client_Secret',\
        'password','PASSWORD','Password',\
        'secret','SECRET','Secret']

# Extract nested values from a JSON tree.
def json_extract(obj, key):
    # Recursively fetch values from nested JSON.
    arr = []

    def extract(obj, arr, key):
        # Recursively search for values of key in JSON tree.
        if isinstance(obj, dict):
            for k, v in obj.items():
                if v != "":
                    if isinstance(v, (dict, list)):
                        extract(v, arr, key)
                    elif k == key:
                        arr.append(k)
        elif isinstance(obj, list):
            for item in obj:
                extract(item, arr, key)
        return arr

    values = extract(obj, arr, key)
    return values

# setup account input details and define aws profiles
input_switch_statement = input('Choose input type: 1 = comma-separated list of profiles, 2 = path to aws .config file: ')
if input_switch_statement == '1':

    profile_string = input('Specify AWS Profile List: ')
    profile_list = profile_string.split(",")

elif input_switch_statement == '2':

    profile_string = input('Specify .aws config file path: ')
    profile_list = []

    # Using readlines()
    config_file = open(profile_string, 'r')
    file_lines = config_file.readlines()

    # Strips the newline character
    for line in file_lines:
        line_contents = line.split()
        if len(line_contents) > 0:
            if line_contents[0] == '[profile':
                profile_name = line_contents[1].split(']')
                profile_list.append(profile_name[0])

else:
    raise Exception("Sorry, no numbers below zero")

# initiate counter for profiles / buckets / objects scanned
terminal_stats = [0,0,0]
# establish client with each aws account
for profile in profile_list:
    session = boto3.Session(profile_name=profile)
    s3_client = session.client('s3')
    s3_resource = session.resource('s3')

    try:
        response = s3_client.list_buckets()
        account_id = session.client('sts').get_caller_identity().get('Account')
        terminal_stats[0] += 1
        buckets = []
        tfstate_buckets = []
        tfstate_files = []
        row = []

        print("")
        print("Scanning Account ID " + account_id)
        print("...")
        
        # obtain list of s3 buckets and check bucket names for 'tfstate'
        for bucket in response['Buckets']:
            buckets += {bucket["Name"]}
            terminal_stats[1] += 1

        print("Scanning S3 Buckets for terraform content")
        print("")
        for bucket in buckets:
            if "state" in bucket:
                tfstate_buckets += {bucket}
                my_bucket = s3_resource.Bucket(bucket)
                print("- " + bucket)
                
                # recursively scan bucket for objects
                for my_bucket_object in my_bucket.objects.all():
                    object_name = my_bucket_object.key
                    object_name_n = object_name[len(object_name) - 1]
                    if object_name_n != '/':
                        secret_detected = False
                        tfstate_files += {object_name}
                        terminal_stats[2] += 1
                        print(" -- " + object_name, end=" ")
                        object_data = s3_client.get_object(Bucket = bucket, Key = object_name)
                        contents = object_data['Body'].read().decode("utf-8")

                        try:
                            json_contents = json.loads(contents)
                        except ValueError:  # includes simplejson.decoder.JSONDecodeError
                            print(':ERROR: Decoding JSON has failed - S3 object incorrectly formatted for .tfstate')

                        json_sensitive_keys = []

                        # checks for sensitive attributes according to pre-defined search strings
                        for sensitive_string in sensitive_strings:
                            json_sensitive_keys += json_extract(json_contents,sensitive_string)
                            if json_sensitive_keys != []:
                                secret_detected = True
                        
                        if secret_detected:
                            print(" !!! SECRET DETECTED !!!")
                            for sensitive_key in json_sensitive_keys:
                                print("   * " + sensitive_key)
                                # get aws account ID and add it to row
                                row.clear()
                                row.append(account_id)
                                row.append(bucket)
                                row.append(object_name)
                                row.append(sensitive_key)
                                # write a row to the csv file
                                writer.writerow(row)
                        else:
                            print(" clean ")
        del session

    except botocore.exceptions.ClientError as error:
        # Put your error handling logic here
        print("Access Denied to profile '" + profile + "', moving on to next profile ...")

    except botocore.exceptions.ParamValidationError as error:
        raise ValueError('The parameters you provided are incorrect: {}'.format(error))

    # finish here with summary stats of profiles scanned out of total, buckets, objects etc.

# close the file
f.close()

# Summarises scanning activity
print("")
print("Scanning Complete: " + str(terminal_stats[0]) + " Profiles, " + str(terminal_stats[1]) + " Buckets, " + str(terminal_stats[2]) + " Objects scanned.")