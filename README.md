# AWS Terraform State Scanner

## Description

This simple python script scrapes json-formatted S3 objects to identify any sensitive values that have not been masked / hidden. This script can be used to identify .tfstate files that have failed to include 'sensitive attribute' flags for sensitive content. 

**NOTE**: The script ONLY alerts to cases where a sensitive key has a corresponding non-null, non-empty value (e.g., "secret" = "" **would NOT** return a scan finding, but "secret" = "password123" **would** return a scan finding)

The sensitive attributes identified by this script are:

*'access_token'
*'ACCESS_TOKEN'
*'Access_token'
*'Access_Token'
*'client_secret'
*'CLIENT_SECRET'
*'Client_secret'
*'Client_Secret'
*'password'
*'PASSWORD'
*'Password'
*'secret'
*'SECRET'
*'Secret'

# Requirements and Installation

To run this script you'll need to have valid [python3]https://www.python.org/downloads/, [pip]https://python.land/virtual-environments/installing-packages-with-pip and [boto3]https://pypi.org/project/boto3/ installations. 

Next, simply clone the repository and execute the python script through a terminal session.

# Running a scan

To run a scan, execute the script through a terminal session:

        $ python3 aws-tfstate-scanner.py

There are two options provided for scanning:

- Option 1 (comma-separated list of profiles)

For this option simply provide a comma-separated list of AWS profiles to scan. Profiles should correspond with the listed profile names within your .aws/.config file. E.g., for a scan against 3 profiles named **PROFILE1**,**PROFILE2**,**PROFILE3**:

        $ python3 aws-tfstate-scanner.py
        $ Choose input type: 1 = comma-separated list of profiles, 2 = path to aws .config file: 1
        $ Specify AWS Profile List: PROFILE1,PROFILE2,PROFILE3

- Option 2 (path to aws .config file)

For this option simply provide a path to your .aws/.config file. **NOTE**: This will scan against **ALL** of the AWS profiles listed within your .aws/.config file. Depending on the number of buckets/objects in each AWS Account represented by a profile, this could take several seconds/minutes per account.

# Output

Both scan types (see above) produce a live feed of scanning within the terminal window. Once the scan is completed, a file *'aws-tfstate-scanner.csv'* is output to the directory where the script is executed from. The file contains a list of sensitive keys with non-zero / non-empty values that have been identified in all the AWS Accounts / Buckets / Objects scanned. E.g:

| AccountID | BucketName | ObjectName | SensitiveKey |
| ------------- | ------------- | ------------- | ------------- |
| ACCOUNT1  | BUCKET1 | OBJECT1 | client_secret |
| ACCOUNT2  | BUCKET2 | OBJECT2 | password |