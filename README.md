# meghscan
A python program to perform secure configuration review of AWS.

This script currently performs checks only for S3 service. Support for other services will be added eventually. This script is written with python3 and have been tested on linux. I strongly recommend to use python3 to run this script or unexpected errors/behaviours may be encountered.

# Prerequisites
1. `python3`. Make sure you have python3 installed.
2. `dictor`. Dictor is a Python 2 and 3 compatible JSON/Dictionary handler. Install it using `pip3 install dictor`.
3. `aws cli`. Make sure you have aws cli configured. This script uses aws cli commands to check configuration of AWS.

Before running this script, make sure to set the relevant aws cli profile. Use below command in linux terminal to set the aws cli profile:
    
    $ export AWS_PROFILE=user1
    
# Usage

    $ python3 meghscan.py -h
    
# Contribution
The idea of writing this script was born during one my assessments of AWS secure configuration review, where i spent quite a time doing checks manualy. It could be really long and boring if you have several buckets like more than 10. Next, the support for IAM will be added. If you want to contribute in any way like adding test cases, further development, finding flaws or bugs, code quality, etc. feel free to join me.

All the test cases/rules used in this script are referenced from Cloud conformity. For more information visit below link :
https://www.cloudconformity.com/knowledge-base/aws/
    
    
