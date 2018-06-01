#!/usr/bin/env python

# Upside Travel, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Modifications for Dryad made by Daisie Huang

import boto3
import botocore
import clamav
import copy
import json
import metrics
import urllib
import sys
import re
from common import *
from datetime import datetime
from distutils.util import strtobool
from optparse import OptionParser

ENV = os.getenv("ENV", "")
LOG = s3.Object("dryad-logs", "unscanned_files.txt")
LOGFILE = "/tmp/logfile"
LARGE_FILE_TEMP_PATH = "/transfer-complete/temp"

class SizeError(Exception):
    def __init__(self, msg):
        self.msg = msg

def event_object(event):
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = urllib.unquote_plus(event['Records'][0]['s3']['object']['key'].encode('utf8'))
    if (not bucket) or (not key):
        print("Unable to retrieve object from event.\n%s" % event)
        raise Exception("Unable to retrieve object from event.")
    return s3.Object(bucket, key)

def is_object_scannable(s3_object):
    # copy down the current log file, if it exists
    try:
        LOG.download_file(LOGFILE)
        LOG.delete()
    except botocore.exceptions.ClientError as e:
        pass

    lf = open(LOGFILE,"a")
    summary = s3.ObjectSummary(s3_object.bucket_name, s3_object.key)
    summary.load()
    if (summary.size > 500000000):
        lf.write(s3_object.bucket_name + "/" + s3_object.key + "\n")
        lf.close()
        LOG.upload_file(LOGFILE)
        raise SizeError("Too big for lambda: %s" % (s3_object.key))
    if (summary.storage_class == 'GLACIER'):
        lf.write(s3_object.bucket_name + "/" + s3_object.key + "\n")
        lf.close()
        LOG.upload_file(LOGFILE)
        raise SizeError("Object is in " + summary.storage_class)
        

def verify_s3_object_version(s3_object):
    # validate that we only process the original version of a file, if asked to do so
    # security check to disallow processing of a new (possibly infected) object version
    # while a clean initial version is getting processed
    # downstream services may consume latest version by mistake and get the infected version instead
    if str_to_bool(AV_PROCESS_ORIGINAL_VERSION_ONLY):
        bucketVersioning = s3.BucketVersioning(s3_object.bucket_name)
        if (bucketVersioning.status == "Enabled"):
            bucket = s3.Bucket(s3_object.bucket_name)
            versions = list(bucket.object_versions.filter(Prefix=s3_object.key))
            if len(versions) > 1:
                print("Detected multiple object versions in %s.%s, aborting processing" % (s3_object.bucket_name, s3_object.key))
                raise Exception("Detected multiple object versions in %s.%s, aborting processing" % (s3_object.bucket_name, s3_object.key))
            else:
                print("Detected only 1 object version in %s.%s, proceeding with processing" % (s3_object.bucket_name, s3_object.key))
        else:
            # misconfigured bucket, left with no or suspended versioning
            print("Unable to implement check for original version, as versioning is not enabled in bucket %s" % s3_object.bucket_name)
            raise Exception("Object versioning is not enabled in bucket %s" % s3_object.bucket_name)

def download_s3_object(s3_object, local_prefix):
    local_path = "%s/%s/%s" % (local_prefix, s3_object.bucket_name, s3_object.key)
    create_dir(os.path.dirname(local_path))
    s3_object.download_file(local_path)
    return local_path


def set_av_metadata(s3_object, result):
    content_type = s3_object.content_type
    metadata = s3_object.metadata
    metadata[AV_STATUS_METADATA] = result
    metadata[AV_TIMESTAMP_METADATA] = datetime.utcnow().strftime("%Y/%m/%d %H:%M:%S UTC")
    s3_object.copy(
        {
            'Bucket': s3_object.bucket_name,
            'Key': s3_object.key
        },
        ExtraArgs={
            "ContentType": content_type,
            "Metadata": metadata,
            "MetadataDirective": "REPLACE"
        }
    )


def set_av_tags(s3_object, result):
    curr_tags = s3_client.get_object_tagging(Bucket=s3_object.bucket_name, Key=s3_object.key)["TagSet"]
    new_tags = copy.copy(curr_tags)
    for tag in curr_tags:
        if tag["Key"] in [AV_STATUS_METADATA, AV_TIMESTAMP_METADATA]:
            new_tags.remove(tag)
    new_tags.append({"Key": AV_STATUS_METADATA, "Value": result})
    new_tags.append({"Key": AV_TIMESTAMP_METADATA, "Value": datetime.utcnow().strftime("%Y/%m/%d %H:%M:%S UTC")})
    s3_client.put_object_tagging(
        Bucket=s3_object.bucket_name,
        Key=s3_object.key,
        Tagging={"TagSet": new_tags}
    )

def sns_start_scan(s3_object):
    if AV_SCAN_START_SNS_ARN is None:
        return
    message = {
        "bucket": s3_object.bucket_name,
        "key": s3_object.key,
        "version": s3_object.version_id,
        AV_SCAN_START_METADATA: True,
        AV_TIMESTAMP_METADATA: datetime.utcnow().strftime("%Y/%m/%d %H:%M:%S UTC")
    }
    sns_client = boto3.client("sns")
    sns_client.publish(
        TargetArn=AV_SCAN_START_SNS_ARN,
        Message=json.dumps({'default': json.dumps(message)}),
        MessageStructure="json"
    )

def sns_scan_results(s3_object, result):
    if AV_STATUS_SNS_ARN is None:
        return
    message = {
        "bucket": s3_object.bucket_name,
        "key": s3_object.key,
        "version": s3_object.version_id,
        AV_STATUS_METADATA: result,
        AV_TIMESTAMP_METADATA: datetime.utcnow().strftime("%Y/%m/%d %H:%M:%S UTC")
    }
    sns_client = boto3.client("sns")
    sns_client.publish(
        TargetArn=AV_STATUS_SNS_ARN,
        Message=json.dumps({'default': json.dumps(message)}),
        MessageStructure="json"
    )


def lambda_handler(event, context):
    s3_object = event_object(event)
    start_time = datetime.utcnow()
    print("Script starting at %s\n" %
          (start_time.strftime("%Y/%m/%d %H:%M:%S UTC")))
    scan_object(s3_object)
    print("Script finished at %s\n" %
          datetime.utcnow().strftime("%Y/%m/%d %H:%M:%S UTC"))


def scan_object(s3_object):
    verify_s3_object_version(s3_object)
    try:
        is_object_scannable(s3_object)
    except SizeError as e:
        print(e.msg)
        return
    sns_start_scan(s3_object)
    file_path = download_s3_object(s3_object, "/tmp")
    clamav.update_defs_from_s3(AV_DEFINITION_S3_BUCKET, AV_DEFINITION_S3_PREFIX)
    scan_result = clamav.scan_file(file_path)
    print("Scan of s3://%s resulted in %s\n" % (os.path.join(s3_object.bucket_name, s3_object.key), scan_result))
    if "AV_UPDATE_METADATA" in os.environ:
        set_av_metadata(s3_object, scan_result)
    set_av_tags(s3_object, scan_result)
    sns_scan_results(s3_object, scan_result)
    metrics.send(env=ENV, bucket=s3_object.bucket_name, key=s3_object.key, status=scan_result)
    # Delete downloaded file to free up room on re-usable lambda function container
    try:
        os.remove(file_path)
    except OSError:
        pass

def str_to_bool(s):
    return bool(strtobool(str(s)))

def main():
    parser = OptionParser()
    parser.add_option("--file", dest="file", help="File containing list of bucket/key values to scan")
    (options, args) = parser.parse_args()

    if options['file'] is None:
        # copy down the current log file, if it exists
        try:
            LOG.download_file(LOGFILE)
            LOG.delete()
            keyfile = LOGFILE
        except botocore.exceptions.ClientError as e:
            sys.exit()
    else:
        keyfile = options['file']
    
    lf = open(keyfile,"r")

    clamav.update_defs_from_s3(AV_DEFINITION_S3_BUCKET, AV_DEFINITION_S3_PREFIX)
    for object in lf.readlines():
        s3_pieces = re.match("^(.+?)\/(.+)", object)
        bucket_name = s3_pieces.group(1)
        key = s3_pieces.group(2)
        s3_object = s3.Object(bucket_name, key)
        print("Scanning " + object)
        sns_start_scan(s3_object)
        file_path = download_s3_object(s3_object, LARGE_FILE_TEMP_PATH)
        scan_result = clamav.scan_file(file_path)
        print("Scan of s3://%s resulted in %s\n" % (os.path.join(s3_object.bucket_name, s3_object.key), scan_result))
        if "AV_UPDATE_METADATA" in os.environ:
            set_av_metadata(s3_object, scan_result)
        set_av_tags(s3_object, scan_result)
        sns_scan_results(s3_object, scan_result)
        metrics.send(env=ENV, bucket=s3_object.bucket_name, key=s3_object.key, status=scan_result)
        try:
            os.remove(file_path)
        except OSError:
            pass


if __name__ == '__main__':
    main()
