#!/usr/bin/env python
"""
logrotate_s3.py
Author: Mike Babineau <michael.babineau@gmail.com>
Licensed under the GPL
"""
import os, gzip, ConfigParser, time, shutil
from optparse import OptionParser
from boto.s3.connection import S3Connection, Key

def rotate(file_src):
	"""Rotate log"""
	# Build new name ("<unix time>.<hostname>.r.log") and move file
	file_dst = "%s/%s.%s.r.log" % (os.path.dirname(file_src), int(time.time()), os.uname()[1])
	shutil.move(file_src, file_dst)
	
	# Touch src file using append instead of write just in case
	open(file_src, 'a').close()
	
	return file_dst
	
	
def compress(file_in, file_out):
	"""Compress a file using gzip"""
	f = open(file_in, 'rb')
	zf = gzip.open(file_out, 'wb')
	zf.writelines(f)
	f.close()
	zf.close()
# Uncomment to delete uncompressed file
#	os.remove(file_in)


def upload_to_s3(file, key, bucket, aws_access_key_id, aws_secret_access_key):
	"""Upload a file to S3"""
	# Build S3 connector
	conn = S3Connection(aws_access_key_id, aws_secret_access_key)

	# Use specified bucket, creating it if it does not exist
	b = conn.create_bucket(bucket)
	
	# Upload file
	k = Key(b)
	k.key = key
	k.set_contents_from_filename(file)


def main():
	# Parse arguments
	parser = OptionParser()
	parser.add_option("-c", "--config", dest="configfile", help="configuration file")
	parser.add_option("-f", "--file", dest="file", help="file to be compressed and uploaded")
	(options, args) = parser.parse_args()
	file_in = options.file
	configfile = options.configfile

	# Parse config file
	config = ConfigParser.ConfigParser()
	config.read(configfile)

	# Set vars based on values from config file
	aws_access_key_id = config.get("AWS", "aws_access_key_id")
	aws_secret_access_key = config.get("AWS", "aws_secret_access_key")
	bucket = config.get("Log", "bucket")
	key_prefix = config.get("Log", "key_prefix")

	# Rotate, compress, and upload to S3
	file_rot = rotate(file_in)
	file_out = file_rot+".gz"
	key = key_prefix+os.path.basename(file_out)
	compress(file_rot, file_out)
	upload_to_s3(file_out, key, bucket, aws_access_key_id, aws_secret_access_key)
	
	
if __name__ == "__main__":
	main()
	