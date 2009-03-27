#!/usr/bin/env python
# encoding: utf-8
"""
aws_logmover.py

Script for moving logs files into and out of S3 using SQS messages for reference.
Supports two modes:
push - Renames a file (<unix time>.<hostname>.log.gz), uploads it to S3, and creates an SQS message containing the S3 location
pull - Reads in an SQS message, downloads the referenced file, then removes the message from the SQS queue

Requirements:
-boto, a Python interface for Amazon Web Services (http://code.google.com/p/boto/).
-AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, read in from same-named environment 
variables, from boto.cfg (see boto manual), or from a specified config file (see README).

Created by Mike Babineau <michael.babineau@gmail.com>.
Copyright (c) 2009 ShareThis. All rights reserved.
"""

import os, sys, ConfigParser, gzip, time, shutil, boto
from optparse import OptionParser
from boto.s3.connection import S3Connection, Key
from boto.sqs.connection import SQSConnection
from boto.sqs.message import Message


USAGE = 'See "aws_logmover.py -h" for usage'
config = ConfigParser.ConfigParser()

class AWSLog:
	working_file = None
	aws_id = boto.config.get('Credentials','aws_access_key_id')
	aws_key = boto.config.get('Credentials','aws_secret_access_key')
	
	def __init__(self, src=None):
		if src:
			self.working_file = src
	
	def rename_local_file(self, src=None, dst=None):
		"""
		Rename a file
		"""
		if not src:	src = self.working_file
		if not dst: dst = "%s/%s.%s.log.gz" % (os.path.dirname(src), int(os.path.getmtime(src)), os.uname()[1])
		shutil.move(src, dst)
		self.working_file = dst
		return self.working_file
		
	def push_s3_file(self, bucket, src=None, key=None):
		"""
		Upload a file to an S3 bucket
		"""
		if not src:	src = self.working_file
		if not key: key = os.path.basename(src)
		conn = boto.connect_s3(self.aws_id, self.aws_key)
		b = conn.create_bucket(bucket)
		k = Key(b)
		k.key = key
		k.set_contents_from_filename(src)
		self.working_file = '%s/%s' % (bucket, key)
		return self.working_file
		
	def push_sqs_message(self, queue, msg=None):
		"""
		Add a message to an SQS queue
		"""
		if not msg: msg = self.working_file
		conn = boto.connect_sqs(self.aws_id, self.aws_key)
		q = conn.create_queue(queue)
		m = Message()
		m.set_body(msg)
		status = q.write(m)
		return status

	def pull_sqs_message(self, queue, timeout=60):
		"""
		Get a message from an SQS queue
		"""
		conn = boto.connect_sqs(self.aws_id, self.aws_key)
		q = conn.create_queue(queue)
		m = q.read(timeout)
		return m

	def delete_sqs_message(self, queue, message):
		"""
		Delete a message from an SQS queue
		"""
		conn = boto.connect_sqs(self.aws_id, self.aws_key)
		q = conn.create_queue(queue)
		q.delete_message(message)

	def pull_s3_file(self, bucket, key, dst):
		"""
		Get a file from an S3 bucket
		"""
		conn = boto.connect_s3(self.aws_id, self.aws_key)
		b = conn.create_bucket(bucket)
		k = Key(b)
		k.key = key
		k.get_contents_to_filename(dst)


def push_log(src_file, queue, bucket):
	log = AWSLog(src_file)
	
	sys.stdout.write("Renaming...")
	try:
		log.rename_local_file()
	except (IOError, OSError):
		print '\nError: Unable to rename file.  Verify both the source file and destination path exist and the necessary permissions are set.'
		sys.exit(1)
	else:
		print "done"
		
	sys.stdout.write("Uploading to S3...")
	try:
		log.push_s3_file(bucket)
	except boto.exception.S3CreateError:
		print '\nError: Bucket "%s" already exists and is owned by someone else.' % bucket
		sys.exit(1)
	else:
		print "done"

	sys.stdout.write("Adding to SQS...")
	try:
		log.push_sqs_message(queue)
	except:
		print '\nError: Unable to add message to queue "%s"' % queue
		sys.exit(1)
	else:
		print "done"
		sys.exit(0)


def pull_log(queue, dst_dir):
	log = AWSLog()

	m = log.pull_sqs_message(queue)

	msg = m.get_body()
	bucket = msg.split("/",1)[0]
	key = msg.split("/",1)[1]
	filename = key.split("/")[-1]
	dst = '%s/%s' % (dst_dir, filename)

	print 'Downloading S3 file %s/%s to %s' % (bucket, filename, dst)
	try:
		log.pull_s3_file(bucket, key, dst)
	except:
		print 'Error: Unable to write S3 file %s/%s to %s' % (bucket, key, dst)
		sys.exit(1)
	else:
		print 'Complete'
		log.delete_sqs_message(queue, m)
		sys.exit(0)


def main():
	# Parse arguments
	parser = OptionParser()
	parser.add_option("-m", "--mode", dest="mode", metavar="MODE", help="mode of the task (\"push\" or \"pull\")")	
	parser.add_option("-q", "--queue", dest="queue", help="Amazon SQS queue name (ex: \"acme_queue_1\")")
	parser.add_option("-f", "--file", dest="src_file", metavar="FILE", help="(push) file to be moved (ex: \"/var/log/httpd.log.1.gz\")")
	parser.add_option("-b", "--bucket", dest="bucket", help="(push) Amazon S3 bucket name (ex: \"acme_bucket_1\")")
	parser.add_option("-o", "--output-dir", dest="dst_dir", metavar="DIR", help="(pull) output directory for retrieved file (ex: \"/tmp/scratch\")")
	(options, args) = parser.parse_args()
	mode = options.mode
	src_file = options.src_file
	bucket = options.bucket
	queue = options.queue
	dst_dir = options.dst_dir
	
	if not mode:
		print 'Error: Mode must be specified'
		print USAGE
		sys.exit(1)
	
	if mode == 'pull':		
		if not dst_dir or not queue:
			print 'Error: Queue and output directory must be specified for "pull" mode'
			print USAGE
			sys.exit(1)
		else:
			pull_log(queue, dst_dir)
	elif mode == 'push':
		if not src_file or not queue or not bucket:
			print 'Error: File, queue, and bucket must be specified "push" mode'
			print USAGE
			sys.exit(1)
		else:
			push_log(src_file, queue, bucket)
	
if __name__ == '__main__':
	main()
