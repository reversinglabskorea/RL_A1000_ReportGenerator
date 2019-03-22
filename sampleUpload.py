#!/usr/bin/python
#-*- coding: utf-8 -*-

import argparse

import hashlib
import sys
import os

import io

import json
import base64

import urllib.request

default_metadata_template = \
"""<?xml version="1.0" encoding="UTF-8"?>
<rl>
<properties>
<property>
<name>file_name</name>
<value>{0}</value>
</property>
</properties>
<domain></domain>
</rl>"""

class file_stream(io.FileIO):
    def __init__(self, file_name):
        super(file_stream, self).__init__(file_name, mode='rb')
        sha1 = hashlib.sha1()
        self.size = 0
        while True:
            data = self.read(8192)
            sha1.update(data)
            self.size += len(data)
            if len(data) != 8192:
                break

        self.seek(0)
        self.sha1 = sha1.hexdigest()

    def __len__(self):
        return self.size

class upload_sample:
    def __init__(self, addr):
        self.sample_service = addr
        print(self.sample_service)

    def generate_headers(self, user, password):
        data = '%s:%s' % (user, password)
        auth = base64.b64encode(data.encode('utf-8')).decode()
        headers = {
            'Authorization': 'Basic %s' % (auth,)
        }
        return headers

    def check(self, sha1):
        try:
            if len(sha1.decode('hex')) != 20:
                raise ValueError('invalid sha1 hash')
        except TypeError:
            raise ValueError('invalid sha1 hash')

    def upload_sample(self, user, password, sha1, data):
        url = '%s/api/spex/upload/%s' % (self.sample_service, sha1)

        headers = self.generate_headers(user, password)
        headers['Content-Type'] = 'application/octet-stream'

        req = urllib.request.Request(url, data, headers)
        response = urllib.request.urlopen(req)

        response.read()

    def upload_meta(self, user, password, sha1, data):
        url = '%s/api/spex/upload/%s/meta' % (self.sample_service, sha1)

        headers = self.generate_headers(user, password)
        headers['Content-Type'] = 'application/octet-stream'

        req = urllib.request.Request(url, data, headers)
        response = urllib.request.urlopen(req)

        response.read()

    def upload_meta_from_file(self, user, password, sha1, path):
        data = file(path, 'rb').read()

        self.upload_meta(user, password, sha1, data)

    def upload_default_meta(self, user, password, sha1, sample):
        file_name = os.path.basename(sample)

        data = default_metadata_template.format(file_name).encode('utf-8')

        self.upload_meta(user, password, sha1, data)

    def upload(self, user, password, sample_path, meta):
        data = file_stream(sample_path)
        sha1 = data.sha1

        self.upload_sample(user, password, sha1, data)

        if meta != None:
            self.upload_meta_from_file(user, password, sha1, meta)
        else:
            self.upload_default_meta(user, password, sha1, sample_path)

        return sha1
