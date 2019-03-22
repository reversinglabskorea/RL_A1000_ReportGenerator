#!/usr/bin/python
#-*- coding: utf-8 -*-

from jinja2 import Template, Environment, FileSystemLoader

import sys
import os
import requests
import base64
import json
import argparse
import urllib.request
import hashlib

from datetime import datetime

from sampleUpload import upload_sample

def get_auth_file(fileaddr):
    try:
        with open(fileaddr, "r") as f:
            data = {}
            while True:
                line = f.readline().rstrip('\n')
                if not line: break
                data[line.split(' ')[0]] = line.split(' ')[1]
            return data
    except IOError as err:
        print("IOError:", err)

def get_upload_file_list(fileaddr):
    try:
        upload_list = []
        with open(fileaddr, "r", encoding='UTF-8') as f:
            while True:
                line = f.readline().rstrip('\n')
                if not line: break
                upload_list.append(line)
            return upload_list
    except IOError as err:
        print("IOError:", err)

def format_bytes(bytes_num):
    sizes = [ "B", "KB", "MB", "GB", "TB" ]

    i = 0
    dblbyte = bytes_num

    while (i < len(sizes) and  bytes_num >= 1024):
        dblbyte = bytes_num / 1024.0
        i = i + 1
        bytes_num = bytes_num / 1024

    return str(round(dblbyte, 2)) + " " + sizes[i]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='ReversingLabs Korea - Report Generator Using A1000 api')
    parser.add_argument('--auth', metavar='AUTH', required=True, help='auth data file')
    parser.add_argument('-u', '--upload', metavar='SAMPLE', required=True, help='sample list file to upload')

    meta = None
    # meta data check
    args = vars(parser.parse_args())

    hash_type = 'sha1'
    result_format = 'json' # can be xml

    time_list = []

    utc_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    local_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    time_list.append(utc_time)
    time_list.append(local_time)

    if args['upload'] != None and args['auth'] != None:
        authdata = get_auth_file(args['auth'])
        addr = authdata['addr']
        token = authdata['token']
        file_list = get_upload_file_list(args['upload'])
        su = upload_sample(addr)
        index = 1

        data = {}
        data_categorized_number = {"KNOWN":0, "UNKNOWN":0, "SUSPICIOUS":0, "MALICIOUS":0}


        for f in file_list:
            if f[0] is "~" :
                hash_code = f[1:]
                file_name = f[1:]
            else:
                hash_code = su.upload(authdata['username'], authdata['password'], f, meta)
                file_name = os.path.basename(f)

            print("hash_code:", hash_code)

            rootdata = requests.get(addr+'/api/samples/'+hash_code+'/ticore/',
                            headers ={'Authorization': 'Token %s' % token})

            root = json.loads(rootdata.text)

            savefile_name = str(index)+'_'+file_name

            ##
            tf = open("template.html", "r", encoding='utf-8')
            tmpl2 = Template(tf.read())
            with open('result\\'+savefile_name+'.html', "w", encoding='utf-8') as fp :
                fp.write(tmpl2.render(root = root, time_list = time_list, file_name = file_name))
                print(os.getcwd()+"\\"+'result\\'+savefile_name+'.html SAVED')

            index+=1

    print("FINISH")

"""
        stf = open("summarypage_template.html", "r", encoding='utf-8')
        summarytmpl = Template(stf.read())

        print(data_categorized_number)
        with open('result\\summarypage.html', "w", encoding='utf-8') as fp :
            fp.write(summarytmpl.render(data = data, time_list = time_list, data_categorized_number = data_categorized_number))
            print(os.getcwd()+"\\"+"result\\"+"summarypage.html"+" SAVED")

        print("data:", data)
"""



### "0x{:08x}".format(1998848) (Hex)
