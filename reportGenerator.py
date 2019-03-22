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

def generate_headers(user, password):
    data = '%s:%s' % (user, password)
    auth = base64.b64encode(data.encode('utf-8')).decode()
    headers = {
        'Authorization': 'Basic %s' % (auth,)
    }
    return headers

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
    parser = argparse.ArgumentParser(description='ReversingLabs Korea - Report Generator Using TiCloud api')
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

        hd = generate_headers(authdata['username'], authdata['password'])

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
            r0101 = requests.get(addr+'/api/databrowser/malware_presence/query/'+hash_type+'/'+hash_code+'?format='+result_format+'&extended=true',
                headers = hd )

            r0104 = requests.get(addr+'/api/databrowser/rldata/query/'+hash_type+'/'+hash_code+'?format='+result_format+'&extended=true',
                headers = hd )

            if r0101.status_code != 200:
                print(r0101.status_code)
                break

            if r0104.status_code != 200:
                print(r0104.status_code)
                break

            d = r0101.text # type : string
            jsontext = json.loads(d) # type : dict
            rl = jsontext['rl']
            rl_malwarepresence = rl['malware_presence']

            data_categorized_number[rl_malwarepresence['status']]+=1

            d2 = r0104.text
            jt2 = json.loads(d2)
            r0104_dict = jt2['rl']['sample']['analysis']['entries'][0]['tc_report']
            dos_header_dict = r0104_dict['metadata']['application']['pe']['dos_header']
            dos_header_keys = list(r0104_dict['metadata']['application']['pe']['dos_header'].keys())

            for k in dos_header_keys:
                if type(dos_header_dict[k]) is int :
                    dos_header_dict[k] = "0x{:08x}".format(dos_header_dict[k])

            print('dos_header:', r0104_dict['metadata']['application']['pe']['dos_header'])
            print("dos_header_keys:", dos_header_keys)

            rl_sample = jt2['rl']['sample']
            rl_sample_xref_entries = rl_sample['xref']['entries']
            data[hash_code]=[f, rl_malwarepresence['status']]
            #r0104_dict = json.loads(d2)

            savefile_name = str(index)+'_'+file_name

            data[hash_code]=[f, rl_malwarepresence['status'], savefile_name]
            filesize_formatted = format_bytes(rl_sample['sample_size'])

            ##
            tf = open("template.html", "r", encoding='utf-8')
            tmpl2 = Template(tf.read())
            with open('result\\'+savefile_name+'.html', "w", encoding='utf-8') as fp :
                fp.write(tmpl2.render(savefile_name = savefile_name, file_name = file_name, rl_malwarepresence = rl_malwarepresence, r0104_dict = r0104_dict, time_list = time_list, rl_sample = rl_sample, filesize_formatted = filesize_formatted))
                print(os.getcwd()+"\\"+'result\\'+savefile_name+'.html SAVED')

            ##
            tf = open("TiCloudpage_template.html", "r", encoding='utf-8')
            tmpl3 = Template(tf.read())
            with open('result\\'+savefile_name+'_TiCloud'+'.html', "w", encoding='utf-8') as fp :
                fp.write(tmpl3.render(savefile_name = savefile_name, file_name = file_name, rl_malwarepresence = rl_malwarepresence, time_list = time_list, rl_sample_xref_entries = rl_sample_xref_entries))
                print(os.getcwd()+"\\"+'result\\'+savefile_name+'_TiCloud.html SAVED')

            ##
            file_loader = FileSystemLoader('./')
            env = Environment(loader = file_loader)
            tmpl4 = env.get_template('dos_header_template.html')
            with open('result\\'+savefile_name+'_dos_header'+'.html', "w", encoding='utf-8') as fp :
                fp.write(tmpl4.render(dos_header_keys = dos_header_keys, savefile_name = savefile_name, file_name = file_name, rl_malwarepresence = rl_malwarepresence, r0104_dict = r0104_dict, time_list = time_list, rl_sample = rl_sample, filesize_formatted = filesize_formatted))
                print(os.getcwd()+"\\"+'result\\'+savefile_name+'_dos_header.html SAVED')

            index+=1

        stf = open("summarypage_template.html", "r", encoding='utf-8')
        summarytmpl = Template(stf.read())

        print(data_categorized_number)
        with open('result\\summarypage.html', "w", encoding='utf-8') as fp :
            fp.write(summarytmpl.render(data = data, time_list = time_list, data_categorized_number = data_categorized_number))
            print(os.getcwd()+"\\"+"result\\"+"summarypage.html"+" SAVED")

        print("data:", data)

    print("FINISH")


### "0x{:08x}".format(1998848) (Hex)
