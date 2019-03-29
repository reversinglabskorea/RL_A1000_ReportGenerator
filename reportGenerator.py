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

def get_utc_local_time():
    time_list = []

    utc_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    local_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    time_list.append(utc_time)
    time_list.append(local_time)

    return time_list

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='ReversingLabs Korea - Report Generator Using A1000 api')
    parser.add_argument('--auth', metavar='AUTH', required=True, help='auth data file')
    parser.add_argument('-u', '--upload', metavar='SAMPLE', required=True, help='sample list file to upload')

    meta = None
    # meta data check
    args = vars(parser.parse_args())

    hash_type = 'sha1'
    result_format = 'json' # can be xml

    time_list = get_utc_local_time()

    if args['upload'] != None and args['auth'] != None:
        authdata = get_auth_file(args['auth'])
        addr = authdata['addr']
        token = authdata['token']
        file_list = get_upload_file_list(args['upload'])
        index = 1

        data = {}
        data_categorized_number = {"known":0, "unknown":0, "suspicious":0, "malicious":0}

        for f in file_list:
            if f[0] is "~" :
                hash_code = f[1:]
                file_name = f[1:]
            else:
                response = requests.post('%s/api/uploads/' % addr, files={'file': open(f, 'rb')},
                            headers = {'Authorization': 'Token %s' % token})

                response_json = json.loads(response.text)

                hash_code = response_json["detail"]['sha1']
                file_name = os.path.basename(f)

            #print("hash_code:", hash_code)

            ticoredata = requests.get('%s/api/samples/%s/ticore/' % (addr, hash_code),
                            headers = {'Authorization': 'Token %s' % token})

            ticore = json.loads(ticoredata.text)

            post_data = {"hash_values": hash_code, "fields": ["id", "sha1", "sha256", "sha512", "md5", "category", "file_type", "file_subtype", "identification_name",\
                   "identification_version", "file_size", "extracted_file_count", "local_first_seen", "local_last_seen",\
                   "classification_origin", "classification_reason",\
                   "threat_status", "trust_factor", "threat_level", "threat_name",\
                   "summary", "ticloud", "aliases"]}
            print(post_data)
            listdata = requests.post('%s/api/samples/list/' % addr,
                            data=post_data,
                            headers = {'Authorization': 'Token %s' % token})

            if listdata.status_code != 200:
                print('status : ', listdata.status_code)
            else:
                result = json.loads(listdata.text)

                if result['count'] is 0 :
                    print('result not found- hash', hash_code)
                else:
                    result = result['results'][0]

                    savefile_name = str(index)+'_'+file_name

                    data[hash_code] = [f, result['threat_status'], savefile_name]
                    data_categorized_number[result['threat_status'].lower()]+=1

                    filesize_formatted = format_bytes(result['file_size'])
                    result['file_size'] = filesize_formatted
                    ##
                    file_loader = FileSystemLoader('./')
                    env = Environment(loader = file_loader)
                    tmpl_detail = env.get_template('summarypage_template.html')
                    with open('result\\%s.html' % savefile_name , "w", encoding='utf-8') as fp :
                        fp.write(tmpl_detail.render(ticore = ticore, time_list = time_list, savefile_name = savefile_name, result = result))
                        print(os.getcwd()+"\\result\\%s.html SAVED" % savefile_name)

                    tmpl_detail2 = env.get_template('info-file_template.html')
                    with open('result\\%s+info_file.html' % savefile_name, "w", encoding='utf-8') as fp :
                        fp.write(tmpl_detail2.render(ticore = ticore, time_list = time_list, savefile_name = savefile_name, result = result))
                        print(os.getcwd()+"\\result\\%s+info_file.html SAVED" % savefile_name)

                    index+=1

    stf = open("mainpage_template.html", "r", encoding='utf-8')
    summarytmpl = Template(stf.read())

    with open('result\\summarypage.html', "w", encoding='utf-8') as fp :
        fp.write(summarytmpl.render(data = data, time_list = time_list, data_categorized_number = data_categorized_number))
        print(os.getcwd()+"\\"+"result\\"+"summarypage.html"+" SAVED")

    print("FINISH")




### "0x{:08x}".format(1998848) (Hex)
