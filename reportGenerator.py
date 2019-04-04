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

def get_indicator_dict():
    indicator_dict = { 0: ['NETWORK', 'Has network related indicators'], \
                        1: ['EVASION', 'Tries to evade common debuggers/sandboxes/analysis tools'],\
                        2: ['STEALTH', 'Tries to hide its presence'],\
                        3: ['AUTOSTART', 'Tampers with autostart settings'],\
                        4: ['MEMORY', 'Tampers with memory of foreign processes'],\
                        5: [],\
                        6: ['ANOMALY', 'Contains unusual characteristics'],\
                        7: ['MONITOR', 'Able to monitor host activities'],\
                        8: [],\
                        9: ['REGISTRY', 'Accesses registry and configuration files in an unusual way'],\
                        10: ['EXECUTION', 'Creates other processes or starts other applications'],\
                        11: ['PERMISSIONS', 'Tampers with or requires permissions'],\
                        12: ['SEARCH', 'Enumerates or collects information from a system'],\
                        13: ['SETTINGS', 'Tampers with system settings'],\
                        14: ['MACRO', 'Contains macro functions or scripts'],\
                        15: [],\
                        16: [],\
                        17: ['SIGNATURE', 'Matches a known signature'],\
                        18: ['STEAL', 'Steals and leaks sensitive information'],\
                        19: [],\
                        20: [],\
                        21: [],\
                        22: ['FILE', 'Accesses files in an unusual way'],\
                        }

    return indicator_dict


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

            print(index, '/', len(file_list), '| Generating report -', file_name)

            ticoredata = requests.get('%s/api/samples/%s/ticore/' % (addr, hash_code),
                            headers = {'Authorization': 'Token %s' % token})

            ticore = json.loads(ticoredata.text)

            post_data = {"hash_values": hash_code, "fields": ["id", "sha1", "sha256", "sha512", "md5", "category", "file_type", "file_subtype", "identification_name",\
                   "identification_version", "file_size", "extracted_file_count", "local_first_seen", "local_last_seen",\
                   "classification_origin", "classification_reason",\
                   "threat_status", "trust_factor", "threat_level", "threat_name",\
                   "summary", "ticloud", "aliases"]}

            listdata = requests.post('%s/api/samples/list/' % addr,
                            data = post_data,
                            headers = {'Authorization': 'Token %s' % token})

            if listdata.status_code != 200:
                print('status : ', listdata.status_code)
            else:
                result = json.loads(listdata.text)

                if result['count'] is 0 :
                    print('result not found- hash', hash_code)
                else:
                    result = result['results'][0]

                    # for detail page
                    savefile_name = str(index)+'_'+file_name

                    # for summary page
                    data[hash_code] = [f, result['threat_status'], savefile_name]
                    data_categorized_number[result['threat_status'].lower()]+=1

                    # data processing
                    filesize_formatted = format_bytes(result['file_size'])
                    result['file_size'] = filesize_formatted

                    # make menu dict
                    ticore_keys = list(ticore.keys())

                    print("result status:", result['threat_status'])

                    # write summary page
                    file_loader = FileSystemLoader('./')
                    env = Environment(loader = file_loader)
                    tmpl_detail = env.get_template('summarypage_template.html')
                    with open('result\\%s.html' % savefile_name , "w", encoding='utf-8') as fp :
                        fp.write(tmpl_detail.render(ticore = ticore, time_list = time_list, savefile_name = savefile_name, result = result))
                        print(os.getcwd()+"\\result\\%s.html SAVED" % savefile_name)

                    # write info-file page
                    tmpl_detail2 = env.get_template('info-file_template.html')
                    with open('result\\%s+info_file.html' % savefile_name, "w", encoding='utf-8') as fp :
                        fp.write(tmpl_detail2.render(ticore = ticore, time_list = time_list, savefile_name = savefile_name, result = result))
                        print(os.getcwd()+"\\result\\%s+info_file.html SAVED" % savefile_name)

                    # write info-hashes page
                    tmpl_detail = env.get_template('info-hashes_template.html')
                    with open('result\\%s+info_hashes.html' % savefile_name, "w", encoding='utf-8') as fp :
                        fp.write(tmpl_detail.render(ticore = ticore, time_list = time_list, savefile_name = savefile_name, result = result))
                        print(os.getcwd()+"\\result\\%s+info_hashes.html SAVED" % savefile_name)

                    # write app-capabilities Page
                    try:
                        capabilities = ticore['application']['capabilities']
                        tmpl_detail = env.get_template('app-capabilities.html')
                        with open('result\\%s+capabilities.html' % savefile_name, "w", encoding='utf-8') as fp :
                            fp.write(tmpl_detail.render(ticore = ticore, time_list = time_list, savefile_name = savefile_name, result = result, capabilities = capabilities))
                            print(os.getcwd()+"\\result\\%s+capabilities.html SAVED" % savefile_name)

                    except KeyError:
                        print("Key Capabilities not found")

                    # write app-dos_header page
                    try:
                        dos_header_dict = ticore['application']['pe']['dos_header']
                        dos_header_keys = list(dos_header_dict.keys())

                        for k in dos_header_keys:
                            if type(dos_header_dict[k]) is int :
                                dos_header_dict[k] = "0x{:08x}".format(dos_header_dict[k])

                        tmpl_detail3 = env.get_template('app-dos_header.html')
                        with open('result\\%s+dos_header.html' % savefile_name, "w", encoding='utf-8') as fp :
                            fp.write(tmpl_detail3.render(ticore = ticore, time_list = time_list, savefile_name = savefile_name, result = result, dos_header_keys = dos_header_keys ))
                            print(os.getcwd()+"\\result\\%s+dos_header.html SAVED" % savefile_name)

                    except KeyError:
                        print("Key dos_header not found")

                    # write app-file_header Page
                    try:
                        file_header_dict = ticore['application']['pe']['file_header']
                        file_header_keys = list(file_header_dict.keys())

                        for k in file_header_keys:
                            if k == "pointer_to_symbol_table" or k == "number_of_symbols" or k == "size_of_optional_headers" or k == "time_date_stamp" :
                                file_header_dict[k] = "0x{:08x}".format(file_header_dict[k])

                        tmpl_detail = env.get_template('app-file_header.html')
                        with open('result\\%s+file_header.html' % savefile_name, "w", encoding='utf-8') as fp :
                            fp.write(tmpl_detail.render(ticore = ticore, time_list = time_list, savefile_name = savefile_name, result = result, file_header_keys = file_header_keys))
                            print(os.getcwd()+"\\result\\%s+file_header.html SAVED" % savefile_name)

                    except KeyError:
                        print("Key file_header not found")

                    # write app-version_info page
                    try:
                        version_info = ticore['application']['pe']['version_info']

                        tmpl_detail = env.get_template('app-version_info.html')
                        with open('result\\%s+version_info.html' % savefile_name, "w", encoding='utf-8') as fp :
                            fp.write(tmpl_detail.render(ticore = ticore, time_list = time_list, savefile_name = savefile_name, result = result))
                            print(os.getcwd()+"\\result\\%s+version_info.html SAVED" % savefile_name)

                    except KeyError:
                        print("Key version_info not found")

                    # write app-imports page
                    try:
                        imports = ticore['application']['pe']['imports']

                        tmpl_detail = env.get_template('app-imports.html')
                        with open('result\\%s+imports.html' % savefile_name, "w", encoding='utf-8') as fp :
                            fp.write(tmpl_detail.render(ticore = ticore, time_list = time_list, savefile_name = savefile_name, result = result, imports = imports))
                            print(os.getcwd()+"\\result\\%s+imports.html SAVED" % savefile_name)

                    except KeyError:
                        print("Key imports not found")

                    # write app-sections page
                    try:
                        sections = ticore['application']['pe']['sections']
                        
                        for section in sections :
                            section['size'] = format_bytes(section['size'])
                            section['address'] = "0x{:08x}".format(section['address'])
                            section['offset'] = "0x{:08x}".format(section['offset'])

                        tmpl_detail = env.get_template('app-sections.html')
                        with open('result\\%s+sections.html' % savefile_name, "w", encoding='utf-8') as fp :
                            fp.write(tmpl_detail.render(ticore = ticore, time_list = time_list, savefile_name = savefile_name, result = result, sections = sections))
                            print(os.getcwd()+"\\result\\%s+sections.html SAVED" % savefile_name)

                    except KeyError:
                        print("Key sections not found")

                    # write indicator page
                    if len(ticore['indicators']) is not 0 :
                        indicators = {}
                        for i in ticore['indicators']:
                            if i['category'] in indicators:
                                indicators[i['category']].append(i['description'])
                            else:
                                indicators[i['category']] = [i['description']]
                        indicator_dict = get_indicator_dict()
                        tmpl_detail = env.get_template('ticore-indicator.html')
                        with open('result\\%s+indicator.html' % savefile_name, "w", encoding='utf-8') as fp :
                            fp.write(tmpl_detail.render(ticore = ticore, time_list = time_list, savefile_name = savefile_name, result = result, indicators = indicators, indicator_dict = indicator_dict))
                            print(os.getcwd()+"\\result\\%s+indicator.html SAVED" % savefile_name)

                    index+=1

    print("Generating Summary Report Page ...")

    stf = open("mainpage_template.html", "r", encoding='utf-8')
    summarytmpl = Template(stf.read())
    with open('result\\summarypage.html', "w", encoding='utf-8') as fp :
        fp.write(summarytmpl.render(data = data, time_list = time_list, data_categorized_number = data_categorized_number))
        print(os.getcwd()+"\\"+"result\\"+"summarypage.html"+" SAVED")

    print("Complete to generate", index-1, "files")

### "0x{:08x}".format(1998848) (Hex)
