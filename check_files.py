#!/usr/bin/env python3

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is used to check that all installation files (except ignored and exceptions) have the expected permissions, owner, group ...
# It is a free software; you can redistribute it and/or modify it under the terms of GPLv2


import json
import argparse
import os
import grp
import pwd
import stat
import sys
from collections import Counter


_filemode_list = [
    {stat.S_IFLNK : "l",
    stat.S_IFREG: "-",
    stat.S_IFBLK: "b",
    stat.S_IFDIR: "d",
    stat.S_IFCHR: "c",
    stat.S_IFIFO: "p"},

    {stat.S_IRUSR: "r"},

    {stat.S_IWUSR: "w"},

    {stat.S_IXUSR | stat.S_ISUID: "s",
    stat.S_ISUID: "S",
    stat.S_IXUSR: "x"},

    {stat.S_IRGRP: "r"},

    {stat.S_IWGRP: "w"},

    {stat.S_IXGRP | stat.S_ISGID: "s",
    stat.S_ISGID: "S",
    stat.S_IXGRP: "x"},

    {stat.S_IROTH: "r"},

    {stat.S_IWOTH: "w"},

    {stat.S_IXOTH | stat.S_ISVTX: "t",
    stat.S_ISVTX: "T",
    stat.S_IXOTH: "x"}
]
# ---------------------------------------------------------------------------------------------------------------

# Aux functions

# ---------------------------------------------------------------------------------------------------------------

"""
    Convert a file's mode to a string of the form '-rwxrwxrwx'.
    Parameters:
        - mode: st_mode field of a file or directory from os.stat_result (Example: 16893)
    Return:
        String of the permissions set '-rwxrwxrwx'
    Example:
        33204 --> -rw-rw-r--
"""

def get_filemode(mode):
    permission = []
    for items in _filemode_list:                                        #walk through the list of dict 
        for k,v in items.items():                                       
            if mode & k == k:                                           #and function betwen the mode and the key of the dict
                permission.append(v)                                    #store the value of the dict
                break
        else:
            permission.append('-')                                      #add - in case no match
    return "".join(permission)

# ---------------------------------------------------------------------------------------------------------------

"""
    Get the checkfile data from a file or directory.
    Parameters:
        - item: filepath or directory.
    Return:
        Dictonary with checkfile data.
    Example:
        '/var/ossec/active-response' -->
            {
                "group": "wazuh",
                "mode": "750",
                "prot": "drwxr-x---",
                "type": "directory",
                "user": "root"
            }
"""

def get_data_information(item):
    try:
        stat_info = os.stat(item)                                           #get item information in a 10 lenght arrary

        user = pwd.getpwuid(stat_info.st_uid)[0]                            #Return the password database entry for the given numeric user ID.
        group = grp.getgrgid(stat_info.st_gid)[0]
        mode = oct(stat.S_IMODE(stat_info.st_mode))                         #octal mode
        mode_str = str(mode).replace('o', '')                               #replace o = octal mode for a ''
        if len(mode_str) > 3:
            mode = mode_str[-3:]                                            #get last 3 digits (just we need)
        else:
            mode = mode_str
        protection = get_filemode(stat_info.st_mode)        
        if os.path.isdir(item):                                             #check if it is a directory or a file
            type = "directory"
        else:
            type = "file"

        return {'group': group, 'mode': mode, 'type': type, 'user': user, 'prot': protection}
   
    except FileNotFoundError:
        return {'group': None, 'mode': None, 'type': None, 'user': None, 'prot': None}
    except OSError: #Permission denied
        pass



# ---------------------------------------------------------------------------------------------------------------

"""
    Get a dictionary with all checkfile information from all files and directories located in a specific path
    Parameters:
        -path: Path to begin extract information.
        -ignore_folders: Forders to be ignored
    Return:
        Dictonary with all check files corresponding to the analized path. It has the following format:
        "/var/ossec/active-response":{
                "group": "wazuh",
                "mode": "0750",
                "prot": "drwxr-x---",
                "type": "directory",
                "user": "root"
        }, ...
"""

def get_current_items(path='/', ignore_folders=[]):
    files_items_dict = {}                                                   
    flag_no_file_detected = False                                           #flag to indicate if a file/folder was found
    for (dirpath, dirnames, filenames) in os.walk(path, followlinks=False): #walk through the path
        dirpath = remove_ending_bar_chars(dirpath)                          #remove ending "/" in case it has it
        aux_dirpath = remove_initial_bar_chars(dirpath)                     #remove beginning "/" in case it has it
        path_list = Counter(aux_dirpath.split('/'))                         #create a counter element (list of element separated by "/")
        
        for item_ignored in ignore_folders:                                 #walk through ignored folders
            item_ignored = remove_initial_bar_chars(item_ignored)           #remove beginning "/" in case it has it
            substract_folders = Counter(item_ignored.split('/')) - path_list#create a counter element (list of element separated by "/")
                                                                            #and substract conter element "path_list", if result is an empty dict
                                                                            #means that path match with the ignored element                   
            if substract_folders == {}:                                     #if empty, break loop and analize next element 
                flag_no_file_detected = True
                break
            else:
                flag_no_file_detected = False                               #element was not found yet and enable watch for properties
        if not flag_no_file_detected:
            files_items_dict[dirpath] = get_data_information(dirpath)       #store the directory element and they properties
            for filename in filenames:                                      
                file_path = f'{dirpath}/{filename}'                         
                if not file_path.endswith('.pyc') and not file_path in ignore_folders:
                    files_items_dict[file_path] = get_data_information(file_path)#store files element and they properties
        flag = False       
    return files_items_dict


# ---------------------------------------------------------------------------------------------------------------

"""
    Remove "/" character in the beginning of a path in case exists
    Parameters:
        - path: path to be analized
    Return:
        - path without initial "/" character

    Example:
        - /home/user becomes home/user
        
"""
def remove_initial_bar_chars(path):
    if path[0] == '/':
        path=path[1:]    #[1:]remove 1st char    
    return path

# ---------------------------------------------------------------------------------------------------------------

"""
    Remove "/" character in the the end of a path in case exists
    Parameters:
        - path: path to be analized
    Return:
        - path without ending "/" character

    Example:
        - /home/user becomes home/user
"""
def remove_ending_bar_chars(path):    
    if path[len(path) - 1] == '/':
        path=path[:-1]    #[:-1]remove last char
    return path

# ---------------------------------------------------------------------------------------------------------------

"""
    Class to be used in debug mode
    Parameters:
        - path: path to be analized
        - os: operated systen
        - ignore: path to be ignore
        - no_show_ignore_list: flag to show/hide ignore paths
"""

class Args:
    def __init__(self, path, os, ignore, no_show_ignore_list=False) -> None:
        self.path = path
        self.os =  os
        self.ignore = ignore
        self.no_show_ignore_list = no_show_ignore_list
        pass

# ---------------------------------------------------------------------------------------------------------------

"""
    Entry point 

    Execution example: 
    
    python3 check_files.py -p '/home/fede/Downloads' -o 'linux' -i '/var/ossec,/home/fede/Downloads/wazuh.json'
    
"""

# ---------------------------------------------------------------------------------------------------------------

DEBUG_MODE = False

if __name__ == "__main__":

    if not DEBUG_MODE:
        arg_parser = argparse.ArgumentParser()
        arg_parser.add_argument("-p", "--path", type=str, required=True, help="/home/user")
        arg_parser.add_argument("-o", "--os", type=str, required=True,  choices=['linux', 'windows', 'redhat', 'debian'], help="Operating system or host distribution")
        arg_parser.add_argument("-i", "--ignore", type=str, help="Ignore path: /var/ossec,/home")
        arg_parser.add_argument("-n", "--no_show_ignore_list", action="store_true", help="Show ignore list")
        args = arg_parser.parse_args()
    else:
        args = args = Args('/home/fede/Videos', 'linux', '/var/ossec,/home/fede/Videos/Wazuh-meets')
    
    try:
        print(str(args))
        print("Checking files...")

        template_file = f'{args.os}_files.json'                             #create output json file 
        original_path = args.path                                           #get current path to be analized
        no_show_ignore_list = args.no_show_ignore_list                      #flag that indicate if it will show ignored folder

        if args.ignore:                                                     #get ignored folder as a list
            ignore_folders = args.ignore.split(',')
        
        current_items = get_current_items(original_path, ignore_folders)    #get list of dict with the files information

       
        dictArray = {}
        element_list = []
        description_list = []
        i = 0       
        for name in sorted(current_items):                                  #order information to be stored in a json file
            id = i            
            try:
                group =  current_items[name]['group']
            except TypeError:
                group = '-'
            try:
                mode = current_items[name]['mode']
            except TypeError:
                mode = '-'
            try:
                prot = current_items[name]['prot']
            except TypeError:
                prot = '-'
            try:
                type = current_items[name]['type']
            except TypeError:
                type = '-'
            try:
                user = current_items[name]['user']
            except TypeError:
                user = '-'

            description_list.append({
                "group": group,
                "mode": mode,
                "prot": prot,
                "type": type,
                "user": user
            })

            element_list.append({
                "id": i,
                "name": name,
                "description" : description_list[i]                
            })            
            i = i + 1

        dictArray = {"data" : element_list}
        with open(template_file, 'w') as convert_file:                      #create a json file
            convert_file.write(json.dumps(dictArray))
        
        if len(ignore_folders) > 0 and not no_show_ignore_list:             #show ignored folders/files
            print("\nIgnored:")
            print('\n'.join(sorted(set(ignore_folders))))
       
        print("\nCongrats!.")

    except Exception as e:
        print(f'Error: {str(e)}')
        raise
        sys.exit(1)