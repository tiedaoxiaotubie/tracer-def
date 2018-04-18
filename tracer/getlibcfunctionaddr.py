#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os, sys, errno
import r2pipe
import re
import json

###################################################################################
#使用方法：1、安装radare
#~ $ wget http://cloud.rada.re/get/1.6.0/radare2-1.6.0.tar.gz
#~ $ tar xzvf radare2-1.6.0.tar.gz
#~ $ cd radare2-1.6.0/
#~/radare2-1.6.0 $ ./configure --prefix=/usr
#~/radare2-1.6.0 $ make -j8
#~/radare2-1.6.0 $ sudo make install
#2、安装 r2pipe
#~ $  pip install r2pipe
#3、正常使用，将libc-sdb.json(数据库文件)和getlibcfunctionaddr.py(分析匹配模块)拷贝到自己项目中
#   调用get_known_libc_functionaddr(fullpath_to_target_binary)即可
#由于分析过程比较耗时，建议：
#程序启动时执行一次分析，将结果存放到全局变量中,后续直接通过全局变量查表即可获取识别的函数名称。
###################################################################################


# Do not load r2 plugins to speedup startup times
os.environ['R2_NOPLUGINS'] = '1'

cur_script_path = os.path.split(os.path.realpath(__file__))[0]

sdb = {}
libc_sdb_file = os.path.join(cur_script_path, 'libc-sdb_defcc.json')
with open(libc_sdb_file, 'r+') as f:
    sdb = json.load(f)
    print len(sdb)

funcs = []

new_function_name_file = os.path.join(cur_script_path, 'new_function_name.txt')
with open(new_function_name_file, 'r') as f:
    for line in f.readlines():
        funcs.append(line[:-1]) # strip '\n'

def get_known_libc_functionaddr(file_path):

    ret = {}
    print('Scanning \"%s\"...' % file_path)
    # start radare instance
    r2 = r2pipe.open(file_path)
    # perform initial analysis
    r2.cmd('aaa')

    # Get code section first to avoid FP.
    sections = r2.cmd('S')
    re_text = re.compile(ur"va=(0x.*?) sz=(0x.*?) vsz=(0x.*?) .text")
    text_start = 0x0
    text_end   = 0x0
    for item in re_text.finditer(sections):
        text_info  = item.groups(1)
        text_start = int(text_info[0], 16)
        text_end   = int(text_info[1], 16) + text_start
        break

    for fn_info in sdb:
        fn_name  = fn_info['name']
        if fn_name not in funcs:
            continue
        fn_bytes = fn_info['bytes']

        searchresult = r2.cmd('/x %s' % fn_bytes)
        print searchresult
        re_text = re.compile(ur"0x(.*?) hit")
        try:
            for item in re_text.finditer(searchresult):
                startaddr = item.group(1)
                startaddr_num = int(startaddr, 16)
                if startaddr_num >= text_start and startaddr_num <= text_end:
                    ret['0x%s' % startaddr] = fn_name 
        except Exception as e:
            print e
            pass

    r2.quit()

    return ret

if __name__ == "__main__":
    known_libc_functions = get_known_libc_functionaddr('/home/epeius/DefCC/test_cbs_recompile/pwn02_cb')
    print known_libc_functions
