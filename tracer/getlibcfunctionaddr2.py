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

internal_functions_features={}
internal_functions_features['vasprintf']={'name':'vasprintf','searchbytes':'5557565381ECCC000000C70424640000008BBC24E0000000E8........85C089','startaddr':0x0}
internal_functions_features['vfprintf']={'name':'vfprintf','searchbytes':'5565A10000000089E557565381EC0C050000C7C1D4FFFFFF8B75088985ACFBFFFF8B04088985A8FBFFFF8B466885C00F','startaddr':0x0}
internal_functions_features['vsscanf']={'name':'vsscanf','searchbytes':'5381ECC80000008D5C2420891C24C744241000000000C744240C00000000C7442408FFFFFFFFC744240400800000C744246800000000E8........8B8424D0000000891C24C744240C00000000C74424080000000089442404C78424B400000040940C08E8........8B8424D8000000891C24C744240C00000000894424088B8424D400000089442404E83127FFFF81','startaddr':0x0}
internal_functions_features['__isoc99_vsscanf']={'name':'__isoc99_vsscanf','searchbytes':'5381ECC80000008D5C2420891C24C744241000000000C744240C00000000C7442408FFFFFFFFC744240400800000C744246800000000E8........8B8424D0000000891C24C744240C00000000C74424080000000089442404C78424B400000040940C08E8........8B8424D8000000891C24C744240C00000000834C245C10894424088B8424D400000089442404E8','startaddr':0x0}

sdb = {}
with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),'libc-sdb.json'), 'r+') as f:
    sdb = json.load(f)

def get_known_libc_functionaddr(file_path):

    ret = {}
    print('Scanning \"%s\"...' % file_path)
    # start radare instance
    r2 = r2pipe.open(file_path)
    # perform initial analysis
    r2.cmd('aa;aad')

    for (fn,fndata) in internal_functions_features.items():
        print "search [%s]=" % fn,fndata
        searchresult = r2.cmd('/x %s' % fndata['searchbytes'])
        print searchresult
        re_text = re.compile(ur"0x(.*?) hit")
        try:
            for item in re_text.finditer(searchresult):
                startaddr = item.group(1)
                fndata['startaddr'] = startaddr
                break
        except:
            pass

    #使用数据库进行匹配
    for (fn,fndata) in sdb.items():
        print "search [%s]=" % fn,fndata
        searchresult = r2.cmd('/x %s' % fndata['searchbytes'])
        print searchresult
        re_text = re.compile(ur"0x(.*?) hit")
        try:
            for item in re_text.finditer(searchresult):
                startaddr = item.group(1)
                fndata['startaddr'] = startaddr
                # if fndata['offset'] != ('0x%s' % startaddr):
                #     print "check [%s]=" % fn,fndata
                if "xprintf" in fn:
                    #search ['fprintf']
                    vfprintfaddr = internal_functions_features['vfprintf']['startaddr']
                    offset =  '%08x' % (int(vfprintfaddr,16)-int(startaddr,16)-0x1f)
                    searchbytes = fndata['searchbytes']
                    searchbytes = list(searchbytes)
                    searchbytes[-9-0] = offset[1]
                    searchbytes[-9-1] = offset[0]
                    searchbytes[-9-2] = offset[3]
                    searchbytes[-9-3] = offset[2]
                    searchbytes[-9-4] = offset[5]
                    searchbytes[-9-5] = offset[4]
                    searchbytes[-9-6] = offset[7]
                    searchbytes[-9-7] = offset[6]
                    searchresulti = r2.cmd('/x %s' % ''.join(searchbytes))
                    rei_text = re.compile(ur"0x(.*?) hit")
                    for itemx in rei_text.finditer(searchresulti):
                        fprintfaddr = item.group(1)
                        ret[fprintfaddr] = 'fprintf'
                        break

                    vfprintfaddr = internal_functions_features['vsscanf']['startaddr']
                    offset =  '%08x' % (int(vfprintfaddr,16)-int(startaddr,16)-0x1f)
                    searchbytes = fndata['searchbytes']
                    searchbytes = list(searchbytes)
                    searchbytes[-9-0] = offset[1]
                    searchbytes[-9-1] = offset[0]
                    searchbytes[-9-2] = offset[3]
                    searchbytes[-9-3] = offset[2]
                    searchbytes[-9-4] = offset[5]
                    searchbytes[-9-5] = offset[4]
                    searchbytes[-9-6] = offset[7]
                    searchbytes[-9-7] = offset[6]
                    searchresulti = r2.cmd('/x %s' % ''.join(searchbytes))
                    rei_text = re.compile(ur"0x(.*?) hit")
                    for itemx in rei_text.finditer(searchresulti):
                        fprintfaddr = item.group(1)
                        ret[fprintfaddr] = 'sscanf'
                        break

                    vfprintfaddr = internal_functions_features['__isoc99_vsscanf']['startaddr']
                    offset =  '%08x' % (int(vfprintfaddr,16)-int(startaddr,16)-0x1f)
                    searchbytes = fndata['searchbytes']
                    searchbytes = list(searchbytes)
                    searchbytes[-9-0] = offset[1]
                    searchbytes[-9-1] = offset[0]
                    searchbytes[-9-2] = offset[3]
                    searchbytes[-9-3] = offset[2]
                    searchbytes[-9-4] = offset[5]
                    searchbytes[-9-5] = offset[4]
                    searchbytes[-9-6] = offset[7]
                    searchbytes[-9-7] = offset[6]
                    searchresulti = r2.cmd('/x %s' % ''.join(searchbytes))
                    rei_text = re.compile(ur"0x(.*?) hit")
                    for itemx in rei_text.finditer(searchresulti):
                        fprintfaddr = item.group(1)
                        ret[fprintfaddr] = '__isoc99_sscanf'
                        break

                ret['0x%s' % startaddr] =  fndata['name']
        except:
            pass

    r2.quit()

    return ret

if __name__ == "__main__":
    known_libc_functions = get_known_libc_functionaddr('/home/wb/rhg/samples/functionidentify/cb-s')
    print known_libc_functions
    #check 0x080a4fa0 if it's a known functions
    if '0x080a4fa0' in known_libc_functions.keys():
        print 'found known function: %s ' %  known_libc_functions['0x080a4fa0']
    else:
        print 'failed'
