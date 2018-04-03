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
internal_functions_features['vasprintf']={'name':'vasprintf','searchbytes':'5589e55756be........5381ecb40000008b....c7............e8........85c089c30f84........8d..........893424c7............c744241000000000c744240c00000000c7..............c7..............e8........893424c7............895c240cc7..............895c2404e8........8b....83a554fffffffe893424894424088b....c7............c7............89442404e8........85c089c60f88........8b..........8b..........8b..........83c30129d029d3d1e839c372..8b..........895c2404890424e8........85c0890774..c64418ff0081c4b400000089f05b5e5f5dc30f1f4000891c24e8........85c0890774..8d53ff895424088b..........89042489542404e8........8b..........890424e8........8b..85c075..8b..........8907eb..0f1f008b..........890424','startaddr':0x0}
internal_functions_features['vfprintf']={'name':'vfprintf','searchbytes':'8d......83e4f0ff71fc5589e581ecac050000c7..........89b424a4050000658b..........898c249c050000899c24a005000089bc24a80500008b....8b..8b....8b....89..........','startaddr':0x0}
internal_functions_features['vsscanf']={'name':'vsscanf','searchbytes':'5589e55381ecb40000008d..........891c24c7............c744241000000000c744240c00000000c7..............c7..............e8........8b....891c24c7............c744240c0000000089442404c744240800000000e8........8b....891c24c744240c00000000894424088b....89442404e8........81c4b40000005b5dc3','startaddr':0x0}
internal_functions_features['__isoc99_vsscanf']={'name':'__isoc99_vsscanf','searchbytes':'5589e55381ecb40000008d..........891c24c7............c744241000000000c744240c00000000c7..............c7..............e8........8b....891c24c7............c744240c0000000089442404c744240800000000e8........8b....891c24834d9810894424088b....c744240c0000000089442404e8........81c4b40000005b5dc3','startaddr':0x0}
internal_functions_features['vdprintf']={'name':'vdprintf','searchbytes':'5589e5565381ec680100008d..........8d..........8944240cc7............c7..............c744240800000000c7..............891c24e8........c7............891c24e8........8b....891c2489442404e8........85c00f84........8b..........891c2425f3efffff83c84489..........8b....894424088b....89442404e8........83f8ff89c674..8b....85c07e..8b....8b....8b....891c248954240429d0c1f80289442408e8........83f8ff0f94c084c0b8........0f45f08b....c744240400000000891c24ff....81c46801000089f05b5e5dc30f1f4400008b..........8b..........891c248954240429d089442408e8........83f8ff0f94c0eb..891c24be........e8fd','startaddr':0x0}
internal_functions_features['vsnprintf']={'name':'vsnprintf','searchbytes':'5589e581ec040100008b....89....8b....89....89....85c00f85........8d....c7..................89de8d..........c7..................c744241000000000c744240c00000000c7..............c7..............893c24e8........c7............c606008b..........8974240c89742404893c2489442408e8........8b....893c24894424088b....89442404e8........39..........74..8b..........c602008b....8b....8b....89ec5dc39083e80189..........8d....e95effff','startaddr':0x0}

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
        re_text =  re.compile(ur"0x(.*?) hit(.*?) (.*)") #re.compile(ur"0x(.*?) hit(\s*?) (.*?)")
        try:
            for item in re_text.finditer(searchresult):
                startaddr = item.group(1)
                if fndata['searchbytes'][:2] in item.group(3)[:3]:
                    fndata['startaddr'] = startaddr
                if int(fndata['offset'],16) != int(startaddr,16) and ("xprintf" not in fn):
                     print "check [%s]=" % fn,fndata
                if "xprintf" in fn:
                    #search ['fprintf']
                    vfprintfaddr = internal_functions_features['vfprintf']['startaddr']
                    offset =  '%08x' % (int(vfprintfaddr,16)-int(startaddr,16)-0x1f)
                    searchbytes = fndata['searchbytes']
                    searchbytes = list(searchbytes)
                    searchbytes[-5-0] = offset[1]
                    searchbytes[-5-1] = offset[0]
                    searchbytes[-5-2] = offset[3]
                    searchbytes[-5-3] = offset[2]
                    searchbytes[-5-4] = offset[5]
                    searchbytes[-5-5] = offset[4]
                    searchbytes[-5-6] = offset[7]
                    searchbytes[-5-7] = offset[6]
                    searchresulti = r2.cmd('/x %s' % ''.join(searchbytes))
                    rei_text = re.compile(ur"0x(.*?) hit")
                    for itemx in rei_text.finditer(searchresulti):
                        fprintfaddr = item.group(1)
                        ret[fprintfaddr] = 'fprintf'
                        break

                    vfprintfaddr = internal_functions_features['vdprintf']['startaddr']
                    offset =  '%08x' % (int(vfprintfaddr,16)-int(startaddr,16)-0x1f)
                    searchbytes = fndata['searchbytes']
                    searchbytes = list(searchbytes)
                    searchbytes[-5-0] = offset[1]
                    searchbytes[-5-1] = offset[0]
                    searchbytes[-5-2] = offset[3]
                    searchbytes[-5-3] = offset[2]
                    searchbytes[-5-4] = offset[5]
                    searchbytes[-5-5] = offset[4]
                    searchbytes[-5-6] = offset[7]
                    searchbytes[-5-7] = offset[6]
                    searchresulti = r2.cmd('/x %s' % ''.join(searchbytes))
                    rei_text = re.compile(ur"0x(.*?) hit")
                    for itemx in rei_text.finditer(searchresulti):
                        fprintfaddr = item.group(1)
                        ret[fprintfaddr] = 'printf'
                        break


                    vfprintfaddr = internal_functions_features['vasprintf']['startaddr']
                    offset =  '%08x' % (int(vfprintfaddr,16)-int(startaddr,16)-0x1f)
                    searchbytes = fndata['searchbytes']
                    searchbytes = list(searchbytes)
                    searchbytes[-5-0] = offset[1]
                    searchbytes[-5-1] = offset[0]
                    searchbytes[-5-2] = offset[3]
                    searchbytes[-5-3] = offset[2]
                    searchbytes[-5-4] = offset[5]
                    searchbytes[-5-5] = offset[4]
                    searchbytes[-5-6] = offset[7]
                    searchbytes[-5-7] = offset[6]
                    searchresulti = r2.cmd('/x %s' % ''.join(searchbytes))
                    rei_text = re.compile(ur"0x(.*?) hit")
                    for itemx in rei_text.finditer(searchresulti):
                        fprintfaddr = item.group(1)
                        ret[fprintfaddr] = 'asprintf'
                        break

                    vfprintfaddr = internal_functions_features['vsnprintf']['startaddr']
                    offset =  '%08x' % (int(vfprintfaddr,16)-int(startaddr,16)-0x1f)
                    searchbytes = fndata['searchbytes']
                    searchbytes = list(searchbytes)
                    searchbytes[-5-0] = offset[1]
                    searchbytes[-5-1] = offset[0]
                    searchbytes[-5-2] = offset[3]
                    searchbytes[-5-3] = offset[2]
                    searchbytes[-5-4] = offset[5]
                    searchbytes[-5-5] = offset[4]
                    searchbytes[-5-6] = offset[7]
                    searchbytes[-5-7] = offset[6]
                    searchresulti = r2.cmd('/x %s' % ''.join(searchbytes))
                    rei_text = re.compile(ur"0x(.*?) hit")
                    for itemx in rei_text.finditer(searchresulti):
                        fprintfaddr = item.group(1)
                        ret[fprintfaddr] = 'snprintf'
                        break

                    vfprintfaddr = internal_functions_features['vsscanf']['startaddr']
                    offset =  '%08x' % (int(vfprintfaddr,16)-int(startaddr,16)-0x1f)
                    searchbytes = fndata['searchbytes']
                    searchbytes = list(searchbytes)
                    searchbytes[-5-0] = offset[1]
                    searchbytes[-5-1] = offset[0]
                    searchbytes[-5-2] = offset[3]
                    searchbytes[-5-3] = offset[2]
                    searchbytes[-5-4] = offset[5]
                    searchbytes[-5-5] = offset[4]
                    searchbytes[-5-6] = offset[7]
                    searchbytes[-5-7] = offset[6]
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
                    searchbytes[-5-0] = offset[1]
                    searchbytes[-5-1] = offset[0]
                    searchbytes[-5-2] = offset[3]
                    searchbytes[-5-3] = offset[2]
                    searchbytes[-5-4] = offset[5]
                    searchbytes[-5-5] = offset[4]
                    searchbytes[-5-6] = offset[7]
                    searchbytes[-5-7] = offset[6]
                    searchresulti = r2.cmd('/x %s' % ''.join(searchbytes))
                    rei_text = re.compile(ur"0x(.*?) hit")
                    for itemx in rei_text.finditer(searchresulti):
                        fprintfaddr = item.group(1)
                        ret[fprintfaddr] = '__isoc99_sscanf'
                        break
                else:
                    if fndata['searchbytes'][:2] in item.group(3)[:3]:
                        ret['0x%s' % startaddr] =  fndata['name']
        except:
            pass

    r2.quit()

    return ret

if __name__ == "__main__":
    known_libc_functions = get_known_libc_functionaddr('/home/wb/Downloads/80-YY_IO_BS_005_eip')
    print known_libc_functions
    #check 0x080a4fa0 if it's a known functions
    if '0x080a4fa0' in known_libc_functions.keys():
        print 'found known function: %s ' %  known_libc_functions['0x080a4fa0']
    else:
        print 'failed'
