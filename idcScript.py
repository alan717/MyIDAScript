#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2019/5/13 17:54
# @Author  : libo
# @File    : idcScript.py

import idautils
import idc
import idaapi


#获取模块基地址
def get_module_base(moduleName):

    print moduleName
    module_base = idc.GetFirstModule()

    while module_base != None:
        module_name = idc.GetModuleName(module_base)
        if module_name.find(moduleName) >= 0:
            print module_name
            break
        module_base = idc.GetNextModule(module_base)

    return  module_base

#添加断点到 jni_load init_arary
def add_breakpointer():

    print '[*]Find linker begin...'
    libart = 'libjdbitmapkit.so'
    linker = 'linker'

    #JNI_OnLoad 下断点
    art_module_base = get_module_base(libart)
    if art_module_base != None:
        module_size = idc.GetModuleSize(art_module_base)
        print '[*] %s base=>0x%08X, Size=0x%08X' % (libart,art_module_base, module_size)
       
       # 小米6
        # addr = art_module_base + 0x234FC8 #0x23FFC8
        # idc.AddBpt(addr)   

        # addr = art_module_base + 0x23FFC8 #0x23FFC8
        # idc.AddBpt(addr)

        #大佬手机 art jni_load
        #addr = art_module_base + 0x00012F4C
        offset=0x000114E0  #######加密函数点first_challenge->switch:sub_114E0开始
        addr = art_module_base + offset
        print "bp : %08X,%08X"% (addr,offset)
        idc.AddBpt(addr)
        offset=0x00012D2E ####这个是114E0加密后
        addr = art_module_base + offset  # 乘法
        print "bp : %08X,%08X"% (addr,offset)
        idc.AddBpt(addr)
		
		###########################这个是特殊点。永远不会触发的。在这里设置是为了测试这个
        offset=0x00013522  #####sub_13478 下边的v6==0的情况。理论上200% 不会触发这个断点
        addr = art_module_base + offset  # gettimeofday
        print "bp : %08X,%08X"% (addr,offset)
        idc.AddBpt(addr)
        # offset=0x00012F4C
        # addr = art_module_base + offset  # 除法
        # print "bp : %08X,%08X"% (addr,offset)
        # idc.AddBpt(addr)
        # offset=0x00012F60
        # addr = art_module_base + offset  # 判断大小
        # print "bp : %08X,%08X"% (addr,offset)
        # idc.AddBpt(addr)  
    # #init_ary 下断点
    # linkerModuleBase = get_module_base(linker)
    # if linkerModuleBase != None:
    #      moduleSize = idc.GetModuleSize(linkerModuleBase)
    #      print '[*] linker base=>0x%08X, Size=0x%08X' % (linkerModuleBase, moduleSize)
    #      addr = linkerModuleBase + 0x00006718
    #      idc.AddBpt(addr)


def make_fun_name():#修改函数名称

    libDexHelp = 'libDexHelper.so'

    DexHelperModuleBase = get_module_base(libDexHelp)
    if DexHelperModuleBase != None:
        moduleSize = idc.GetModuleSize(DexHelperModuleBase)
        print '[*] libDexHelper.so base=>0x%08X, Size=0x%08X' % (DexHelperModuleBase, moduleSize)


        # idc.MakeName(DexHelperModuleBase + 0xD0E4 ,"strcpy")
        # idc.MakeName(DexHelperModuleBase + 0xD09C, "memset")
        # idc.MakeName(DexHelperModuleBase + 0xD060, "strlen")
        # idc.MakeName(DexHelperModuleBase + 0xD0A8, "getpid")
        # idc.MakeName(DexHelperModuleBase + 0xD1A4, "sprintf")
        # idc.MakeName(DexHelperModuleBase + 0xD18C, "opendir")
        # idc.MakeName(DexHelperModuleBase + 0xD198, "readdir")
        # idc.MakeName(DexHelperModuleBase + 0xD1C8, "atoi")
        # idc.MakeName(DexHelperModuleBase + 0xD2E8, "readlink")
        # idc.MakeName(DexHelperModuleBase + 0xD15C, "strstr")  
        # idc.MakeName(DexHelperModuleBase + 0xD120, "fopen")
        # idc.MakeName(DexHelperModuleBase + 0xD168, "fgets")
        # idc.MakeName(DexHelperModuleBase + 0xD258, "fread")
        # idc.MakeName(DexHelperModuleBase + 0xD150, "fclose")
        # idc.MakeName(DexHelperModuleBase + 0xD228, "memcmp")
        # idc.MakeName(DexHelperModuleBase + 0xD228, "memcmp")
        # idc.MakeName(DexHelperModuleBase + 0xD090, "malloc")
        # idc.MakeName(DexHelperModuleBase + 0xD1BC, "closedir")
        # idc.MakeName(DexHelperModuleBase + 0x100CC, "StrDecrypt")

        idc.AddBpt(DexHelperModuleBase + 0x1CCC4)  #反调试点上一行 挂了
        idc.AddBpt(DexHelperModuleBase + 0x1CCFE)  #反调试点上一行 挂了

        #idc.AddBpt(DexHelperModuleBase + 0X1CCC4)  #反调试点
        #idc.AddBpt(DexHelperModuleBase + 0X34DD0)  #启动反调试线程
        #idc.AddBpt(DexHelperModuleBase + 0X34FF6)  #启动反调试线程

        idc.PatchDword(DexHelperModuleBase,0x00BF00BF)

        
    else:
        print ""

def get_fun_name():
    print '[*] memset address => 0x%08X' % idc.LocByName("memset")

def dump_module(name):

    module_base = get_module_base(name)
   
    if None != module_base:
        module_size = idc.GetModuleSize(module_base)
        print '[*] libart.so base=>0x%08X, Size=0x%08X' % (module_base, module_size)
    
        data = idaapi.dbg_read_memory(module_base, module_size)
        fp = open('C:\\Users\\Administrator\\Desktop\\art.so', 'wb+')
        fp.write(data)
        fp.close()


def add_all_breakpionter():
    idautils.Functions()

def main():

    # add_all_breakpionter()
     add_breakpointer()
    # make_fun_name()
    # dump_module('libart.so')
    # make_fun_name()
    # GetFunName()

main()