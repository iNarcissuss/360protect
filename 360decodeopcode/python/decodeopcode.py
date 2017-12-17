#coding: UTF-8

import os
import shutil
import struct
import sys

#workpath="E:\\cyclopaedia\\all_shell\\360\\20170919_mydemoproduce_AllDalvikOpcodeDemo\\360decodeopcode\\"

#2017824_360加固1.5.1.x版---------------
workpath=os.getcwd()+"\\20170824_1.5.1.x"
decode_key=0xBC
switch_table_addr=0x35D04

#2017919_360加固1.5.1.5版---------------
#workpath=os.getcwd()+"\\20170919_1.5.1.5"
#decode_key=0xD0
#switch_table_addr=0x35CCC  

#2017925_360加固1.5.3.0版和10月30---------------
jiami_decode_temp=workpath+"\\360jiami_decode_temp"  	#第一次解密临时存放文件
decode_success=workpath+"\\360decode_success"				#解密后的指令
opcodemaptable=workpath+"\\360opcodemaptable.config"	#解密指令用到的映射表
switchtable=workpath+"\\360switch_table.config"  	#switch表
jiami_decode=workpath+"\\360jiami_decode"  			#被360加密的dalvik指令等待解密

#第一次解密然后将值存入360jiami_decode_temp中
def firstjiemidecode():  
	fp=open(jiami_decode,"rb")
	if not fp:
		print ("cannot open the fp %s for writing" % jiami_decode)
	filedata = fp.read() 
	filesize = fp.tell()
	#print "filesize="+str(filesize)
	fp.close()
	filedata2 = bytearray(filedata)
	for i in range(0,filesize):
		filedata2[i]=filedata2[i]^decode_key
	fpw=open(jiami_decode_temp,"wb")
	if not fpw:
		print ("cannot open the fpw %s for writing" % jiami_decode_temp)
	fpw.write(filedata2)
	fpw.close()


#根据指令映射表和偏移得到真正的指令的值和指令的长度
def getrealopcodevalue(opcodeoff):
	fp=open(opcodemaptable,"r")
	if not fp:
		print ("cannot open the fp %s for writing" % opcodemaptable)
	map_table=fp.readlines()
	for map_table_line in map_table:
		map_table_line_str=map_table_line.split(",")
		if 5==len(map_table_line_str):#排除掉注释
			if	0x0==map_table_line_str[2]:  #发现不存在的指令，或者错误！！！！！！！
				print "------------------bad---------------------"
			if int(opcodeoff,16)==int(map_table_line_str[3],16):
				return (map_table_line_str[0],map_table_line_str[1],map_table_line_str[4])
	fp.close()

	
#根据360的的指令值，得到在ida中的偏移值
def getoff(opcode_360_value):
	opcode_360_2=opcode_360_value-1
	if -1==opcode_360_2:
		opcode_360_2=0xff
	print "switch case opcode_360_2="+str(hex(opcode_360_2))
	fp=open(switchtable,"r")
	if not fp:
		print ("cannot open the fp %s for writing" % switchtable)
	switch_table=fp.readlines()
	fp.close()
	return switch_table[opcode_360_2]
	
#第二次根据switch_table解密得到360decode_success
def secondjiemidecode():
	fp=open(jiami_decode_temp,"rb")
	if not fp:
		print ("cannot open the fp %s for writing" % jiami_decode_temp)
	filedata = fp.read() 
	filesize = fp.tell()
	fp.close()
	filedata2 = bytearray(filedata)
	print "filesize="+str(filesize)
	#print "filedata2[0]="+str(hex(filedata2[0]))
	sign=0
	while sign<filesize:	#根据映射表第二次解密
		print "------------------------------------"
		print "sign="+str(hex(sign))
		print "360jiami_decode_temp file sign="+str(hex(sign))
		opcodeoff=getoff(filedata2[sign])
		print "opcodeoff="+opcodeoff
		(realopvalue,realoplen,realopdec)=getrealopcodevalue(opcodeoff) #得到真正的指令值和长度
		print "realopvalue="+realopvalue+",realoplen="+realoplen+",realopdec="+realopdec	
		filedata2[sign]=int(realopvalue,16)
		sign=sign+int(realoplen,16)
		
	#把解密的数据写入文件
	fpw=open(decode_success,"wb")
	if not fpw:
		print ("cannot open the fpw %s for writing" % decode_success)
	fpw.write(filedata2)
	fpw.close()

def main():
	firstjiemidecode()
	secondjiemidecode()

	
main()