#coding=utf-8
import dpkt
import struct
import hashlib
import socket
from OpenSSL import crypto
import json
import time
 
def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET,inet)
    except:
        return False

# logfile = open('log.txt', 'w')
all_cert_chains = []

def read_tcp_packets(pcap, tcp_piece):
    # 读入所有的tcp包，个数计入count
    count=0
    for ts, buf in pcap:
        count+=1
        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        
        ippack=eth.data
        if not (isinstance(ippack.data, dpkt.tcp.TCP) and len(ippack.data.data)):
            continue
        tcppack=ippack.data
        ssldata=tcppack.data

        src_ip=inet_to_str(ippack.src)
        dst_ip=inet_to_str(ippack.dst)
        src_port=tcppack.sport
        dst_port=tcppack.dport

        #定义了一个四元组（源IP，目的IP，源端口，目的端口）
        tuple4=(src_ip, dst_ip, src_port, dst_port)
        seq=tcppack.seq
        if tuple4 not in tcp_piece:
            tcp_piece[tuple4]={}
        tcp_piece[tuple4][seq]=ssldata # 按sequence number保存tcp.data
    return count

def build_tcp_stream(tcp_piece):
    #A->B和B->A是按两个流统计的，所以遍历一边源，就可以遍历到所有情况。
    for t4,dic in tcp_piece.items():    #根据4元组进行组流
        src_ip=t4[0]
        src_port=t4[2]
        #md5_dstip_dstport=md5.md5(t4[1]+str(t4[3])).hexdigest()
        seq=min(dic.keys()) # 选取最小的sequence number
        sslcombined=dic[seq]
        piecelen=len(dic[seq])
        while(seq+piecelen in dic):
            seq=seq+piecelen
            sslcombined+=dic[seq] # 拼接tcp stream
            piecelen=len(dic[seq])
        totallen=len(sslcombined)
        # 四元组对应流
        tcp_piece[t4] = sslcombined

def get_server_names(tcp_piece, server_names):
    # 获取Server Name
    for t4, sslcombined in tcp_piece.items():
        # totallen = len(sslcombined)
        # curpos=0
        try:
            record = dpkt.ssl.TLSRecord(sslcombined)
        except Exception as e: # dpkt.ssl.SSL3Exception as exception:
            continue
        if (record.type != 22):
            continue
        hello = record.data
        if hello[0] != 1: # handshake type: client hello
            continue
        
        session_id_len = hello[38]
        hello = hello[39+session_id_len:]
        cipher_suites_len = struct.unpack('!H', hello[:2])[0]
        hello = hello[2+cipher_suites_len:]
        compression_methods_len = hello[0]
        hello = hello[1+compression_methods_len:]
        # extensions_len = struct.unpack('!H', hello[:2])[0]
        # hello = hello[2:2+extensions_len]
        extensions = dpkt.ssl.parse_extensions(hello)
        server_name = ""
        for i, v in extensions:
            if i == 0:
                # name_list_len = struct.unpack('!H', v[:2])[0]
                name_type = v[3]
                if name_type == 0: # Server Name Type: host_name (0)
                    name_len = struct.unpack('!H', v[3:5])[0]
                    server_name = v[5:5+name_len].decode()
                break
        server_names[t4] = server_name

def extract_file(filepath):
    if not filepath.endswith('cap'):
        return

    print('Extract: %s' % (filepath))
    
    f = open(filepath,'rb')
    try:
        pcap = dpkt.pcap.Reader(f)
    except:
        print ("Error reading cap: %s", filepath)
        return

    tcp_piece={}
    read_tcp_packets(pcap, tcp_piece)
    f.close()

    build_tcp_stream(tcp_piece)

    server_names={}
    get_server_names(tcp_piece, server_names)
        
    for t4, sslcombined in tcp_piece.items():
        totallen = len(sslcombined)
        curpos=0
        while(curpos<totallen):
            #如果特别小，直接跳过
            if totallen-curpos<12: break
            # Content Type: Handshake
            if sslcombined[curpos]!=0x16:
                break
            handshake_len=struct.unpack('!H', sslcombined[curpos+3:curpos+5])[0]
            curpos+=5 # handshake protocol start
            cur_handshakelen=0
            while(cur_handshakelen<handshake_len and curpos<totallen):
                this_handshake_len=struct.unpack('!I', b'\x00'+sslcombined[curpos+1:curpos+4])[0]
                cur_handshakelen+=this_handshake_len+4
                # 证书链开始
                if sslcombined[curpos]== 0x0b: # '\x0b': #如果这一段是证书
                    certlen=struct.unpack('!I', b'\x00'+sslcombined[curpos+4:curpos+7])[0]
                    if certlen>totallen:    #证书的长度超过了数据包的长度，通常是数据包数据丢失导致的
                        break                    
                    curpos+=7 # certificates start
                    sub_cert_len=0 #所有子证书的总大小            
                    sub_cert_count=1 #子证书编号，编号形成证书链，越靠下越小
                    cert_chain = []
                    cert_chain_data = []
                    while(sub_cert_len<certlen):
                        this_sub_len=struct.unpack('!I', b'\x00'+sslcombined[curpos:curpos+3])[0]   #当前子证书大小
                        curpos+=3
                        this_sub_cert=sslcombined[curpos:curpos+this_sub_len]
                        sub_cert_len+=this_sub_len+3    #+3是“证书长度”，3个字节
                        curpos+=this_sub_len
                        md5cert = hashlib.md5(this_sub_cert).hexdigest()
                        filename='%s.der' % md5cert
                        with open('certs/%s'%filename, 'wb') as f:
                            f.write(this_sub_cert)
                        # print(filename)
                        # 
                        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, this_sub_cert)
                        CN = cert.get_subject().CN
                        ISSUER_CN = cert.get_issuer().CN
                        # print("CN:", CN)
                        # print("ISSUER_CN:", ISSUER_CN)
                        sub_cert_count+=1
                        cert_chain.append({"CN": CN, "ISSUER_CN": ISSUER_CN, "md5": md5cert})
                        cert_chain_data.append(this_sub_cert)
                    # 证书链结束
                    # tuple4=(src_ip, dst_ip, src_port, dst_port)
                    # 但这里要反着放源和目的，因为我们的源都记录的是客户端
                    t4_reverse = (t4[1], t4[0], t4[3], t4[2])
                    all_cert_chains.append({"src_ip": t4[1], "dst_ip": t4[0], "src_port": t4[3], "dst_port": t4[2], "server_name": None if t4_reverse not in server_names else server_names[t4_reverse] , "cert_chain_len": len(cert_chain), "cert_chain": cert_chain})
                    # 验证证书链
                    pass
                    # 写入文件

                else:
                    curpos+=this_handshake_len+4  #不是证书直接跳过
    with open('log.txt', 'w') as logfile:
        json.dump(all_cert_chains, logfile, indent="\t")

extract_file('pcaps/1.pcap')
