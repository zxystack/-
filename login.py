# -*- coding:utf-8 -*-

import re
import json
import rsa
import binascii
import base64

import requests
import urllib 

class WeiboLogin(object):

	def __init__(self, user_name, password):
		self.user_name = user_name
		self.init_pwd = password
		self.session = requests.session()
		self.info = self.preLogin()
		self.cookies = []

	def preLogin(self):
		url = "https://login.sina.com.cn/sso/prelogin.php?entry=weibo&callback=sinaSSOController.preloginCallBack&su=MTg2MTE4MzM0NTI%3D&rsakt=mod&checkpin=1&client=ssologin.js(v1.4.19)&_=1519961025874"
		response = requests.get(url)
		content = response.text 
		info = re.findall(r'\{.*\}', content)[0]

		return json.loads(info)

	@property 
	def user_name_encrtpy(self):
		return base64.b64encode(self.user_name)

	def encropy(self):
		e = int('10001', 16)
		pubkey = int(self.info['pubkey'], 16)
		rsa_pubkey = rsa.PublicKey(pubkey, e)
		pwd = '\t'.join([str(self.info['servertime']), str(self.info['nonce'])]) + '\n' + self.init_pwd
		last_pwd = rsa.encrypt(pwd.encode('utf-8'), rsa_pubkey)
		last_pwd = binascii.b2a_hex(last_pwd)
		return last_pwd

	def login (self):
		post_data = {
			"entry": "weibo",
			"gateway": "1",
			"from":"",
			"savestate": "7",
			"qrcode_flag": "false",
			"useticket": "1",
			"pagerefer": "https://login.sina.com.cn/sso/login.php?url=https%3A%2F%2Fweibo.com%2Flogin.php&_rand=1519960999.578&gateway=1&service=miniblog&entry=miniblog&useticket=1&returntype=META&sudaref=https%3A%2F%2Fwww.google.co.jp%2F&_client_version=0.6.23",
			"vsnf":1,
			"su": self.user_name_encrtpy,
			"service":"miniblog",
			"servertime": self.info['servertime'],
			"nonce": self.info['nonce'],
			"pwencode": "rsa2",
			"rsakv": self.info['rsakv'],
			"sp": self.encropy(),
			"sr":1536*864,
			"encoding":"UTF-8",
			"prelt":"107",
			"url": "https://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack",
			"returntype":"META"
		}
		headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.87 Safari/537.36"
        }
		login_url = "https://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.19)"
		response = self.session.post(login_url, data=post_data, headers=headers)
		response.encoding = 'GBK'
		html = response.text
		# url = re.findall('location\.replace\((.*)\)', html)[0]
		# response = requests.get(urllib.unquote(url.strip()), headers=headers)
		# page = response.text 
		#这里的cookies已经可以登陆了
		cookies = self.session.cookies.get_dict()
		self.cookies.append(cookies)
		content = self.session.get("https://weibo.com", cookies=cookies)
		html = content.text 
		

if __name__ == '__main__':
	l = WeiboLogin('username', 'password')
	l.login()
