# DNSChina

DNS反污染代理。同pydnsproxy类似，原理不同。**** 目前仅仅我个人使用，hackers请自便。请小白绕步。 ****

#### 功能

* 采用UDP询问，速度快于TCP
* 优先尝试本地ISP的DNS，必要情况下尝试境外DNS
* 自定义hosts
* 可以定义整个域名的IP（如*.googleapis.com）
* Akamai加速（包括对返回结果中CNAME的识别，如.edgesuite.net）
* Google北京加速
* 单进程
* 反深圳电信DNS的404劫持
* 可以很容易修改代码定制


# 安装

请确保Python版本为2.5~2.7之间。
获取代码

	git clone https://github.com/ccp0101/dnschina
修改dnsproxy.py
	prefs = {
		"upstream_domestic" : "202.96.134.33", 
		"upstream_foreign" : "8.8.8.8", 
		"listen_addr" : ("127.0.0.1", 53), 
	}
将202.96.134.33改为本地ISP的DNS服务器。然后运行
	python dnsproxy.py
DNS服务就启动了。mac用户可以测试
	dig @127.0.0.1 www.youtube.com
	dig @127.0.0.1 www.google.com
返回的应该是有效IP。
