# fetion
fetion for pidgin

该版本不再维护，建议使用 Openfetion 和其pidgin插件。

在跨平台即时通信软件Pidgin上实现中国移动的飞信协议。源码fork自Gradetwo的代码，现仍使用git管理，由standin000集中维护： http://github.com/standin000/fetion

目前支持飞信的聊天、发送长短信、查看用户信息等飞信基本功能。

*2010.7.31版本借鉴openfetion实现了飞信v4的登录协议，使用手机号可以正常登录啦*

如果遇到SSL失效的问题，请删除 `~/.purple/certificates/x509/tls_peers/` 下面的证书。

如果是升级，`*-SysCfg.xml`得删掉，旧的dll/so也要删掉。`*`是手机号码。

建议在此提交Bug，提交时请附带pidgin -d的输出，或附带pidgin“调试窗口”中的内容。


简介

先安装pidgin，再下载编译好的.dll或.so文件，将其放置到指定位置即可。

Linux
Linux版本的Pidgin插件后缀为.so，可放置在如下位置之一：

~/.purple/plugins
/usr/lib/purple-2/
Windows
请补充Windows版插件的存放位置

Delete comment Comment by ste.live.dk, Aug 17, 2010
Windows版插件的存放位置是默认路径的 %HOMEDRIVE%(系统分区):\Program Files\Pidgin\plugins\，或者自定义路径的X:\...\Pidgin\plugins\

2010/08/01

在Google Code建立项目，方便发布信息、下载及Bug tracking
2010/07/31(pull from cxcxcxcx)
使用v4协议登录，插件又能使用了~
2010/05/21(pull from cxcxcxcx)
改进了下载头像代码
修正了性别显示为“女”的问题
2010/05/08
AUR页面建立，ArchLinux?的朋友有福了
2010/04/11
感谢cxcxcxcx网友的建议，现在支持给离线好友发直接消息，如果好友确实不在线，服务器那端会变成短信发给对方
2010/03/04
biAji网友编译了64位插件
2010/02/07
为拒绝好友请求的用户加记号。补上长短信功能，因为之前版本弄乱了。居然没人报告这个Bug，:(
2010/01/04
为未通过好友请求的用户区加记号，类似官方的？号。
2009/7/27
修正发送长短信给非飞信用户的问题，非飞信用户不能接收长短信。
2009/6/1
支持发送长短信，不受官方飞信180字限制，只取决于手机能接收的长度。
2009/5/19
解决timeout问题。
2009/4/22
加入获得飞信用户手机号码的功能。
