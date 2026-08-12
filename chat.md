```cpp
/send_captcha 邮箱地址(@163.com);//发送验证码,在登录，注册，忘记密码前发送

/reg name password email code(验证码);//注册

/login name password email code;//登录

/foegetpassword  name password email code;//忘记密码

/add name;//添加好友

/list_request;//列出好友列表

/accpet name;//同意好友申请

/reject name;//拒绝好友申请

/list;//列出好友

/msg name msg;//私聊

/block name;//屏蔽好友

/unblock name;//解除屏蔽

/joingroup groupname;//申请加入群聊;

/leavegroup groupname;//推出群聊;

/groupchat groupname msg;//群聊；

/creategroup groupname;//建群;

/groupmembers groupname;//查看群聊成员;

/mygroups;//查看自己的群聊;

/list_group groupname;//查看群聊申请（群主和管理员）

/approve groupname name;//同意加群申请（群主和管理员）

/rejectgroup groupname name;//拒绝加群申请（群主和管理员）

/del_groupmember groupname name;//删除群成员（群主和管理员）

/setadmin groupname name;//设置管理员（群主）

/deladmin groupname name;//删除管理员（群主）

/dismissgroup groupname;//解散群聊（群主）

/sendfile name filepath(绝对路径);//发送文件（可同时实现私聊和群发）

/download file_id filesavepath(绝对路径);//下载文件

/history name;//查看历史记录
```
