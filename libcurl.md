模块定位：这个文件的作用是什么？它对外提供什么接口？
作用:发送验证码，提供发送邮件的接口

核心流程：发送一封邮件需要哪些步骤？
1.设置邮件内容；
2.设置句柄：curl_easy_creat(curl)
3.设置发送者邮箱    curl_easy_setopt(curl,CURLOPT_MAIL_FROM,send_from);
4.设置邮箱SMTP     curl_easy_setopt(curl,CURLOPT_URL,SMTP_URL.c_str());
5.设置使用者      curl_easy_setopt(curl,CURLOPT_USERNAME,send_from);
6.设置授权码      curl_easy_setopt(curl,CURLOPT_PASSWORD,password.c_str());
7.创建指针链表用于存储收件人邮箱      curl_slist*receiver=nullptr;
8.将收件人邮箱存入链表      receiver=curl_slist_append(receiver,to.c_str());
9.设置收件人邮箱      curl_easy_setopt(curl,CURLOPT_MAIL_RCPT,receiver);
10.不考虑证书      curl_easy_setopt(curl,CURLOPT_SSL_VERIFYHOST,0);
      curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,0);
11.连接时强制使用SSL/TSL加密      curl_easy_setopt(curl,CURLOPT_USE_SSL,CURLUSESSL_ALL);
12.调用回调函数      curl_easy_setopt(curl,CURLOPT_READFUNCTION,recall);
13.传递给回调函数用户数据指针 curl_easy_setopt(curl,CURLOPT_READDATA,&email);
14.说明是上传      curl_easy_setopt(curl,CURLOPT_UPLOAD,1);
15 用于测试      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
8.运行:curl_perform(curl);
9.初始化：curl_slist_free_all(链表);curl_cleanup(curl);
10.检查验证码是否发送成功,发送失败通过curl_stderr(res)打印错误信息

数据结构：你用到了哪些结构体？它们的作用是什么？

emaildata结构体，用于存储完整邮件内容和recall函数里读到的位置
curl_slist链表，用于存储收件人邮箱地址

回调函数：recall 函数的作用和实现逻辑。

读取完整邮件内容
用buffer存储email->data并用pos记录当前当前位置，len=元素大小*最大元素数<data.size()-pos?前者：后者
memcpy(buffer,email->data.c_str()+pos,len);
