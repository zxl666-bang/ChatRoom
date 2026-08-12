#include "send_email.h"
#include<string.h>
#include<string>
#include <iostream>
#include<curl/curl.h>
using namespace std;
struct emaildata
{
    string data;
    size_t pos;
};
static size_t recall(char*buffer,size_t item,size_t maxitem,void*usedata)
{
     emaildata*email=(emaildata*)usedata;
     if(email->data.size()<=email->pos)
     {
        return 0;
     }
    size_t m=item*maxitem;
    size_t remain=email->data.size()-email->pos;
    size_t len=m>remain?remain:m;
    memcpy(buffer,email->data.data()+email->pos,len);
    email->pos+=len;
    return len;
}
bool send_email(const string& to//收件人邮箱地址
    , const string& subject, const string& body)
{
      CURL*curl=curl_easy_init();
      static const string SMTP_URL="smtps://smtp.163.com:465";
      static const string password="UGf6D3BqAEvjLAYi";
      const char*send_from="19859355259@163.com";
      string content;
      content+="From: "+string(send_from)+"\r\n";
      content+="To: "+to+"\r\n";
      content+="Subject:"+subject+"\r\n";
      content+="\r\n";
      content+=body+"\r\n";
      emaildata email;
      email.data=content;
      email.pos=0;
      curl_easy_setopt(curl,CURLOPT_MAIL_FROM,send_from);
      curl_easy_setopt(curl,CURLOPT_URL,SMTP_URL.c_str());
      curl_easy_setopt(curl,CURLOPT_USERNAME,send_from);
      curl_easy_setopt(curl,CURLOPT_PASSWORD,password.c_str());
      curl_slist*receiver=nullptr;
      receiver=curl_slist_append(receiver,to.c_str());
      curl_easy_setopt(curl,CURLOPT_MAIL_RCPT,receiver);
      curl_easy_setopt(curl,CURLOPT_SSL_VERIFYHOST,0);
      curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,0);
      curl_easy_setopt(curl,CURLOPT_USE_SSL,CURLUSESSL_ALL);
      curl_easy_setopt(curl,CURLOPT_READFUNCTION,recall);
       curl_easy_setopt(curl,CURLOPT_READDATA,&email);
      curl_easy_setopt(curl,CURLOPT_UPLOAD,1);
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
      CURLcode res=curl_easy_perform(curl);
      if(res==CURLE_OK)
      {
        curl_slist_free_all(receiver);
        curl_easy_cleanup(curl);
        return true;
      }
      else
      {

        cerr<<"邮件发送失败"<<curl_easy_strerror(res)<<endl;
        curl_slist_free_all(receiver);
        curl_easy_cleanup(curl);
        return false;
      }
}
