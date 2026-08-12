#ifndef SEND_EMAIL_H
#define SEND_EMAIL_H

#include <string>

bool send_email(const std::string& to, const std::string& subject, const std::string& body);

#endif