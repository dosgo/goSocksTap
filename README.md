# goSocksTap
This is a simple implementation of sockstap, developed with golang, supports windows, linux, currently only supports tcp, linux has not been tested. .




##Notice
If your socks service also uses dns resolution (port 53), then it must be added to the excludeDomain list, otherwise it will loop