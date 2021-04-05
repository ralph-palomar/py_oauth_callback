#!/bin/bash
source venv/bin/activate
pip3 install -r requirements.txt
export ALLOWED_ORIGIN=*
export ALLOWED_HEADERS=Authorization,JWT,Overwrite,Destination,Content-Type,Depth,User-Agent,Translate,Range,Content-Range,Timeout,X-File-Size,X-Requested-With,If-Modified-Since,X-File-Name,Cache-Control,Location,Lock-Token,If
export ALLOWED_METHODS=OPTIONS,GET,POST,PUT,PATCH,DELETE
waitress-serve --port=8080 main:api
