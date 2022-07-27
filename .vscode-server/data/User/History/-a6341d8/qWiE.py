from functools import wraps
from flask import request,make_response,abort
from ..utils import log
from ..db import query
import requests
from flask import jsonify
import json
import jwt
import time

#Verify if token exists for CRM user
def getAdminId(api_key):
    result=query("SELECT","SELECT `user_id` FROM `api_auth` WHERE `token`=%s",[str(api_key)])
    if(result['status']==1):
        rows=result['result']
        if(len(rows)>0):
            row=rows[0]
            return row['user_id']
        else:
            return 0
    else:
        return 0

#Verify if token exists for the mobile user
def getCustomerId(api_key):
    result=query("SELECT","SELECT `user_id` FROM `cust_api` WHERE `token`=%s",[str(api_key)])
    if(result['status']==1):
        rows=result['result']
        if(len(rows)>0):
            row=rows[0]
            return row['user_id']
        else:
            return 0
    else:
        return 0

#The function is invoked by end points if authentication is not required
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        # api=request.headers.get("Auth")
        # id=getCustomerId(api)
        # if(id>0):
            return f(*args, **kwargs)   
        # else:
            # abort(401)
    return wrap

#Validate the JWT token sent by Cognito Authenticated User
def admin_login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        api=request.headers.get("Auth")
        try:
            data=jwt.decode(api, verify=False)
            epoch_time = int(time.time())
            if(data['exp'] >= epoch_time):
                return f(*args, **kwargs)
            else:
                log.info('Token Expired')
                abort(401)
        except Exception as e:
            log.info('Invalid Token. Not able to decode.')
            abort(401)
    return wrap
	
#Validate token for Mobile App User
def cust_login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
         api=request.headers.get("Auth")
         id=getCustomerId(api)
         if(id==237):
            log.info('browser_login')
            log.info(id)
            log.info('api '+api)
         if(id>0):
            result=query("UPDATE","UPDATE customers set updated_on=NOW() WHERE id=%s",[str(id)])
            return f(*args, **kwargs)
         else:
             abort(401)
             log.info('Something wrong with api token')
             log.info('api '+api)
             log.info('id '+id)
    return wrap
