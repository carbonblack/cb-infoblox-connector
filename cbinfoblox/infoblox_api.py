import requests
import time
#t1=`date +%s`;t0=`expr $t1 - 86400`;curl -k -H "Authorization: Token PASSWORD" "https://www-test.csp.infoblox.com/api/threats/v1/dns_event?t0=$t0&t1=$t1"

def dns_event_request(route,auth_token,t0,t1):
    headers = {"Authorization": "Token " + auth_token}
    return requests.get(route,params=(("t0",t0),("t1",t1)),headers=headers).json()

def parse_infoblox_dns_event(dns_event):
    if (dns_event):
        if dns_event.get('status_code','0') == '200':
            return dns_event.get('result',[])
        else:
            return None
    else:
        return None