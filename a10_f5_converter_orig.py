from dotenv import load_dotenv
import requests
import json
import os
import jinja2
import sys
import datetime
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#Read and load the .env file. The .env file should be in the same directory
#as the a10_f5_converter.py script
load_dotenv()
A10USER = os.getenv("A10USER")
A10PASS = os.getenv("A10PASS")

#Jinja templates
loader = jinja2.FileSystemLoader(os.getcwd())
jenv = jinja2.Environment(loader=loader, trim_blocks=True, lstrip_blocks=True)
template_clientssl = jenv.get_template("template_clientssl.txt")
template_serverssl = jenv.get_template("template_serverssl.txt")
template_healthcheck = jenv.get_template("template_monitor.txt")
template_pool = jenv.get_template("template_pool.txt")
template_vs = jenv.get_template("template_vs.txt")


date_stamp = datetime.date.today()
spacer_w_hash = "\n##############################################################################################\n"
spacer_w_dash = "----------------------------------------------------------------------------------------------"
f = open(f"SMOP_{date_stamp}.txt", "a")

#Auth Token Generation
def a10_key(fqdn):
    username = A10USER
    password = A10PASS
    try:
        url = f"https://{fqdn}/axapi/v3/auth"
        auth_headers = {"content-type": "application/json"}
        auth_payload = {
            "credentials": {"username": f"{username}", "password": f"{password}"}
        }
        response = requests.post(
            url,
            data=json.dumps(auth_payload),
            headers=auth_headers,
            verify=False,
            timeout=10,
        )
        json_resp = json.loads(response.text)
        auth = json_resp["authresponse"]["signature"]
        #print(fqdn, auth)
    except requests.exceptions.RequestException as e:
        print("exception caught", e)
        auth = "noconnection"
    return auth

#Start config generation logic
def build_f5_config(lb):

    print(datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S") + ": Start config Generation")
    f.write(datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S") + ": Start config Generation")
    print(spacer_w_hash)
    f.write(spacer_w_hash)
    f.write('\n')

    auth = a10_key(lb)

    app_description = (
        "ITRC Appname:"
        + " " + ";" + " " + ";"
        + f"{date_stamp}" + ";"
        + "A10-to-F5 Migration"
    )

    #Start with getting virtual-servers list
    try:
        url = f"https://{lb}/axapi/v3/slb/virtual-server"
        headers = {
            "content-type": "application/json",
            "Authorization": f"A10 {auth}",
            "Cache-Control": "no-cache",
        }
        s = requests.Session()
        s.headers.update({"content-type": "application/json","Authorization": f"A10 {auth}","Cache-Control": "no-cache"})
        response = s.get(url,verify=False)
        response_code = response.status_code
        if response_code == 204:
            print(lb, response_code)
        else:
            json_resp = json.loads(response.text)

        count =1 #Variable to count virtual-server iterations
        
        for virtual in json_resp["virtual-server-list"]:
            vs_handle = virtual['name'].partition("_")[2]
            for port in virtual["port-list"]:
                f.write("\n"+str(count)+spacer_w_dash+"\n")
                print("\n"+str(count)+spacer_w_dash+"\n")

                if 'name' not in port: #check for vs name
                    port['name'] = virtual['name']
                if 'service-group' not in port: #check for pool
                    port['service-group'] = "NA"
                if 'pool' not in port: #check for SNAT pool
                    port['pool'] = "NA"
                
                #Handle virtual-server type configs
                if port['protocol'] == 'tcp':
                    ip_protocol = 'tcp'
                    vs_profiles = 'fastL4'
                elif port['protocol'] == 'http' or port['protocol'] == 'https':
                    if 'template-tcp-proxy' in port:
                        ip_protocol = 'tcp'
                        vs_profiles = 'tcp_dscp-af22'
                    else:
                        ip_protocol = 'tcp'
                        vs_profiles = 'tcp' 
                elif port['protocol'] == 'sip':
                        ip_protocol = 'udp'
                        vs_profiles = 'fastL4'

                #Client-SSL template section
                if 'template-client-ssl' in port:
                    url = (
                        f"https://{lb}/axapi/v3/slb/template/client-ssl/{port['template-client-ssl']}"
                    )
                    clientssl_template_response = s.get(url,verify=False)
                    json_resp = json.loads(clientssl_template_response.text)
                    clientssl_output = template_clientssl.render (
                        clientssl_profile_name='clientssl_' + vs_handle, #replace profile name
                        cert_name = json_resp['client-ssl']['cert'],
                        key_name =  json_resp['client-ssl']['key'],
                        description = app_description
                    )
                    f.write(clientssl_output)
                    print(clientssl_output)
                    f.write('\n')
                    vs_profiles = vs_profiles + " " + port['template-client-ssl'] + " {context clientside} "

                #Server-SSL template section
                if 'template-server-ssl' in port:
                    url = (
                        f"https://{lb}/axapi/v3/slb/template/server-ssl/{port['template-client-ssl']}"
                    )
                    serverssl_template_response = s.get(url,verify=False)
                    json_resp = json.loads(serverssl_template_response.text)
                    serverssl_output = template_serverssl.render(
                        serverssl_profile_name='serverssl_' + vs_handle, #replace profile name
                        description = app_description
                    )
                    f.write(serverssl_output)
                    print(serverssl_output)
                    f.write('\n')
                    vs_profiles = vs_profiles + " " + port['template-server-ssl'] + " {context serverside} "

                #HTTP template
                if 'template-http' in port and 'x-forwarded' in port['template-http'].lower():
                    vs_profiles = vs_profiles + " http_x-forwarded-for"

                #handle cases to identify ipv4 vs ipv6 virtuals
                if 'ipv6-address' in virtual:
                    vs_address=virtual['ipv6-address'] + "."
                elif 'ip-address' in virtual:
                    vs_address=virtual['ip-address'] + ":"

                #POOL LOGIC
                #Proceed further to get pool config only if the virtual server has a service group
                if port['service-group'] != 'NA':
                    url = (
                        f"https://{lb}/axapi/v3/slb/service-group/{port['service-group']}"
                    )
                    pool_response = s.get(url,verify=False)
                    pool_json_resp = json.loads(pool_response.text)

                    member_list = []
                    #Build pool member list
                    for member_item in pool_json_resp['service-group']['member-list']:
                        pool_member_url = (
                            f"https://{lb}/axapi/v3/slb/server/{member_item['name']}"
                        )
                        pool_member_response = s.get(pool_member_url,verify=False)
                        pool_member_json_resp = json.loads(pool_member_response.text)
                        pool_member = pool_member_json_resp['server']['host'] + ":" +str(member_item['port'])
                        member_list.append(pool_member)

                    #LB Method Logic
                    if 'lc-method' not in pool_json_resp['service-group']:
                        pool_json_resp['service-group']['lc-method'] = "round-robin"
                    
                    # HEALTH MONITOR Logic
                    if 'health-check' not in pool_json_resp['service-group']:
                        pool_json_resp['service-group']['health-check'] = "NA"
                    #Proceed further to get healthcheck config only if the pool has healthcheck applied
                    else:
                        healthcheck_url = (
                        f"https://{lb}/axapi/v3/health/monitor/{pool_json_resp['service-group']['health-check']}"
                        )
                        healthcheck_response = s.get(healthcheck_url,verify=False)
                        healthcheck_json_resp = json.loads(healthcheck_response.text)

                        #Handle all healthcheck use-cases
                        http_based_healthcheck_flag = 0 #flag to catch http and https monitors
                        if "http" in healthcheck_json_resp['monitor']['method']:
                            if healthcheck_json_resp['monitor']['method']['http']['http-url'] == 0:
                                healthcheck_type = "http"
                                http_method = "GET"
                                http_uri = "/"
                                http_host = ""
                                http_response = "200"
                            elif healthcheck_json_resp['monitor']['method']['http']['http-url'] == 1:
                                healthcheck_type = "http"
                                http_method = healthcheck_json_resp['monitor']['method']['http']['url-type']
                                http_uri = healthcheck_json_resp['monitor']['method']['http']['url-path']
                                if "http-host" in healthcheck_json_resp['monitor']['method']['http']:
                                    http_host = healthcheck_json_resp['monitor']['method']['http']['http-host']
                                else: 
                                    http_host = "NA"
                            healthcheck_data = "defaults-from m_placeholder_http " + "send \"" + http_method + " "+  http_uri + " HTTP/1.1\\r\\nHost: " + http_host + "\\r\\nUser-Agent: slb-healthcheck\\r\\nConnection: Close\\r\\n\\r\\n" + "\""  
                            http_based_healthcheck_flag = 1
                            healthcheck_name="m_" + vs_handle + "_" + str(port['port-number']) + "_" + healthcheck_type
                        
                        elif "https" in healthcheck_json_resp['monitor']['method']:
                            if healthcheck_json_resp['monitor']['method']['https']['https-url'] == 0:
                                healthcheck_type = "https"
                                http_method = "GET"
                                http_uri = "/"
                                http_host = ""
                                http_response = "200"
                            elif healthcheck_json_resp['monitor']['method']['https']['https-url'] == 1:
                                healthcheck_type = "https"
                                http_method = healthcheck_json_resp['monitor']['method']['https']['url-type']
                                http_uri = healthcheck_json_resp['monitor']['method']['https']['url-path']
                                if "https-host" in healthcheck_json_resp['monitor']['method']['https']:
                                    http_host = healthcheck_json_resp['monitor']['method']['https']['https-host']
                                else: 
                                    http_host = "NA"
                            healthcheck_data = "defaults-from m_placeholder_https " + "send \"" + http_method + " "+  http_uri + " HTTP/1.1\\r\\nHost: " + http_host + "\\r\\nUser-Agent: slb-healthcheck\\r\\nConnection: Close\\r\\n\\r\\n" + "\"" 
                            http_based_healthcheck_flag = 1
                            healthcheck_name="m_" + vs_handle + "_" + str(port['port-number']) + "_" + healthcheck_type
                        
                        elif "tcp" in healthcheck_json_resp['monitor']['method']:
                            healthcheck_type = "tcp"
                            healthcheck_data = ""
                            healthcheck_name="m_placeholder_tcp"
                        
                        else: 
                            healthcheck_flag = 1
                            healthcheck_type = "NA"
                            http_method = "NA"
                            http_uri = "NA"
                            http_host = ""
                            http_response = "NA"
                            healthcheck_data = "NA"
                        
                        #Build and Write monitor commands only if they are http or https based.
                        if http_based_healthcheck_flag == 1:
                            healthcheck_output = template_healthcheck.render(
                                healthcheck_type = healthcheck_type,
                                healthcheck_name = healthcheck_name,
                                healthcheck_data = healthcheck_data
                                description = app_description
                            ) 
                            f.write(healthcheck_output)
                            print(healthcheck_output)
                            f.write('\n')

                    #Build and Write pool config
                    pool_output = template_pool.render(
                        pool_name="p_" + vs_handle + "_" + str(port['port-number']),
                        pool_lb_method = pool_json_resp['service-group']['lc-method'],
                        pool_healthcheck = healthcheck_name,
                        pool_members = member_list,
                        description = app_description
                    )
                    
                    f.write(pool_output)
                    print(pool_output)
                    f.write('\n')

                #Build and Write virtual server config
                vs_output = template_vs.render(
                    vs_name= "vs_" + vs_handle + "_" + str(port['port-number']),
                    vs_address = vs_address,
                    vs_port=str(port['port-number']),
                    vs_protocol = ip_protocol,
                    vs_profiles = vs_profiles,
                    pool_name=port['service-group'],  
                    snat_pool=port['pool'],
                    description = app_description
                )

                f.write(vs_output)
                print(vs_output)
                f.write('\n')
                    
                count = count + 1 #Increment virtual-server iterations variable
                
    except Exception as e:
        print("Error:", lb, e)

    f.write('\n' + spacer_w_hash)
    f.write('\n')

def main(): 
    lb = "ssl02-d.hillsboro.or.ndchlsbr.placeholder.net"
    build_f5_config(lb)


if __name__ == "__main__":
    main()

