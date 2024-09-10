'''
A10 to F5 Config Converter
'''
import datetime
import jinja2
import json
import os
import sys
import pathlib
import requests
from dotenv import load_dotenv
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
spacer_w_hash = "##############################################################################################"
spacer_w_dash = "----------------------------------------------------------------------------------------------"

smop_dir = 'smops'
pathlib.Path(f"./{smop_dir}").mkdir(parents=True, exist_ok=True)

f = open(f"./{smop_dir}/LB_SMOP_{date_stamp}.txt", "a")
app_description = (
    "ITRC Appname:"
    + " " + ";" + " " + ";"
    + f"{date_stamp}" + ";"
    + "A10-to-F5 Migration"
)

def create_a10_session(device):
    url = f"https://{device}/axapi/v3/auth"
    headers = {"content-type": "application/json"}
    auth_payload = { "credentials": {"username": f"{A10USER}", "password": f"{A10PASS}"} }
    s = requests.Session()
    response = s.post(
        url,
        data=json.dumps(auth_payload),
        headers=headers,
        verify=False,
        timeout=10,
    )
    if response.status_code == 200:
        json_resp = json.loads(response.text)
        auth = json_resp["authresponse"]["signature"]
        return auth, s
    else:
        print(f"[%] Unable to establish session. HTTP status code: {response.status_code}")
        sys.exit()

#Start config generation logic
def print_begin_spacers(device):
    print(f"[%] {datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')} : Start Config Generation for {device}")
    f.write(f"[%] {datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')} : Start Config Generation for {device}\n")
    print(spacer_w_hash)
    f.write(spacer_w_hash)
    f.write('\n')

def build_clientssl_profile(device, auth, s, clientssl_template_name, vs_handle):
    url = f"https://{device}/axapi/v3/slb/template/client-ssl/{clientssl_template_name}"
    s.headers.update(
            {
            "content-type": "application/json",
            "Authorization": f"A10 {auth}",
            "Cache-Control": "no-cache"
            })
        
    clientssl_template_response = s.get(url)
    json_resp = json.loads(clientssl_template_response.text)
    # print(json_resp)
    clientssl_profile_name='clientssl_' + vs_handle
    clientssl_output = template_clientssl.render (
        clientssl_profile_name=clientssl_profile_name, #replace profile name
        cert_name = f"{json_resp['client-ssl']['certificate-list'][0]['cert']}.crt",
        key_name =  f"{json_resp['client-ssl']['certificate-list'][0]['key']}.key",
        description = app_description
    )
    f.write(clientssl_output)
    print(clientssl_output)
    f.write('\n')
    return clientssl_profile_name

def build_serverssl_profile(device, auth, s, serverssl_template_name, vs_handle):
    url = f"https://{device}/axapi/v3/slb/template/server-ssl/{serverssl_template_name}"
    s.headers.update(
            {
            "content-type": "application/json",
            "Authorization": f"A10 {auth}",
            "Cache-Control": "no-cache"
            })
    serverssl_template_response = s.get(url)
    json_resp = json.loads(serverssl_template_response.text)
    serverssl_profile_name='serverssl_' + vs_handle
    serverssl_output = template_serverssl.render(
        serverssl_profile_name=serverssl_profile_name, #replace profile name
        description = app_description
    )
    f.write(serverssl_output)
    print(serverssl_output)
    f.write('\n')
    return serverssl_profile_name

def build_persistence_configs(device, auth, s, persistence_template_name):
    url = f"https://{device}/axapi/v3/slb/template/persist/source-ip/{persistence_template_name}"
    s.headers.update(
            {
            "content-type": "application/json",
            "Authorization": f"A10 {auth}",
            "Cache-Control": "no-cache"
            })
    response = s.get(url)
    json_resp = json.loads(response.text)

    if json_resp['source-ip']['timeout'] >= 1 and json_resp['source-ip']['timeout'] <= 5:
        return "source_address_300s"
    elif json_resp['source-ip']['timeout'] >= 6 and json_resp['source-ip']['timeout'] <= 30:
        return "source_address_1800s"
    else:
        return "source_address_3600s"

def build_healthmonitor(device, auth, s, healthmonitor_name, vs_handle, vs_port):
    healthcheck_url = f"https://{device}/axapi/v3/health/monitor/{healthmonitor_name}"
    s.headers.update(
            {
            "content-type": "application/json",
            "Authorization": f"A10 {auth}",
            "Cache-Control": "no-cache"
            })
    healthcheck_response = s.get(healthcheck_url)
    healthcheck_json_resp = json.loads(healthcheck_response.text)

    healthcheck_port = "*"
    print(healthmonitor_name)
    #Handle all healthcheck use-cases
    known_healthcheck_flag = 0 #flag to catch known http, https, tcp monitors
    if "http" in healthcheck_json_resp['monitor']['method']:
        healthcheck_type = "http"
        healthcheck_port = healthcheck_json_resp['monitor']['method']['http']['http-port']
        if "url-type" in healthcheck_json_resp['monitor']['method']['http']:
            http_method = healthcheck_json_resp['monitor']['method']['http']['url-type']
        else:
            http_method = "GET"
        if healthcheck_json_resp['monitor']['method']['http']['http-url'] == 0:
            http_uri = "/"
        else:
            http_uri = healthcheck_json_resp['monitor']['method']['http']['url-path']
        if "http-host" in healthcheck_json_resp['monitor']['method']['http']:
            http_host = healthcheck_json_resp['monitor']['method']['http']['http-host']
        else: 
            http_host = "NA"
        if "http-text" in healthcheck_json_resp['monitor']['method']['http']:
            http_response = healthcheck_json_resp['monitor']['method']['http']['http-text']
        else:
            http_response = "200"
        
        healthcheck_data = f"defaults-from m_placeholder_http recv \"{http_response}\" send \"{http_method} {http_uri} HTTP/1.1\\r\\nHost: {http_host}\\r\\nUser-Agent: slb-healthcheck\\r\\nConnection: Close\\r\\n\\r\\n\" destination *:{healthcheck_port}"
        known_healthcheck_flag = 1
        healthcheck_name="m_" + vs_handle + "_" + vs_port + "_" + healthcheck_type
    
    elif "https" in healthcheck_json_resp['monitor']['method']:
        healthcheck_type = "https"
        healthcheck_port = healthcheck_json_resp['monitor']['method']['https']['web-port']
        if "url-type" in healthcheck_json_resp['monitor']['method']['https']:
            http_method = healthcheck_json_resp['monitor']['method']['https']['url-type']
        else:
            http_method = "GET"
        if healthcheck_json_resp['monitor']['method']['https']['https-url'] == 0:
            http_uri = "/"
        else:
            http_uri = healthcheck_json_resp['monitor']['method']['https']['url-path']
        if "http-host" in healthcheck_json_resp['monitor']['method']['https']:
            http_host = healthcheck_json_resp['monitor']['method']['https']['https-host']
        else: 
            http_host = "NA"
        if "http-text" in healthcheck_json_resp['monitor']['method']['https']:
            http_response = healthcheck_json_resp['monitor']['method']['https']['https-text']
        else:
            http_response = "200"

        healthcheck_data = f"defaults-from m_placeholder_https recv \"{http_response}\" send \"{http_method} {http_uri} HTTP/1.1\\r\\nHost: {http_host}\\r\\nUser-Agent: slb-healthcheck\\r\\nConnection: Close\\r\\n\\r\\n\" destination *:{healthcheck_port}"
        known_healthcheck_flag = 1
        healthcheck_name="m_" + vs_handle + "_" + vs_port + "_" + healthcheck_type
    
    elif "tcp" in healthcheck_json_resp['monitor']['method']:
        healthcheck_type = "tcp"
        healthcheck_port = healthcheck_json_resp['monitor']['method']['tcp']['tcp-port']
        healthcheck_data = f"defaults-from m_placeholder_tcp destination *:{healthcheck_port}"
        known_healthcheck_flag = 1
        healthcheck_name="m_" + vs_handle + "_" + vs_port + "_" + healthcheck_type
    
    else: 
        healthcheck_flag = 1
        healthcheck_type = "NA"
        http_method = "NA"
        http_uri = "NA"
        http_host = ""
        http_response = "NA"
        healthcheck_data = "NA"
    
    #Build and Write monitor commands only if they are http or https based.
    if known_healthcheck_flag == 1:
        healthcheck_output = template_healthcheck.render(
            healthcheck_type = healthcheck_type,
            healthcheck_name = healthcheck_name,
            healthcheck_data = healthcheck_data,
            description = app_description
        ) 
        f.write(healthcheck_output)
        print(healthcheck_output)
        f.write('\n')
        return healthcheck_name


def build_pool(device, auth, s, a10_pool_name, vs_handle, vs_address_type, vs_port):
    url = f"https://{device}/axapi/v3/slb/service-group/{a10_pool_name}"
    s.headers.update(
            {
            "content-type": "application/json",
            "Authorization": f"A10 {auth}",
            "Cache-Control": "no-cache"
            })
    pool_response = s.get(url)
    pool_json_resp = json.loads(pool_response.text)

    member_list = []
    #Build pool member list
    for member_item in pool_json_resp['service-group']['member-list']:
        pool_member_url = f"https://{device}/axapi/v3/slb/server/{member_item['name']}"
        pool_member_response = s.get(pool_member_url)
        #print(pool_member_response.text)
        pool_member_json_resp = json.loads(pool_member_response.text)
        if 'host' in pool_member_json_resp['server']:
            pool_member = pool_member_json_resp['server']['host'] + ":" +str(member_item['port'])
        elif 'server-ipv6-addr' in pool_member_json_resp['server']:
            pool_member = pool_member_json_resp['server']['server-ipv6-addr'] + "." +str(member_item['port'])
        member_list.append(pool_member)

    #LB Method Logic
    if 'lc-method' not in pool_json_resp['service-group']:
        lb_method = "round-robin"
    elif pool_json_resp['service-group']['lc-method'] == "least-connection":
        lb_method = "least-connections-member"

    # HEALTH MONITOR Logic
    if 'health-check' not in pool_json_resp['service-group']:
        pool_json_resp['service-group']['health-check'] = "NA"
        healthcheck_name = "NA"
    #Proceed further to get healthcheck config only if the pool has healthcheck applied
    else:
        healthcheck_name = build_healthmonitor(device, auth, s, pool_json_resp['service-group']['health-check'], vs_handle, vs_port)

    if vs_address_type == "v6":
        pool_name = f"p_{vs_handle}_{vs_port}_v6"
    elif vs_address_type == "v4":
        pool_name = f"p_{vs_handle}_{vs_port}" 

    #Render the template
    pool_output = template_pool.render(
        pool_name = pool_name,
        pool_lb_method = lb_method,
        pool_healthcheck = healthcheck_name,
        pool_members = member_list,
        description = app_description
        )
    
    f.write(pool_output)
    print(pool_output)
    f.write('\n')
    return pool_name

def build_config(device, auth, s):
    #Start with getting virtual-servers list
    #try:
    url = f"https://{device}/axapi/v3/slb/virtual-server"
    s.headers.update(
        {
        "content-type": "application/json",
        "Authorization": f"A10 {auth}",
        "Cache-Control": "no-cache"
        })
    response = s.get(url)
    response_code = response.status_code

    if response_code == 204:
        print(device, response_code)
    else:
        json_resp = json.loads(response.text)

    count = 1 #Variable to count virtual-server iterations
    
    for virtual in json_resp["virtual-server-list"]:
        ip_protocol = '' #Initialize
        vs_profiles = ''
        vs_handle = virtual['name'].partition("_")[2]
        
        if 'port-list' in virtual:
            for port in virtual["port-list"]:
                f.write(f"\n{str(count)}{spacer_w_dash}\n")
                print(f"\n{str(count)}{spacer_w_dash}\n")

                if 'name' not in port: #check for vs name
                    port['name'] = virtual['name']
                if 'service-group' not in port: #check for pool
                    port['service-group'] = "NA"
                if 'pool' in port: #check for SNAT pool 
                    snat_info = f"source-address-translation {{ type snat pool {port['pool']}  }}"
                else:
                    snat_info = ''
                
                #Handle virtual-server type configs
                if port['protocol'] == 'tcp':
                    ip_protocol = 'tcp'
                    vs_profiles = 'fastL4'
                elif port['protocol'] == 'udp':
                    ip_protocol = 'udp'
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

                
                #SSL Profile Logic
                if 'template-client-ssl' in port:
                    clientssl_profile_name = build_clientssl_profile(device, auth, s, port['template-client-ssl'], vs_handle)
                    vs_profiles =  clientssl_profile_name + " {context clientside} " + " " + vs_profiles

                if 'template-server-ssl' in port:
                    serverssl_profile_name = build_serverssl_profile(device, auth, s, port['template-server-ssl'], vs_handle)
                    vs_profiles = serverssl_profile_name + " {context serverside} "  + " " + vs_profiles
                
                #HTTP template
                if 'template-http' in port and 'x-forwarded' in port['template-http'].lower():
                    vs_profiles = vs_profiles + " http_x-forwarded-for"
                
                #Persistence Profile Logic
                if 'template-persist-source-ip' in port:
                    persist_profile_name = build_persistence_configs(device, auth, s, port['template-persist-source-ip'])
                    persist_profile_data = "replace-all-with { " + persist_profile_name + " }"
                else:
                    persist_profile_data = "none"

                #handle cases to identify ipv4 vs ipv6 virtuals
                if 'ipv6-address' in virtual:
                    vs_address=virtual['ipv6-address'] + "."
                    vs_name= f"vs_{vs_handle}_{str(port['port-number'])}_v6"
                    vs_address_type = "v6"
                elif 'ip-address' in virtual:
                    vs_address=virtual['ip-address'] + ":"
                    vs_name= f"vs_{vs_handle}_{str(port['port-number'])}"
                    vs_address_type = "v4"

                #Call function to build pool config
                if port['service-group'] != 'NA':
                    pool_name = build_pool(device, auth, s, port['service-group'], vs_handle, vs_address_type, str(port['port-number']))            

                #Build and Write virtual server config
                vs_output = template_vs.render(
                    vs_name= vs_name,
                    vs_address = vs_address,
                    vs_port=str(port['port-number']),
                    vs_protocol = ip_protocol,
                    vs_profiles = vs_profiles,
                    persist_profile = persist_profile_data,
                    pool_name = pool_name,  
                    snat_pool = snat_info,
                    description = app_description
                )

                f.write(vs_output)
                print(vs_output)
                f.write('\n')
                count = count + 1 #Increment virtual-server iterations variable
        else:
            print('no port')
            count = count + 1 #Increment virtual-server iterations variable
                
    f.write('\n' + spacer_w_hash)
    f.write('\n')

def main(): 
    
    lb = "ssl08-d.hillsboro.or.ndchlsbr.placeholder.net"

    auth, s = create_a10_session(lb)
    print_begin_spacers(lb)

    build_config(lb, auth, s)


if __name__ == "__main__":
    main()

