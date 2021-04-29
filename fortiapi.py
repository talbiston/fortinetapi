from typing import List
from FortiJson.rpcrequest import JsonRpc, HTTPclient
import requests
import json
from time import sleep
from datetime import datetime, timedelta
from getpass import getpass

API_USER = 'CloudSmartz-RW'
API_FMG_IP = '10.215.17.123'
API_FAZ_IP = '10.215.17.124'

def time_frame(days):
    
    dtnow = datetime.now()
    dtstart = dtnow - timedelta(days=days)

    strdtnow = dtnow.strftime("%Y-%m-%d %H:%M:%S")
    strstart = dtstart.strftime("%Y-%m-%d %H:%M:%S")
    
    return {'starttime': strstart, 'endtime': strdtnow}

# First need to get session and have it persist
class FmgApi:
    def __init__(self, fmg, **kwargs):

        #self.json_data = self._load_json()
        #self.fmg_values = self.json_data[fmg]

        managers = {"lab-fmg": API_FMG_IP}
        logins = {"lab-fmg": (API_USER, getpass())}
        base_url = f'https://{managers[fmg]}/jsonrpc'
        self.client = HTTPclient(base_url)
        self.user = logins[fmg][0]
        self.password = logins[fmg][1]
        self.session = self.get_session()


        def _replace_iter(self, _dict, string):

            for key, value in _dict.items():
                print(f"KEY {key} VAL {value}")
                string = string.replace(key, value)

            return string

    def console_log(self, request, response):
        
        if request is None:
            print("\n", f"RESPONSE:\n{response.text}", "\n")
        else:
            print("\n", f"RPC CALL:\n{request}", "\n")
            print("\n", f"RESPONSE:\n{response.text}", "\n")
        
        
    def get_session(self):
        request = JsonRpc('exec', url='/sys/login/user', data={'user':self.user, 'passwd': self.password})
        response = self.client.send(request)
        self.console_log(None, response)
        self.session = json.loads(response.text)['session']
        return self.session


    def close_session(self):
        request = JsonRpc('exec', session=self.session, url='/sys/logout')
        response = self.client.send(request)
        self.console_log(request, response)                
        return response.text


    def get_adoms(self) -> List[str]:

        adoms = []
        request = JsonRpc('get', session=self.session, url='/dvmdb/adom', fields=["name"])
        response = self.client.send(request)
        self.console_log(request, response)
        
        response =  json.loads(response.text)
        if response['result'][0]['status']['message'] == 'OK':
            adoms_json = response['result'][0]['data']

            omit = ['FortiAnalyzer', 'FortiAuthenticator', 'FortiCache', 'FortiCarrier', 'FortiClient', 'FortiDDoS', 
            'FortiDeceptor', 'FortiFirewall', 'FortiMail', 'FortiManager', 'FortiNAC', 'FortiProxy', 'FortiSandbox', 
            'FortiWeb', 'others', 'root', 'rootp']
            for item in adoms_json:
                if item['name'] not in omit:
                    adoms.append(item['name'])
            return adoms
        else:
            return [response]



    def get_devices(self, adom):
        request = JsonRpc('get', session=self.session, url=f'/dvmdb/adom/{adom}/device')
        response = self.client.send(request)  
        self.console_log(request, response)
        response =  json.loads(response.text)
        
        if response['result'][0]['status']['message'] == 'OK':
            devices = response['result'][0]['data']
            return devices
        else:
            return response


    def get_device(self, adom, device):
        request = JsonRpc('get', session=self.session, url=f'/dvmdb/adom/{adom}/device/{device}')
        response = self.client.send(request)
        self.console_log(request, response)
        
        response =  json.loads(response.text)
        if response['result'][0]['status']['message'] == 'OK':
            devices = response['result'][0]['data']
            return devices
        else:
            return response

    def get_adom_uuid(self, adom):
        response = self.client.send(JsonRpc('get', session=self.session, url=f'/dvmdb/adom/{adom}', fields=["uuid"]))
        response = json.loads(response.text)
        if response['result'][0]['status']['message'] == 'OK':
            res = response['result'][0]['data']
            return (res['oid'], res['uuid'])
        else:
            return response

    def get_adom_obj(self, adom):
        response = self.client.send(JsonRpc('get', session=self.session, url=f'/pm/config/adom/{adom}/obj'))
        response = json.loads(response.text)
        if response['result'][0]['status']['message'] == 'OK':
            res = response['result'][0]['data']
            return res
        else:
            return response

    def get_adom_group(self, adom):
        response = self.client.send(JsonRpc('get', session=self.session, url=f'csf/adom/{adom}/group'))
        response = json.loads(response.text)
        if response['result'][0]['status']['message'] == 'OK':
            res = response['result'][0]['data']
            return res
        else:
            return response

    def get_adom_folder(self, adom):
        response = self.client.send(JsonRpc('get', session=self.session, url=f'/dvmdb/adom/{adom}/folder'))
        response = json.loads(response.text)
        if response['result'][0]['status']['message'] == 'OK':
            res = response['result'][0]['data']
            return res
        else:
            return response        

    def update_adom_folder(self, adom, dev_name, dev_oid):
        response = self.client.send(JsonRpc('add', session=self.session, url=f'/dvmdb/adom/{adom}/folder', data={"object member":{'name': f'{dev_name}', 'oid': f'{dev_oid}'}}))
        response = json.loads(response.text)
        if response['result'][0]['status']['message'] == 'OK':
            res = response
            return res
        else:
            return response       

    def update_sdwan_pdmap(self, adom, int, dev_mod, cost, weight, priority, gateway):
        data = {'dynamic_mapping': [{'_scope':[{'name':f'{dev_mod}', 'vdom': 'root'}], 'cost': cost, 'gateway': f'{gateway}', 'priority': priority, 'weight': weight}]}
        response = self.client.send(JsonRpc('update', session=self.session, url=f'/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/members/{int}', data=data))
        self.workSpaceCommit(adom)
        return response.text

    def workSpaceCommit(self, adom):
        response = self.client.send(JsonRpc('exec', session=self.session, url=f'/dvmdb/adom/{adom}/workspace/commit'))
        return response.text

    def get_system_status(self):
        request = JsonRpc('get', session=self.session, url="/sys/status")
        response = self.client.send(request)
        self.console_log(request, response)
        return response.text
        
    def get_system_perf(self):

        api_call = self._replace_iter(_dict={'$session': self.session}, string=self.json_data['get_fmg_system_perf'])
        system_perf = requests.post(self.fmg_values['url'], data=api_call, verify=False).json()['result'][0]['data']

        return system_perf	

    def update_device_meta_new(self, adom, device, meta_fields={} ):

        print(f'\n')
        print(meta_fields)
        print(f'\n')
        response = self.client.send(JsonRpc('update', session=self.session, url=f'/dvmdb/adom/{adom}/device/{device}',data={'meta fields': meta_fields}))
        response = json.loads(response.text)
        return response


    def getmeta(self, adom, device):
        values = {'$adom': adom, "$device": device, '$session': self.session}
        api_call = self._replace_iter(_dict=values, string=self.json_data['get_meta'])
        print("\n"* 5,f"{api_call}","\n"* 5)
        devices = requests.post(self.fmg_values['url'], data=api_call, verify=False).json()['result'][0]['data']
        return devices

    def getDeviceMetaList(self):
        
        request = JsonRpc('get', session=self.session, url='/dvmdb/_meta_fields/device')
        response = self.client.send(request)
        
        self.console_log(request, response)
        data = json.loads(response.text)['result'][0]['data']
        
        
        for i in data:
            print(i['name'])

    def lock(self, adom):
        request = JsonRpc('exec', session=self.session, url=f'/dvmdb/adom/{adom}/workspace/lock')
        response = self.client.send(request)
        self.console_log(request, response)
        if response:
            return response.text 
        
    def unlock(self, adom):
        request = JsonRpc('exec', session=self.session, url=f'/dvmdb/adom/{adom}/workspace/unlock')
        response = self.client.send(request)
        self.console_log(request, response)
        
        return response.text


    def regdev(self):
        values = {'$session': self.session}
        api_call = self._replace_iter(_dict=values, string=self.json_data['regdev'])
        print("\n"* 2,f"{api_call}","\n"* 2)
        res = requests.post(self.fmg_values['url'], data=api_call, verify=False)
        return res.text


    def set_hostname(self, dev_name, dev_sn):
        request = JsonRpc('set', session=self.session, url=f'pm/config/device/{dev_name}/global/system/global')
        response = self.client.send(request, data={ "hostname": f"{dev_sn}"})
        self.console_log(request, response)
        return response.text


    def add_device(self, dev_name, dev_sn, adom):
        ''' In order to get this to work and add a device into the Adom i had to add the following fields
            - branch_pt            - flags
            - build                - verrion  
            - mr                   - os_ver 
            need to work out how to populate these from other calls.'''
        request = JsonRpc(
            'exec', 
            session=self.session, 
            url="dvm/cmd/add/device",
            data={
                'adom': f'{adom}', 
                'device': {
                    "build": 0,
                    'mr': 2, 
                    "os_ver": 6, 
                    "patch": 3,
                    "flags": 67371040, 
                    'name': f'{dev_name}', 
                    'sn':f'{dev_sn}'}, 
                    'flags':[
                        "create_task",
                        "nonblocking"
                    ] 
            })
        
        response = self.client.send(request)
        self.console_log(request, response)
        
        res = json.loads(response.text)
        
        if res['result'][0]['status'] == 'OK':
            pid = res['result'][0]['data']['pid']
            taskid = res['result'][0]['data']['taskid']

            add_host_name = self.set_hostname(dev_name=dev_name, dev_sn=dev_sn)
            return (pid, taskid)
        else:
            return response


    def get_task(self, taskid):
        request = JsonRpc('get', session=self.session, url=f'task/task/{taskid}/line')
        response = self.client.send(request)
        sleep(5)
        self.console_log(request, response)
        return response.text


    def get_sysperf(self, adom, device):
        request = JsonRpc('get', session=self.session, url=f'/dvmdb/adom/{adom}/device/{device}')
        response = self.client.send(request)
        self.console_log(request, response)
        return response.text


    def _process_fmg_devices(self, data):

        dev_list = []
        for i in data:
            dev_list.append({
                'hostname': i['hostname'].upper(),
                'ip': i['ip'],
                'ips_ver': i['ips_ver'],
                'latitude': i['latitude'],
                'longitude': i['longitude'],
                'platform': i['platform_str'],
                'maxvdom' : i['maxvdom'],
                'sn': i['sn'],
                'vdom_count': len(i['vdom']) -1,
                'conn_status': i['conn_status']})

        return dev_list    

    def get_devices_fmg(self, adom):

        ''' gets all devices under a adom on the fmg and then passed to process_fmg_devices to fitler out
            just the relevent data in a list of dicts '''
        request = JsonRpc('get', session=self.session, data=[], url=f'/dvmdb/adom/{adom}/device')
        response = self.client.send(request)
        self.console_log(request, response)
        
        response =  json.loads(response.text)
        if response['result'][0]['status']['message'] == 'OK':
            devices = response['result'][0]['data']
            processed = self._process_fmg_devices(devices)
            return processed
        else:
            return response

    def getFmgPref(self):
        request = JsonRpc('get', session=self.session, url='/cli/global/system/performance')
        response = self.client.send(request)
        self.console_log(request, response)
        return response.text



    def getEventMgmtAlerts(self, adom):
        request = JsonRpc('get', session=self.session, url=f'/eventmgmt/alerts', apiver= 3, filter="severity == 3",limit= 1000)
        response = self.client.send(request)
        self.console_log(request, response)
        return response.text
    
    
    def get_adom_revisions(self, adom):
        request = JsonRpc('get', session=self.session, url=f'/dvmdb/adom/{adom}/revision')
        response = self.client.send(request)
        self.console_log(request, response)
        
        return response.text
    
    def get_policy_packages(self, adom):
        request = JsonRpc('get', session=self.session, url=f'/pm/pkg/adom/{adom}')
        response = self.client.send(request)
        self.console_log(request, response)
        
        return response.text
    
    def get_firewall_policy_package(self, adom, pkg):
        request = JsonRpc('get', session=self.session, url=f'/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy')
        response = self.client.send(request)
        self.console_log(request, response)
        
        return response.text
    
    def get_firewall_address_all(self, adom):
        request = JsonRpc('get', session=self.session, url=f'/pm/config/adom/{adom}/obj/firewall/address')
        response = self.client.send(request)
        self.console_log(request, response)
        
        return response.text
    
    def get_firewall_address(self, adom, address):
        request = JsonRpc('get', session=self.session, url=f'/pm/config/adom/{adom}/obj/firewall/address/{address}')
        response = self.client.send(request)
        self.console_log(request, response)
        
        return response.text
    
    def get_firewall_addrgrp_all(self, adom):
        request = JsonRpc('get', session=self.session, url=f'/pm/config/adom/{adom}/obj/firewall/addrgrp')
        response = self.client.send(request)
        self.console_log(request, response)
        
        return response.text
    
    
    def get_firewall_addrgrp(self, adom, addrgrp):
        request = JsonRpc('get', session=self.session, url=f'/pm/config/adom/{adom}/obj/firewall/addrgrp/{addrgrp}')
        response = self.client.send(request)
        self.console_log(request, response)
        
        return response.text
    
    
    def get_firewall_inet_service(self, adom):
        request = JsonRpc('get', session=self.session, url=f'pm/config/adom/{adom}/obj/firewall/internet-service')
        response = self.client.send(request)
        self.console_log(request, response)
        
        return response.text
    
    def get_firewall_inet_service_custom_all(self, adom):
        request = JsonRpc('get', session=self.session, url=f'/pm/config/adom/{adom}/obj/firewall/internet-service-custom')
        response = self.client.send(request)
        self.console_log(request, response)
        
        return response.text
    
    def get_firewall_inet_service_custom(self, adom, internet_service_custom):
        request = JsonRpc('get', session=self.session, url=f'/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet_service_custom}')
        response = self.client.send(request)
        self.console_log(request, response)
        
        return response.text
    
    def get_firewall_service_custom_all(self, adom):
        request = JsonRpc('get', session=self.session, url=f'/pm/config/adom/{adom}/obj/firewall/service/custom')
        response = self.client.send(request)
        self.console_log(request, response)
        
        return response.text
    
    def get_firewall_service_custom(self, adom, custom):
        request = JsonRpc('get', session=self.session, url=f'/pm/config/adom/{adom}/obj/firewall/service/custom/{custom}')
        response = self.client.send(request)
        self.console_log(request, response)
        
        return response.text
    
    def get_firewall_service_group_all(self, adom):
        request = JsonRpc('get', session=self.session, url=f'/pm/config/adom/{adom}/obj/firewall/service/group')
        response = self.client.send(request)
        self.console_log(request, response)
        
        return response.text
    
    def get_firewall_service_group(self, adom, group):
        request = JsonRpc('get', session=self.session, url=f'/pm/config/adom/{adom}/obj/firewall/service/group/{group}')
        response = self.client.send(request)
        self.console_log(request, response)
        
        return response.text
    
    def get_firewall_vip_all(self, adom):
        request = JsonRpc('get', session=self.session, url=f'/pm/config/adom/{adom}/obj/firewall/vip')
        response = self.client.send(request)
        self.console_log(request, response)
        return response.text
      
    def get_firewall_vip(self, adom, vip):
        request = JsonRpc('get', session=self.session, url=f'/pm/config/adom/{adom}/obj/firewall/vip/{vip}')
        response = self.client.send(request)
        self.console_log(request, response)
        return response.text
        
    
    
    
    
class FazApi:
    
    def __init__(self, faz, **kwargs):

        #self.json_data = self._load_json()
        #self.fmg_values = self.json_data[fmg]

        managers = {"lab-faz": API_FAZ_IP}
        logins = {"lab-faz": (API_USER, getpass())}
        base_url = f'https://{managers[faz]}/jsonrpc'
        print(f'BASE URL:\n{base_url}\n')
        self.client = HTTPclient(base_url)
        self.client.session.verify = False
        self.user = logins[faz][0]
        self.password = logins[faz][1]
        self.session = self.get_session()
        
        
    
    def console_log(self, request, response):
        
        if request is None:
            print("\n", f"RESPONSE:\n{response.text}", "\n")
        else:
            print("\n", f"RPC CALL:\n{request}", "\n")
            print("\n", f"RESPONSE:\n{response.text}", "\n")
        
        
    def get_session(self):
        request = JsonRpc('exec', 
                          url='/sys/login/user', 
                          data={'user':self.user, 
                                'passwd': self.password})
        response = self.client.send(request)
        self.console_log(None, response)
        self.session = json.loads(response.text)['session']
        return self.session


    def close_session(self):
        request = JsonRpc('exec', 
                          session=self.session, 
                          url='/sys/logout')
        response = self.client.send(request)
        self.console_log(request, response)                
        return response.text
    

    def get_fortiview_tid(self, adom, view, days):
        
        tframe = time_frame(days)
        
        views = {
            'top-threats': 'top-threats',
            'top-sources': 'top-sources',
            'top-destinations': 'top-destinations',
            'top-countries': 'top-countries',
            'policy-hits': 'policy-hits', 
            'top-applications': 'top-applications',
            'top-cloud-applications': 'top-cloud-applications', 
            'top-websites': 'top-websites',
            'top-browsing-users': 'top-browsing-users',
            'ssl-dialup-ipsec': 'ssl-dialup-ipsec',
            'site-to-site-ipsec': 'site-to-site-ipsec',
            'rogue-access-points': 'rogue-access-points',
            'authorized-access-points': 'authorized-access-points',
            'authorized-ssids': 'authorized-ssids',
            'wifi-clients': 'wifi-clients',
            'admin-logins': 'admin-logins',
            'system-events': 'system-events',
            'resource-usage': 'resource-usage',
            'failed-authentication-attempts': 'failed-authentication-attempts',
            'endpoints': 'endpoints',
            'top-fct-vulnerabilities-dev': 'top-fct-vulnerabilities-dev',
            'top-fct-vulnerabilities-vuln': 'top-fct-vulnerabilities-vuln',
            'top-fct-threats': 'top-fct-threats',
            'top-fct-applications': 'top-fct-applications',
            'top-fct-websites': 'top-fct-websites',
            'top-type': 'top-type'}
        
        request = JsonRpc(
            'add', 
            session=self.session, 
            url=f'/fortiview/adom/{adom}/{view}/run', 
            apiver= 3, 
            case_sensitive='false', 
            device=[{'devid': 'All_FortiGate'}], 
            time_range={ 
                "end": tframe['endtime'],
                "start": tframe['starttime']}
        )
        
        response = self.client.send(request)
        self.console_log(request, response)
        return (json.loads(response.text)['result']['tid'], view)

    def get_fortiview_data(self, adom, tid, view):
        
        request = JsonRpc('get', 
                          session=self.session, 
                          url=f'/fortiview/adom/{adom}/{view}/run/{tid}', 
                          apiver= 3)
        response = self.client.send(request)
        self.console_log(request, response)
        
        return json.loads(response.text)        

    def get_fortiview(self, view, adom='CloudSmartz', days=1):
        
        t = self.get_fortiview_tid(adom, view, days=days)
        s = self.get_fortiview_data(adom, tid=t[0], view=view)
        
        while not s['result']['data']:
            s = self.get_fortiview_data(adom, tid=t[0], view=view)
            sleep(1)
        
        return s['result']['data']
