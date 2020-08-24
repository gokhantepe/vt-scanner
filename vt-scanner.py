import requests
import time
import argparse
import sys


def file_operations(file_name,operation_name,content):
    with open(file_name,operation_name,encoding="utf-8") as file:
        for each in content:
            file.write(each)


def errors(status,value_for_scan,scan_type):
    if status == 204:
        if scan_type=="file":
            unscanned_hashes.append(value_for_scan+"\n")
                
            print("There is no content in HTTP response. It may cause by rate-limiting. Sleeping for 45 seconds.")
            time.sleep(45)

            return f"{value_for_scan} is saved your current directory for next scan.\n\n"

        elif scan_type=="url":
            unscanned_urls.append(value_for_scan+"\n")
            
            print("\nThere is no content in HTTP response. It may cause by rate-limiting. Sleeping for 45 seconds.")
            time.sleep(45)

            return f"{value_for_scan} is saved your current directory for next scan.\n\n"

        elif scan_type=="domain":
            unscanned_domains.append(value_for_scan+"\n")
            
            print("\nThere is no content in HTTP response. It may cause by rate-limiting. Sleeping for 45 seconds.")
            time.sleep(45)

            return f"{value_for_scan} is saved your current directory for next scan.\n"

        elif scan_type=="ip":
            unscanned_ips.append(value_for_scan+"\n")
            
            print("\nThere is no content in HTTP response. It may cause by rate-limiting. Sleeping for 45 seconds.")
            time.sleep(45)

            return f"{value_for_scan} is saved your current directory for next scan.\n"
            
    elif status == 400:
        sys.exit("""Bad request. Your request was somehow incorrect.
        This can be caused by missing arguments or arguments with wrong values.""")

    elif status == 403:            
        sys.exit("You are not allowed to perform the requested operation.")

    else:
        sys.exit("Unkown HTTP error.\n" + str(status))


def file_scanner(api,file_path,type_file):
    url = 'https://www.virustotal.com/api/v3/files/'
    headers = {'x-apikey':'4cd089f9fbe2593c867c8857b871f0f0f51c8d710d880b9bf2d61f7dc9132f5c'}

    with open(file_path,"r",encoding="utf-8") as r_file:
        for hash in r_file.read().split():
            response = requests.get(url+hash.strip(), headers=headers)
            status = response.status_code
            
            if status == 200:
                values = response.json()
                
                try:
                    if values['data']['attributes']['last_analysis_stats']['malicious']>5:
                        print(f"""{hash} is malicious.\n
                        Harmless: {values['data']['attributes']['last_analysis_stats']['harmless']}
                        Malicious: {values['data']['attributes']['last_analysis_stats']['malicious']}
                        Suspicious: {values['data']['attributes']['last_analysis_stats']['suspicious']}\n
                        VT Url for domain: {values['data']['links']['self']}
                        """)

                    else:
                        print(f"""{hash} is clean.\n
                        Harmless: {values['data']['attributes']['last_analysis_stats']['harmless']}
                        Malicious: {values['data']['attributes']['last_analysis_stats']['malicious']}
                        Suspicious: {values['data']['attributes']['last_analysis_stats']['suspicious']}\n
                        VT Url for domain: {values['data']['links']['self']}
                        """)

                except Exception:
                    # Possible error causes; not valid domain pattern or Domain not found in VT Database. If the reasons is not these, please don't be hesitate for contact me.
                    print(values['error']['message'])
                        
                time.sleep(15)
            
            else:
                print(errors(status,hash,type_file))

    file_operations("file_results\\unscanned_hashes.txt","w",unscanned_hashes)


def url_scanner(api,url_path,type_url):
    url = 'https://www.virustotal.com/vtapi/v2/url/report'

    with open(url_path,"r",encoding="utf-8") as r_file:
        for url_vt in r_file.read().split():
            params = {'apikey': api, 'resource':url_vt.strip()}

            response = requests.get(url, params=params)
            status=response.status_code

            if status == 200:
                values = response.json()
                response_code = values["response_code"]

                if response_code == 0:
                    print(params["resource"] + "\n" + "Url is not found in VT database.\n\n")

                else:
                    positive_values = values["positives"]

                    if positive_values > 0:
                        print(params["resource"] + "\n" + "This url is suspicious.")
                        print("URL for suspicious url: " + values["permalink"] + "\n\n")

                    else:
                        continue # url is clear.
                        
                time.sleep(15)
            
            else:
                print(errors(status,url_vt,type_url))

    file_operations("url_result\\unscanned_urls.txt","w",unscanned_urls)


def domain_scanner(api,domain_path,type_domain):
    url = 'https://www.virustotal.com/api/v3/domains/'
    headers = {'x-apikey':'4cd089f9fbe2593c867c8857b871f0f0f51c8d710d880b9bf2d61f7dc9132f5c'}
    
    with open(domain_path,"r",encoding="utf-8") as r_file:
        for domain in r_file.read().split():
            response = requests.get(url + domain.strip(), headers=headers)
            status=response.status_code
            
            if status == 200:
                values = response.json()
                
                try:
                    if values['data']['attributes']['last_analysis_stats']['malicious']>5:
                        print(f"""{domain} is malicious.\n
                        Harmless: {values['data']['attributes']['last_analysis_stats']['harmless']}
                        Malicious: {values['data']['attributes']['last_analysis_stats']['malicious']}
                        Suspicious: {values['data']['attributes']['last_analysis_stats']['suspicious']}\n
                        VT Url for domain: {values['data']['links']['self']}
                        """)

                    else:
                        print(f"""{domain} is clean.\n
                        Harmless: {values['data']['attributes']['last_analysis_stats']['harmless']}
                        Malicious: {values['data']['attributes']['last_analysis_stats']['malicious']}
                        Suspicious: {values['data']['attributes']['last_analysis_stats']['suspicious']}\n
                        VT Url for domain: {values['data']['links']['self']}
                        """)

                except Exception:
                    # Possible error causes; not valid domain pattern or Domain not found in VT Database. If the reasons is not these, please don't be hesitate for contact me.
                    print(values['error']['message'])
                    
                time.sleep(15)

            else:
                print(errors(status,domain,type_domain))


    if(len(unscanned_domains)==0):
        file_operations("domain_results\\unscanned_domains.txt","w","All domains succesfully scanned, congrats :)")
    else:
        file_operations("domain_results\\unscanned_domains.txt","w",unscanned_domains)


def ip_scanner(api,ip_path,type_ip):
    url = 'https://www.virustotal.com/api/v3/ip_addresses/'
    headers = {'x-apikey':'4cd089f9fbe2593c867c8857b871f0f0f51c8d710d880b9bf2d61f7dc9132f5c'} 
    
    with open(ip_path,"r",encoding="utf-8") as r_file:
        for ip in r_file.read().split():
            response = requests.get(url + ip.strip(), headers=headers)
            status=response.status_code
            
            if status == 200:
                values = response.json()
                
                try:
                    if values['data']['attributes']['last_analysis_stats']['malicious']>5:
                        print(f"""{ip} is malicious.\n
                        Harmless: {values['data']['attributes']['last_analysis_stats']['harmless']}
                        Malicious: {values['data']['attributes']['last_analysis_stats']['malicious']}
                        Suspicious: {values['data']['attributes']['last_analysis_stats']['suspicious']}\n
                        VT Url for domain: {values['data']['links']['self']}
                        """)

                    else:
                        print(f"""{ip} is clean.\n
                        Harmless: {values['data']['attributes']['last_analysis_stats']['harmless']}
                        Malicious: {values['data']['attributes']['last_analysis_stats']['malicious']}
                        Suspicious: {values['data']['attributes']['last_analysis_stats']['suspicious']}\n
                        VT IP for domain: {values['data']['links']['self']}
                        """)

                except Exception:
                    # Possible error causes; not valid domain pattern or Domain not found in VT Database. If the reasons is not these, please don't be hesitate for contact me.
                    print(values['error']['message'])
                    
                time.sleep(15)

            else:
                print(errors(status,ip,type_ip))

    if(len(unscanned_ips)==0):
        file_operations("ip_results\\unscanned_ips.txt","w","All IPs succesfully scanned, congrats :)")
    else:
        file_operations("ip_results\\unscanned_ips.txt","w",unscanned_ips)



def main():
    api = input("Enter your API key. ")
    print("\n\n")

    parser = argparse.ArgumentParser(description='You can submit multiple file hashes and urls with this script.')
    parser.add_argument("-t","--type",help="You should type what you want for submitting VT (url or file or domain).",required=True)
    parser.add_argument("-p","--path",help="Type file path",required=True)
    
    args=parser.parse_args()

    
    if args.type in ("file","File","FILE"):
        file_scanner(api,args.path,args.type)

    elif args.type in ("url","Url","URL"):
        url_scanner(api,args.path,args.type)

    elif args.type in ("domain","Domain","DOMAIN"):
        domain_scanner(api,args.path,args.type)

    elif args.type in ("ip","Ip","IP"):
        ip_scanner(api,args.path,args.type)
    else:
        sys.exit("You entered wrong values.")

        

if __name__=="__main__":
    asterisk="\n\n************************************************************************************************************************************\n\n"
    hypen="------------------------------------------------------------------------------------------------------------------------------------\n"
    unscanned_hashes=list()
    unscanned_urls=list()
    unscanned_domains=list()
    unscanned_ips=list()
    detected_iocs=list()
    detected_sampe_hashes=list()
    main()
    
