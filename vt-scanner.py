import requests
import time
import argparse
import sys
import base64


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
        sys.exit("Unkown HTTP error.\n" + str(status) + value_for_scan)


def file_scanner(api,file_path,type_file):
    url = 'https://www.virustotal.com/api/v3/files/'
    headers = {'x-apikey':api}

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
                        Suspicious: {values['data']['attributes']['last_analysis_stats']['suspicious']}
                        Undetected: {values['data']['attributes']['last_analysis_stats']['undetected']}\n
                        VT Url for file hash: https://virustotal.com/gui/file/{values['data']['attributes']['sha256']}/detection
                        """)

                    else:
                        print(f"""{hash} is clean.\n
                        Harmless: {values['data']['attributes']['last_analysis_stats']['harmless']}
                        Malicious: {values['data']['attributes']['last_analysis_stats']['malicious']}
                        Suspicious: {values['data']['attributes']['last_analysis_stats']['suspicious']}
                        Undetected: {values['data']['attributes']['last_analysis_stats']['undetected']}\n
                        VT Url for file hash: https://virustotal.com/gui/file/{values['data']['attributes']['sha256']}/detection
                        """)

                except Exception:
                    # Possible error causes; not valid domain pattern or Domain not found in VT Database. If the reasons is not these, please don't be hesitate for contact me.
                    print(values['error']['message'])
                        
                time.sleep(15)
            
            else:
                print(errors(status,hash,type_file))

    file_operations("file_results\\unscanned_hashes.txt","w",unscanned_hashes)

    if(len(unscanned_hashes)==0):
        file_operations("file_results\\unscanned_hashes.txt","w","All hashes succesfully scanned, congrats :)")

    else:
        file_operations("file_results\\unscanned_hashes.txt","w",unscanned_hashes)


def url_scanner(api,url_path,type_url):
    url = 'https://www.virustotal.com/api/v3/urls/'
    headers = {'x-apikey':api}

    with open(url_path,"r",encoding="utf-8") as r_file:
        for url_vt in r_file.read().split():
            url_id = base64.urlsafe_b64encode(url_vt.strip().encode()).decode().strip("=")

            response = requests.get(url+url_id,headers=headers)
            status = response.status_code

            if status == 200:
                values = response.json()
                
                try:
                    if values['data']['attributes']['last_analysis_stats']['malicious']>5:
                        print(f"""{url_vt} is malicious.\n
                        Harmless: {values['data']['attributes']['last_analysis_stats']['harmless']}
                        Malicious: {values['data']['attributes']['last_analysis_stats']['malicious']}
                        Suspicious: {values['data']['attributes']['last_analysis_stats']['suspicious']}
                        Undetected: {values['data']['attributes']['last_analysis_stats']['undetected']}\n
                        VT Url for domain: https://virustotal.com/gui/url/{values['data']['id']}/detection
                        """)

                    else:
                        print(f"""{url_vt} is clean.\n
                        Harmless: {values['data']['attributes']['last_analysis_stats']['harmless']}
                        Malicious: {values['data']['attributes']['last_analysis_stats']['malicious']}
                        Suspicious: {values['data']['attributes']['last_analysis_stats']['suspicious']}
                        Undetected: {values['data']['attributes']['last_analysis_stats']['undetected']}\n
                        VT Url for domain: https://virustotal.com/gui/url/{values['data']['id']}/detection
                        """)

                except Exception:
                    # Possible error causes; not valid domain pattern or Domain not found in VT Database. If the reasons is not these, please don't be hesitate for contact me.
                    print(values['error']['message'])
                    
                time.sleep(15)
            
            else:
                print(errors(status,url_vt,type_url))

    file_operations("url_result\\unscanned_urls.txt","w",unscanned_urls)

    if(len(unscanned_urls)==0):
        file_operations("url_results\\unscanned_urls.txt","w","All urls succesfully scanned, congrats :)")

    else:
        file_operations("url_results\\unscanned_urls.txt","w",unscanned_urls)


def domain_scanner(api,domain_path,type_domain):
    url = 'https://www.virustotal.com/api/v3/domains/'
    headers = {'x-apikey':api}
    
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
                        Suspicious: {values['data']['attributes']['last_analysis_stats']['suspicious']}
                        Undetected: {values['data']['attributes']['last_analysis_stats']['undetected']}\n
                        VT Url for domain: https://virustotal.com/gui/domain/{domain}/detection
                        """)

                    else:
                        print(f"""{domain} is clean.\n
                        Harmless: {values['data']['attributes']['last_analysis_stats']['harmless']}
                        Malicious: {values['data']['attributes']['last_analysis_stats']['malicious']}
                        Suspicious: {values['data']['attributes']['last_analysis_stats']['suspicious']}
                        Undetected: {values['data']['attributes']['last_analysis_stats']['undetected']}\n
                        VT Url for domain: https://virustotal.com/gui/domain/{domain}/detection
                        """)

                except Exception:
                    # Possible error causes; not valid domain pattern or Domain not found in VT Database. If the reasons is not these, please don't be hesitate for contact me.
                    print(values['error']['message'])
                    
                time.sleep(15)

            else:
                print(errors(status,domain,type_domain))

    file_operations("domain_results\\unscanned_domains.txt","w",unscanned_domains)

    if(len(unscanned_domains)==0):
        file_operations("domain_results\\unscanned_domains.txt","w","All domains succesfully scanned, congrats :)")

    else:
        file_operations("domain_results\\unscanned_domains.txt","w",unscanned_domains)


def ip_scanner(api,ip_path,type_ip):
    url = 'https://www.virustotal.com/api/v3/ip_addresses/'
    headers = {'x-apikey':api} 
    
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
                        Suspicious: {values['data']['attributes']['last_analysis_stats']['suspicious']}
                        Undetected: {values['data']['attributes']['last_analysis_stats']['undetected']}\n
                        VT Url for IP: https://virustotal.com/gui/ip-address/{ip}/detection
                        """)

                    else:
                        print(f"""{ip} is clean.\n
                        Harmless: {values['data']['attributes']['last_analysis_stats']['harmless']}
                        Malicious: {values['data']['attributes']['last_analysis_stats']['malicious']}
                        Suspicious: {values['data']['attributes']['last_analysis_stats']['suspicious']}
                        Undetected: {values['data']['attributes']['last_analysis_stats']['undetected']}\n
                        VT Url for IP: https://virustotal.com/gui/ip-address/{ip}/detection
                        """)

                except Exception:
                    # Possible error causes; not valid domain pattern or Domain not found in VT Database. If the reasons is not these, please don't be hesitate for contact me.
                    print(values['error']['message'])
                    
                time.sleep(15)

            else:
                print(errors(status,ip,type_ip))

    file_operations("ip_results\\unscanned_domains.txt","w",unscanned_ips)

    if(len(unscanned_ips)==0):
        file_operations("ip_results\\unscanned_ips.txt","w","All IPs succesfully scanned, congrats :)")

    else:
        file_operations("ip_results\\unscanned_ips.txt","w",unscanned_ips)



def main():
    print("""Sample Usages:
    python vt-scanner.py -t file -p hashes.txt
    python vt-scanner.py -t domain -p domains.txt
    python vt-scanner.py -t ip -p ips.txt
    python vt-scanner.py -t url -p urls.txt

    If you faced with errors please contact me on Twitter @gokhanntepe
    """)

    api = input("Enter your API key: ")
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
    main()
    
