import requests
import time
import argparse
import sys
import base64
import csv


class colors:  
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BLUE = '\033[94m'
    UNDERLINE = '\033[4m'


def file_operations(file_name,operation_name,content):
    with open(file_name,operation_name,encoding="utf-8") as file:
        for each in content:
            file.write(each)


def create_report(type_vt,file_name,operation_name,content):
    with open(file_name, mode='w', newline='') as csv_file:
        fieldnames = [type_vt,'Harmless','Malicious','Suspicious','Undetected','Link']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames, delimiter=';')
        
        writer.writeheader()
        for each in content:
            writer.writerow({type_vt: each[0], 'Harmless': each[1], 'Malicious': each[2], 'Suspicious': each[3], 'Undetected': each[4], 'Link': each[5]})


def errors(status,value_for_scan,scan_type,values):
    if status in (404, 429):
        print(f"""{colors.YELLOW}Error Code: {values['error']['code']}\nError Description: {values['error']['message']}{colors.END}""")
        
        if scan_type=="file":
            unscanned_hashes.append(f"{value_for_scan}\n")

            print("Sleeping for 45 seconds.")
            time.sleep(45)
            
            return f"{colors.YELLOW}{value_for_scan} is saved '/file_results' directory for next scan.{colors.END}\n"

        elif scan_type=="url":
            unscanned_urls.append(f"{value_for_scan}\n")

            print("Sleeping for 45 seconds.")
            time.sleep(45)

            return f"{colors.YELLOW}{value_for_scan} is saved '/url_results' directory for next scan.{colors.END}\n"

        elif scan_type=="domain":
            unscanned_domains.append(f"{value_for_scan}\n")

            print("Sleeping for 45 seconds.")
            time.sleep(45)

            return f"{colors.YELLOW}{value_for_scan} is saved '/domain_results' directory for next scan.{colors.END}\n"

        elif scan_type=="ip":
            unscanned_ips.append(f"{value_for_scan}\n")

            print("Sleeping for 45 seconds.")
            time.sleep(45)

            return f"{colors.YELLOW}{value_for_scan} is saved '/ip_results' directory for next scan.{colors.END}\n"
            
    elif status in (400, 401, 403, 409, 503, 504):            
        return f"""{colors.YELLOW}Error Code: {values['error']['code']}\nError Description: {values['error']['message']}{colors.END}\n"""
    
    else:
        return f"{colors.YELLOW}This is unknown error. I will be appreciated if you contact me about this problem.\nResponse: {values}{colors.END}"


def file_scanner(api,file_path,type_file):
    url = 'https://www.virustotal.com/api/v3/files/'
    headers = {'x-apikey':api}

    with open(file_path,"r",encoding="utf-8") as r_file:
        for hash in r_file.read().split():
            response = requests.get(url+hash.strip(), headers=headers)
            values = response.json()
            status = response.status_code
            
            if status == 200:                
                try:
                    if values['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                        print(f"""{colors.RED}{hash} is malicious.{colors.END}
                        Harmless: {values['data']['attributes']['last_analysis_stats']['harmless']}
                        Malicious: {values['data']['attributes']['last_analysis_stats']['malicious']}
                        Suspicious: {values['data']['attributes']['last_analysis_stats']['suspicious']}
                        Undetected: {values['data']['attributes']['last_analysis_stats']['undetected']}
                        VT link for file hash: https://virustotal.com/gui/file/{values['data']['attributes']['sha256']}/detection
                        """)

                    else:
                        print(f"""{colors.GREEN}{hash} is clean.{colors.END}
                        Harmless: {values['data']['attributes']['last_analysis_stats']['harmless']}
                        Malicious: {values['data']['attributes']['last_analysis_stats']['malicious']}
                        Suspicious: {values['data']['attributes']['last_analysis_stats']['suspicious']}
                        Undetected: {values['data']['attributes']['last_analysis_stats']['undetected']}
                        VT link for file hash: https://virustotal.com/gui/file/{values['data']['attributes']['sha256']}/detection
                        """)

                    report_hashes.append((hash,values['data']['attributes']['last_analysis_stats']['harmless'],values['data']['attributes']['last_analysis_stats']['malicious'],
                                      values['data']['attributes']['last_analysis_stats']['suspicious'],values['data']['attributes']['last_analysis_stats']['undetected'],
                                      f"https://virustotal.com/gui/file/{values['data']['attributes']['sha256']}/detection"))

                except Exception:
                    # Possible error causes; not valid hash pattern or hash not found in VT Database. If the reasons is not these, please don't be hesitate for contact me.
                    print(f"{colors.YELLOW}values['error']['message']{colors.END}")
                        
                time.sleep(15)
            
            else:
                print(errors(status,hash,type_file,values))

    create_report(type_file,"file_results\\report_hashes.csv","w",report_hashes)

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
            values = response.json()
            status = response.status_code

            if status == 200:
                try:
                    if values['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                        print(f"""{colors.RED}{url_vt} is malicious.{colors.END}
                        Harmless: {values['data']['attributes']['last_analysis_stats']['harmless']}
                        Malicious: {values['data']['attributes']['last_analysis_stats']['malicious']}
                        Suspicious: {values['data']['attributes']['last_analysis_stats']['suspicious']}
                        Undetected: {values['data']['attributes']['last_analysis_stats']['undetected']}
                        VT link for URL: https://virustotal.com/gui/url/{values['data']['id']}/detection
                        """)

                    else:
                        print(f"""{colors.GREEN}{url_vt} is clean.{colors.END}
                        Harmless: {values['data']['attributes']['last_analysis_stats']['harmless']}
                        Malicious: {values['data']['attributes']['last_analysis_stats']['malicious']}
                        Suspicious: {values['data']['attributes']['last_analysis_stats']['suspicious']}
                        Undetected: {values['data']['attributes']['last_analysis_stats']['undetected']}
                        VT link for URL: https://virustotal.com/gui/url/{values['data']['id']}/detection
                        """)

                    report_urls.append((url_vt,values['data']['attributes']['last_analysis_stats']['harmless'],values['data']['attributes']['last_analysis_stats']['malicious'],
                                      values['data']['attributes']['last_analysis_stats']['suspicious'],values['data']['attributes']['last_analysis_stats']['undetected'],
                                      f"https://virustotal.com/gui/url/{values['data']['id']}/detection"))

                except Exception:
                    # Possible error causes; not valid url pattern or url not found in VT Database. If the reasons is not these, please don't be hesitate for contact me.
                    print(f"{colors.YELLOW}values['error']['message']{colors.END}")
                    
                time.sleep(15)
            
            else:
                print(errors(status,url_vt,type_url,values))

    create_report(type_url,"url_results\\report_urls.csv","w",report_urls)

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
            values = response.json()
            status=response.status_code
            
            if status == 200:                
                try:
                    if values['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                        print(f"""{colors.YELLOW}{domain} is malicious.{colors.END}
                        Harmless: {values['data']['attributes']['last_analysis_stats']['harmless']}
                        Malicious: {values['data']['attributes']['last_analysis_stats']['malicious']}
                        Suspicious: {values['data']['attributes']['last_analysis_stats']['suspicious']}
                        Undetected: {values['data']['attributes']['last_analysis_stats']['undetected']}
                        VT link for domain: https://virustotal.com/gui/domain/{domain}/detection
                        """)

                    else:
                        print(f"""{colors.GREEN}{domain} is clean.{colors.END}
                        Harmless: {values['data']['attributes']['last_analysis_stats']['harmless']}
                        Malicious: {values['data']['attributes']['last_analysis_stats']['malicious']}
                        Suspicious: {values['data']['attributes']['last_analysis_stats']['suspicious']}
                        Undetected: {values['data']['attributes']['last_analysis_stats']['undetected']}
                        VT link for domain: https://virustotal.com/gui/domain/{domain}/detection
                        """)

                    report_domains.append((domain,values['data']['attributes']['last_analysis_stats']['harmless'],values['data']['attributes']['last_analysis_stats']['malicious'],
                                      values['data']['attributes']['last_analysis_stats']['suspicious'],values['data']['attributes']['last_analysis_stats']['undetected'],
                                      f"https://virustotal.com/gui/domain/{domain}/detection"))

                except Exception:
                    # Possible error causes; not valid domain pattern or Domain not found in VT Database. If the reasons is not these, please don't be hesitate for contact me.
                    print(f"{colors.YELLOW}values['error']['message']{colors.END}")
                    
                time.sleep(15)

            else:
                print(errors(status,domain,type_domain,values))

    create_report(type_domain,"domain_results\\report_domains.csv","w",report_domains)

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
            values = response.json()
            status=response.status_code
            
            if status == 200:
                try:
                    if values['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                        print(f"""{colors.RED}{ip} is malicious.{colors.END}
                        Harmless: {values['data']['attributes']['last_analysis_stats']['harmless']}
                        Malicious: {values['data']['attributes']['last_analysis_stats']['malicious']}
                        Suspicious: {values['data']['attributes']['last_analysis_stats']['suspicious']}
                        Undetected: {values['data']['attributes']['last_analysis_stats']['undetected']}
                        VT link for IP: https://virustotal.com/gui/ip-address/{ip}/detection
                        """)

                    else:
                        print(f"""{colors.GREEN}{ip} is clean.{colors.END}
                        Harmless: {values['data']['attributes']['last_analysis_stats']['harmless']}
                        Malicious: {values['data']['attributes']['last_analysis_stats']['malicious']}
                        Suspicious: {values['data']['attributes']['last_analysis_stats']['suspicious']}
                        Undetected: {values['data']['attributes']['last_analysis_stats']['undetected']}
                        VT link for IP: https://virustotal.com/gui/ip-address/{ip}/detection
                        """)

                    report_ips.append((ip,values['data']['attributes']['last_analysis_stats']['harmless'],values['data']['attributes']['last_analysis_stats']['malicious'],
                                      values['data']['attributes']['last_analysis_stats']['suspicious'],values['data']['attributes']['last_analysis_stats']['undetected'],
                                      f"https://virustotal.com/gui/ip-address/{ip}/detection"))

                except Exception:
                    # Possible error causes; not valid ip pattern or ip not found in VT Database. If the reasons is not these, please don't be hesitate for contact me.
                    print(f"{colors.YELLOW}values['error']['message']{colors.END}")
                    
                time.sleep(15)

            else:
                print(errors(status,ip,type_ip,values))

    create_report(type_ip,"ip_results\\report_ips.csv","w",report_ips)

    if(len(unscanned_ips)==0):
        file_operations("ip_results\\unscanned_ips.txt","w","All IPs succesfully scanned, congrats :)")

    else:
        file_operations("ip_results\\unscanned_ips.txt","w",unscanned_ips)



def main():
    print(f"""
        {colors.RED}                                                                                                                                       
                                               ``           ``                                                                              
       .ohhho.  .ohy+-hysoyhhyoshh`        `:ssooshy`   -+ysooyy-     `yhh-     -shhy.   :yh+` /hhh+   `+hy: .ohhhoooshh  /hhhsosss+.       
        `dMMo    +Mo -mo` sMMy `sm.        yMM-   sm` `yNN:   :m/     smMMd`     +MNMm-   yM`   mMMMs`  `My   -MMM   `ym   mMM:  -NMN.      
         :MMN`  .my   .   sMMy   .         hMMh:.  `  sMMs     `     /N-yMM+     +M+mMN/  yM    mhsMMh. `Ms   -MMM  .+``   mMM:   mMM:      
          yMMs  hd`       sMMy      ----.  .smMMmh/`  NMM/          -N/ .NMN.    +M--dMNo yM    md +NMm- Ms   -MMMoodM`    mMMo:/yNh/       
          `NMN-+N.        sMMy     `ddddy    `-+dMMd` mMM+         `mm+++hMMy    +M- .hMMsyM    md  :NMN:Ms   -MMM``-s     mMMo:yMNs`       
           +MMdN/         sMMy      ````` `s-   `mMM. +MMh    `s-  hm.....mMM:   +M-  `sMMNM    md   -dMNMs   -MMM    /y`  mMM:  sMMd`      
            hMMo         -dMMd-           .Nm+::oNd/   /dNh/:/dN/-yMh.   .hMMm: .yMo`   +NMM   :NN-   .hMMs  `oMMM///oNN  :NMMs` `sMMd:     
            `--          ..--..            .--::-.`     `.--:--.``.-.`   `.---. `.-.`    .-.   .--.    `.-`  `.--------.  .---.`   .--.     
                                                                                                                                            
        {colors.END}                                                                                                                                        
    Sample Usages:
    * python vt-scanner.py -t file -p hashes.txt
    * python vt-scanner.py -t domain -p domains.txt
    * python vt-scanner.py -t ip -p ips.txt
    * python vt-scanner.py -t url -p urls.txt\n
    If you faced with errors please contact me on Twitter @gokhanntepe
    """)

    api = input("Enter your API key: ")
    print("\n")

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
    unscanned_hashes = list()
    unscanned_urls = list()
    unscanned_domains = list()
    unscanned_ips = list()
    report_hashes = list()
    report_urls = list()
    report_domains = list()
    report_ips = list()
    main()
    
