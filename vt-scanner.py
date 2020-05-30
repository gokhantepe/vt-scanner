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

            return "This hash is saved your current directory for next scan.\n\n"

        elif scan_type=="url":
            unscanned_urls.append(value_for_scan+"\n")
            
            print("There is no content in HTTP response. It may cause by rate-limiting. Sleeping for 45 seconds.")
            time.sleep(45)

            return "This url is saved your current directory for next scan.\n\n"

        elif scan_type=="domain":
            unscanned_domains.append(value_for_scan+"\n")
            
            print("There is no content in HTTP response. It may cause by rate-limiting. Sleeping for 45 seconds.")
            time.sleep(45)

            return "This domain is saved your current directory for next scan.\n\n"
            
    elif status == 400:
        sys.exit("""Bad request. Your request was somehow incorrect.
        This can be caused by missing arguments or arguments with wrong values.""")

    elif status == 403:            
        sys.exit("You are not allowed to perform the requested operation.")

    else:
        return "Unkown HTTP error.\n" + str(status)


def file_scanner(api,file_path,type_file):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'

    with open(file_path,"r",encoding="utf-8") as file:
        for hash in file.read().split():
            params = {'apikey': api, 'resource': hash.strip()}

            response = requests.get(url, params=params)
            status = response.status_code
            
            if status == 200:
                values = response.json()
                response_code = values["response_code"]

                if response_code == 0:
                    print(params["resource"] + "\n" + "File hash is not found in VT database.\n\n")

                else:
                    positive_values = values["positives"]

                    if positive_values > 10:
                        print(params["resource"] + "\n" + "This hash value is suspicious.")
                        print("URL for suspicious hash: " + values["permalink"] + "\n\n")

                    else:
                        continue # hash is clear.
                        
                time.sleep(15)
            
            else:
                print(errors(status,hash,type_file))

    file_operations("unscanned_hashes.txt","w",unscanned_hashes)


def url_scanner(api,url_path,type_url):
    url = 'https://www.virustotal.com/vtapi/v2/url/report'

    with open(url_path,"r",encoding="utf-8") as file:
        for url_vt in file.read().split():
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

    file_operations("unscanned_urls.txt","w",unscanned_urls)


def domain_scanner(api,domain_path,type_domain,whitelist_file_path):
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    total_detected_urls_score=0

    file_operations("detected_urls.txt","w","Detected Urls          |          Score\n\n")

    with open(domain_path,"r",encoding="utf-8") as file1:
        for domain in file1.read().split():
            params = {'apikey':api, 'domain':domain}
                
            response = requests.get(url, params=params)
            status=response.status_code
            
            if status == 200:
                values = response.json()
                response_code = values["response_code"]
                
                if response_code == 1:
                    for i in range(0,len(values["detected_urls"])):
                        total_detected_urls_score+=values["detected_urls"][i]["positives"]

                    if total_detected_urls_score>len(values["detected_urls"]):
                        with open(whitelist_file_path,"r") as file2:
                            if domain not in file2.read().split():
                                print(f"{domain} Domain is malicious. Score: {total_detected_urls_score}")
                                    
                                for i in range(0,len(values["detected_urls"])):
                                    detected_urls.append(values["detected_urls"][i]["url"] + "    ----->    " + str(values["detected_urls"][i]["positives"]) + "\n")
    
                                detected_urls.append("""\n************************************************************************************************************************************\n
                                ************************************************************************************************************************************\n\n""")

                                print("Detected urls and its score saved your current directory.\n\n")

                    else:
                        print(f"{domain} is clean")    # Domain is clean.
                    
                elif response_code == 0:
                    print(f"{domain}\nDomain is not found in VT database.\n\n")

                time.sleep(15)

            else:
                print(errors(status,domain,type_domain))

    file_operations("detected_urls.txt","a",detected_urls)
    file_operations("unscanned_domains.txt","w",unscanned_domains)



def main():
    api = input("Enter your API key. ")
    print("\n\n")

    parser = argparse.ArgumentParser(description='You can submit multiple file hashes and urls with this script.')
    parser.add_argument("-t","--type",help="You should type what you want for submitting VT (url or file or domain).",required=True)
    parser.add_argument("-p","--path",help="Type file path",required=True)
    parser.add_argument("-w","--whitelist",help="""If you scan for domains, you can exclude benign domains with this parameter.
                                                Add whitelist txt file path.""")
    args=parser.parse_args()

    
    if args.type in ("file","File","FILE"):
        file_scanner(api,args.path,args.type)

    elif args.type in ("url","Url","URL"):
        url_scanner(api,args.path,args.type)

    elif args.type in ("domain","Domain","DOMAIN"):
        domain_scanner(api,args.path,args.type,args.whitelist)

    else:
        sys.exit("You entered wrong values.")

        

if __name__=="__main__":
    unscanned_hashes=list()
    unscanned_urls=list()
    unscanned_domains=list()
    detected_urls=list()
    main()
    
