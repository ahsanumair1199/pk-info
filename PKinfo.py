#!/usr/bin/env python
import sys

VER = 2

try:
    if sys.version_info >= (3,0):
        VER = 3
        from urllib.request import urlopen
        from urllib.error import URLError
    else:
        input = raw_input
        from urllib2 import urlopen
        from urllib2 import URLError
except:
        pass


def fetch(url, decoding='utf-8'):
    "Fetches content of URL"
    return urlopen(url).read().decode(decoding)

def banner():
    print ("        ppppp  k  /   I   NNN     N  FFFFFF   OOOOOOO       ")
    print ("        p   p  k /    I   N  N    N  F       O       O      ")
    print ("        ppppp  k/     I   N   N   N  FFFF    O       O      Made by:")
    print ("        p      k \    I   N    N  N  F       O       O      Ahsan Umair")
    print ("        p      k  \   I   N     NNN  F        OOOOOOO      ")
    print"\n"
       

def menu():
    print("1. Whois Lookup")
    print("2. DNS Lookup + Cloudflare Detector")
    print("3. Zone Transfer")
    print("4. Port Scan")
    print("5. HTTP Header Grabber")
    print("6. Honeypot Detector")
    print("7. Robots.txt Scanner")
    print("8. Link Grabber")
    print("9. IP Location Finder")
    print("10. Traceroute")
    print("11. Contact PK Hacker")
    print("12. Exit")

def pkinfo():
    choice = '1'         # Set as default to enter in the loop
    banner()

    while choice != '11':
        menu()
        choice = input('Enter your choice: (1-11): ')

        if choice == '1':
            domip = input('Enter Domain or IP Address:')
            who = "http://api.hackertarget.com/whois/?q=" + domip
            pwho = fetch(who)
            print(pwho)

        elif choice == '2':
            domain = input('Enter Domain:')
            ns = "http://api.hackertarget.com/dnslookup/?q=" + domain
            pns = fetch(ns)
            print(pns)

            if 'cloudflare' in pns:
                print("Cloudflare Detected!")
            else:
                print("Not Protected By cloudflare")

        elif choice == '3':
            domain = input('Enter Domain:')
            zone = "http://api.hackertarget.com/zonetransfer/?q=" + domain
            pzone = fetch(zone)
            print(pzone)
            if 'failed' in pzone:
                print("Zone transfer failed")

        elif choice == '4':
            domip = input('Enter Domain or IP Address:')
            port = "http://api.hackertarget.com/nmap/?q=" + domip
            pport = fetch(port)
            print (pport)

        elif choice == '5':
            domip = input('Enter Domain or IP Address:')
            header = "http://api.hackertarget.com/httpheaders/?q=" + domip
            pheader = fetch(header)
            print(pheader)

        elif choice == '6':
            ip = input('Enter IP Address:')
            honey = "https://api.shodan.io/labs/honeyscore/" + ip + "?key=C23OXE0bVMrul2YeqcL7zxb6jZ4pj2by"
            
            try:
                phoney = fetch(honey)
            except URLError:
                phoney = None
                print('[-] No information available for that IP!')
            
            if phoney:
                print('{color}mHoneypot Probabilty: {probability}%'.format(color='2' if float(phoney) < 0.5 else '3', probability=float(phoney) * 10))
 

        elif choice == '7':
            domain = input('Enter Domain:')

            if not (domain.startswith('http://') or domain.startswith('https://')):
                domain = 'http://' + domain
            robot = domain + "/robots.txt"
            
            try:
                probot = fetch(robot)
                print(probot)
            except URLError:
                print('[-] Can\'t access to {page}!'.format(page=robot))        

        elif choice == '8':
            page = input('Enter URL:')

            if not (page.startswith('http://') or page.startswith('https://')):
                page = 'http://' + page
            crawl = "https://api.hackertarget.com/pagelinks/?q=" + page
            pcrawl = fetch(crawl)
            print (pcrawl)

        elif choice == '9':
            ip = input('Enter IP Address:')
            geo = "http://ipinfo.io/" + ip + "/geo"
            
            try:
                pgeo = fetch(geo)
                print(pgeo)
            except URLError:
                print('[-] Please provide a valid IP address!')

        elif choice == '10':
            domip = input('Enter Domain or IP Address:')
            trace = "https://api.hackertarget.com/mtr/?q=" + domip
            ptrace = fetch(trace)
            print (ptrace)

        elif choice == '11':
            print("My facebook account: https://www.facebook.com/imran.khalid.5264")
            print("My youtube channel: https://www.youtube.com/channel/UCWmk5tEvUTzNWPKplRctYKw")
            pkinfo()

        elif choice == '12':
            print('12. Exiting')

        else:
            print('[-] Invalid option!')
        #except:
        #    print('[1;31m[-] Something wrong happened!')


#=====# Main #=====#

if __name__ == '__main__':
    pkinfo()
