#!/usr/bin/env python3

import dns.resolver
import argparse

parser = argparse.ArgumentParser(description='SPF Analyser')
parser.add_argument('--domain','-d',help='Enter the Domain name to veriify. E.g. ins1gn1a.com',required=True,nargs='+')
args = parser.parse_args()

spf_record = False
dmarc_record = False

txt_list = []
temp_dmarc = []

for domain in args.domain:

    print ("\n")

    # SPF and Other Checks
    for txt in dns.resolver.query(domain,'TXT').response.answer:
        txt_list.append(txt.to_text())

    txt_list = txt_list[0].split('\n')

    # DMARC Checks
    try:
        for txt in dns.resolver.query(("_dmarc." + domain),'TXT').response.answer:
            temp_dmarc.append(txt.to_text())
        if len(temp_dmarc[0]) > 1:
            txt_list.append(temp_dmarc[0])
    except:
        print ("[!] Unable to perform DMARC checks - No Domain")


    for x in txt_list:
        if "v=spf" in x.lower():
            spf_record = x
        if "v=DMARC" in x:
            dmarc_record = x

    # Main
    print ("[*] Domain: " + domain)

    # SPF Checking

    # Identify servers/hosts in SPF record 
    allowed_servers = []
    spf_allowed_count = 0
    for item in (spf_record.split(" ")[1:]):
        if "include:" in item or "ip4:" in item or "ip6:" in item or "mx:" in item or "a:" in item or "ptr:" in item:
            spf_allowed_count += 1 
            allowed_servers.append(item.split(":")[1])

    # Process checks against *all
    if spf_record:
        print ("    [+] SPF: " + spf_record.split("TXT ")[1])
        if "-all" in spf_record:
            print ("\t[+] Only the following mail servers are authorised to send mail from the " + domain + " domain:")
            for z in allowed_servers:
                print ("\t    - " + z.split(" ")[0])
        elif "~all" in spf_record:
            print ("\t[+] Only the following mail servers are authorised to send mail from the " + domain + " domain with a soft-fail for non-authorised servers, however '~all' should only be used as a transition to '-all':")
            for z in allowed_servers:
                print ("\t    - " + z.split(" ")[0])
        else:
            print ("\t[!] The " + domain + " domain is configured in a way that would allow domain email spoofing to be performed.")
        if "redirect:" in spf_record:
            print ("\t[!] The redirect modifier is configured within the SPF record.")
    else:
        print ("\t[!] The " + domain + " domain does not utilise SPF records for authorising mail servers and is vulnerable to domain email spoofing.")

    if dmarc_record:
        print ("    [+] DMARC: " + dmarc_record.split("TXT ")[1])
        dmarc_policy_reject = False
        dmarc_params = dmarc_record.split(";")
        for p in dmarc_params:
            # Policy checks: reject, none, quarantine
            if " p=quarantine" in p.lower():
                print ("\t[+] p=quarantine: Suspicious emails will be marked as suspected SPAM.")
            elif " p=reject" in p.lower():
                print ("\t[+] p=reject: Emails that fail DKIM or SPF checks will be rejected. (Strong)")
                dmarc_policy_reject = True
            elif " p=none" in p.lower():
                print ("\t[-] p=none: No actions will be performed against emails that have failed DMARC checks. (Weak)")

            # Sender-name (domain/subdomain checks)
            if "adkim=r" in p.lower():
                print ("\t[-] adkim=r (Relaxed Mode): Emails from *." + domain + " are permitted.")
            elif "adkim=s" in p.lower():
                print ("\t[+] adkim=s (Strict Mode): Sender domains must match DKIM mail headers exactly. E.g. if 'd=" + domain + "' then emails are not permitted from subdomains. (Strong)")

            # Percentage Check 
            if "pct=" in p.lower():
                percent_val = p.split("=")[1]
                print ("\t[_] pct=" + percent_val + ": " + percent_val + "% of received mail is subject to DMARC processing")

            if "aspf=r" in p.lower():
                print ("\t[-] aspf=r (Relaxed Mode): Any sub-domain from " + domain + " are permitted to match DMARC to SPF records.")
            elif "aspf=s" in p.lower():
                print ("\t[+] aspf=s (Strict Mode): The 'header from' domain and SPF must match exactly to pass DMARC checks.")

            # Check for SPF/DMARC non-authorsed rejection (No mail)
            if "aspf=s" in p.lower() and spf_allowed_count == 0 and dmarc_policy_reject:
                print ("\t[!] aspf=s: No email can be sent from the " + domain + " domain. No mail servers authorised in SPF and DMARC rejection enabled.")
        
            if "rua=" in p.lower():
                if "mailto:" not in p.lower():
                    print ("\t[!] rua=: Aggregate mail reports will not be sent as incorrect syntax is used. Prepend 'mailto:' before mail addresses.")
                else:
                    if "," in p:
                        print ("\t[+] rua=: Aggregate mail reports will be sent to the following email addresses:")
                        dmarc_mail_list = p.split(",")
                        for dmarc_rua in dmarc_mail_list:
                            try:
                                dmarc_rua = dmarc_rua.split(":")[1]
                            except:
                                dmarc_rua = dmarc_rua
                            print ("\t    - " + dmarc_rua)
                    else:
                        print ("\t[+] rua=" + p[5:] + ": Aggregate mail reports will be sent to this address.")

            if "ruf=" in p.lower():
                if "mailto:" not in p.lower():
                    print ("\t[!] ruf=: Mail failure reports will not be sent as incorrect syntax is used. Prepend 'mailto:' before mail addresses.")
                else:
                    if "," in p:
                        print ("\t[+] rua=: Mail failure reports will be sent to the following email addresses:")
                        dmarc_mail_list = p.split(",")
                        for dmarc_ruf in dmarc_mail_list:
                            try:
                                dmarc_ruf = dmarc_ruf.split(":")[1]
                            except:
                                dmarc_ruf = dmarc_ruf
                            print ("\t    - " + dmarc_ruf)
                    else:
                        print ("\t[+] rua=" + p[5:] + ": Failure reports sent to this address.")
                        

