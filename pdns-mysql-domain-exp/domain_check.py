# -*- coding: utf-8 -*-
import pythonwhois

from collections import Counter
from collections import deque
import datetime
import time
import socket
import subprocess
import random
import traceback
import sys
import re
from typing import Union

from lib.db import domains_from_db
from lib.email import my_sendmail
from lib.exceptions import MyTooManyWhoisQuerisError, MyWhoisBanError

try:
    from settings_local import *
except ImportError:
    from settings import *


if conf_how == 'socket':
    socket.setdefaulttimeout(6)


def get_tld(domain: str) -> str:
    return re.search(r'.+\.([a-z]{2,})$', domain).group(1)


def unique_tld_domains_only(domains: list) -> list:
    """Only 1 domain for each TLD for debug run"""
    domains_unique_tld = []
    tlds = []
    for domain in domains:
        tld = get_tld(domain).upper()
        if tld not in tlds:
            tlds.append(tld)
            domains_unique_tld.append(domain)
    return domains_unique_tld


def find_duplicates(domains: list) -> tuple:
    duplicate_domains = []
    if len(domains) != len(set(domains)):
        counted = Counter(domains)
        duplicate_domains = [x for x in counted if counted[x] > 1]
        domains = list(set(domains))  # do not need duplicates any more
        return (domains, duplicate_domains)


def whois_exp_check(domain: str) -> Union[str, None]:
    """ checks if domain is already expired or close to it """
    tld = get_tld(domain)
    
    if conf_how == 'cli':
        if tld == 'name':
            whois_query = '=' + domain
        elif tld == 'me':
            whois_query = '-h whois.nic.me "%s"' % domain
        else:
            whois_query = '"domain =' + domain + '"'
        raw_whois = subprocess.check_output('whois ' + whois_query, shell=True)
    else:
        if tld == 'name':
            whois_query = "domain =%s" % domain
            server = pythonwhois.net.get_root_server(domain)
            raw_whois = pythonwhois.net.whois_request(whois_query, server)
        elif tld == 'me':
            server = pythonwhois.net.get_root_server(domain)
            raw_whois = pythonwhois.net.whois_request(domain, server)
        else:
            raw_whois = pythonwhois.net.get_whois_raw(domain)
    
    # must e a list (internal pythonwhois format)   
    if type(raw_whois) is not list:
        raw_whois = [raw_whois,]
    result = pythonwhois.parse.parse_raw_whois(raw_whois, True)
    now_dt = datetime.datetime.now()
    try:
        expires = result['expiration_date'][0]  # datetime.datetime obj
        if conf_debug:
            print(domain, expires, 'domains left:', len(domains), 'try:', try_cnt)
        days = int((expires - now_dt).days)
        if days <= conf_days_left:
            return "%d days left" % days
    except (KeyError, IndexError,):
        raw_whois_txt = "\n\n".join(raw_whois)
        if conf_debug:
            print(domain)
            print(raw_whois_txt)  # full whois response text
            print("")
        if 'whois limit exceeded' in raw_whois_txt.lower():  # whois ban?
            raise MyWhoisBanError('%s whois banned us.' % (tld.upper()))
        # no expiration_date, this domain must be free
        return "probably expired"
    
    return None


if __name__ == '__main__':
    try:
        domains = domains_from_db(conf_db, conf_db_limit)
        
        if conf_debug_tld:
            print("Debug mode: checking only 1 domain in each TLD:")
            domains = unique_tld_domains_only(domains)
        
        # unique check
        domains, duplicate_domains = find_duplicates(domains)
        
        # expired check
        random.shuffle(domains)
        domains = deque(domains)
        expired_domains = {}
        max_try = len(domains)*conf_try_factor
        try_cnt = 0
        while(domains):
            try:
                try_cnt += 1
                if try_cnt > max_try:
                    raise MyTooManyWhoisQuerisError(
                        "Too many WHOIS queries performed (already %d queries for %d domains)."
                        % ((try_cnt-1), (max_try/conf_try_factor))
                    )
                time.sleep(8)
                domain = domains.popleft()
                exp = whois_exp_check(domain)
                if exp is not None:
                    expired_domains[domain] = exp
            except MyTooManyWhoisQuerisError as e:
                raise  # reraise to stop execution of the script
            except MyWhoisBanError as e:
                if conf_debug:
                    print(domain)
                    print(e)
                    print("")
                domains.append(domain)
                time.sleep(60-8)
            except (subprocess.CalledProcessError, socket.timeout, socket.error) as e:
                if conf_debug:
                    print(domain)
                    print(e)
                    traceback.print_exc(file=sys.stdout)
                    print("")
                domains.append(domain)
        
        # report about problems
        if expired_domains or duplicate_domains:
            msg_txt = 'Checked %d domains using %d whois-queries.\r\n' % ((max_try/conf_try_factor), try_cnt)
            if expired_domains:
                msg_txt += "\r\nExpiring domains:\r\n"
                for key in expired_domains:
                    msg_txt += "%s %s\r\n" % (key, expired_domains[key])
            if duplicate_domains:
                msg_txt += "\r\nDuplicate entries:\r\n%s\r\n" % ("\r\n".join(duplicate_domains))
            
            if sys.platform == 'win32':  # no sendmail here
                print(msg_txt)
            else:
                for to in conf_mailto:
                    my_sendmail(conf_from_email, to, "Expiring domains", msg_txt)
    
    except Exception as e:
        print("Top-level exception occured!")
        print(e)
        traceback.print_exc(file=sys.stdout)
