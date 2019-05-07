# -*- coding: utf-8 -*-
import MySQLdb
import pythonwhois

from collections import Counter
from collections import deque
import datetime
import time
import socket
from email.mime.text import MIMEText
import subprocess
import random
import traceback
import sys
import re

try:
    from settings_local import *
except ImportError:
    from settings import *


if conf_how == 'socket':
    socket.setdefaulttimeout(6)


class MyTooManyWhoisQuerisError(Exception):
    pass


class MyWhoisBanError(Exception):
    pass


def get_tld(domain):
    return re.search(r'.+\.([a-z]{2,})$', domain).group(1)


def whois_exp_check(domain):
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
    
    # должен быть массивом (внутренний формат библиотеки)    
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
            return "%d дней осталось" % (days)
    except (KeyError, IndexError,):
        raw_whois_txt = "\n\n".join(raw_whois)
        if conf_debug:
            print(domain)
            print(raw_whois_txt)  # full whois response text
            print("")
        if 'whois limit exceeded' in raw_whois_txt.lower():  # org whois ban?
            raise MyWhoisBanError('%s whois banned us.' % (tld.upper()))
        # нет expiration_date, значит домен свободен
        return "предположительно истек"
    
    return None


def my_sendmail(fr, to, subj, body):
    msg = MIMEText(body, 'plain', 'utf-8')
    msg["From"] = fr
    msg["To"] = to
    msg["Subject"] = subj
    p = subprocess.Popen(["/usr/sbin/sendmail", "-t"], stdin=subprocess.PIPE)
    return p.communicate(msg.as_string())


if __name__ == '__main__':
    try:
        # read all domains from DBs
        domains = []
        for connect_params in conf_db:
            if 'charset' not in connect_params:
                connect_params['charset'] = 'utf8'
            db = MySQLdb.connect(**connect_params)
            cursor = db.cursor()
            
            cursor.execute("SELECT count(id) FROM domains")
            data = cursor.fetchall()
            max_i = int(data[0][0])
            if max_i > 0:
                for i in range(0, max_i, conf_db_limit):
                    cursor.execute("SELECT name FROM domains ORDER BY id ASC LIMIT %d, %d" % (i, conf_db_limit))
                    data = cursor.fetchall()
                    for rec in data:
                        domain = rec[0]
                        if domain.count('.') == 1: # не сабдомены
                            domains.append(domain.lower().strip())
            
            db.close()
        
        # для проверки парсера оставим по одному домену из каждой tld
        if conf_debug_tld:
            print("Debug mode: checking only 1 domain in each TLD:")
            domains_unique_tld = []
            tlds = []
            for domain in domains:
                tld = get_tld(domain).upper()
                if tld not in tlds:
                    tlds.append(tld)
                    domains_unique_tld.append(domain)
                    print("%s: %s" % (tld, domain))
            domains = domains_unique_tld
            tlds = None
            print("")
        
        # unique check
        duplicate_domains = []
        if len(domains) != len(set(domains)):
            counted = Counter(domains)
            duplicate_domains = [x for x in counted if counted[x] > 1]
            domains = list(set(domains)) # дубли больше не нужны
        
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
                raise # reraise to stop execution of the script
            except MyWhoisBanError as e:
                if conf_debug:
                    print(domain)
                    print(type(e))
                    print(e)
                    print("")
                domains.append(domain)
                time.sleep(60-8)
            except (subprocess.CalledProcessError, socket.timeout, socket.error) as e:
                if conf_debug:
                    print(domain)
                    print(type(e))
                    print(e)
                    traceback.print_exc(file=sys.stdout)
                    print("")
                domains.append(domain)
        
        # report about problems
        if expired_domains or duplicate_domains:
            msg_txt = 'Всего проверено %d доменов за %d запросов.\r\n' % ((max_try/conf_try_factor), try_cnt)
            if expired_domains:
                msg_txt += "\r\nИстекающие домены:\r\n"
                for key in expired_domains:
                    msg_txt += "%s %s\r\n" % (key, expired_domains[key])
            if duplicate_domains:
                msg_txt += "\r\nДублирующиеся записи:\r\n%s\r\n" % ("\r\n".join(duplicate_domains))
            
            if sys.platform == 'win32':
                print(msg_txt.encode('cp866', 'ignore'))  # console
            else:
                for to in conf_mailto:
                    my_sendmail(conf_from_email, to, "Истекающие домены", msg_txt) # email
        
    except Exception as e:
        print("Top-level exception occured!")
        print(type(e))
        print(e)
        traceback.print_exc(file=sys.stdout)
