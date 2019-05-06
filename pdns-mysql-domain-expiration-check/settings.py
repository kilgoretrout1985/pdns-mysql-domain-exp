# emails to send them a list of domains which are about to expire
conf_mailto = ['admin@localhost', 'user@mail',]

# db connection dicts for MySQLdb.connect(**each_dict)
# each dict being a separate DB connection
conf_db = [
    # { 'unix_socket': '/tmp/mysql.sock', 'user': 'domain_check', 'passwd': '1234pass', 'db': 'pdns' },
    # { 'host': 'remote.host.com', 'user': 'mysqluser42', 'passwd': '456anotherpass', 'db': 'pdns' },
]

conf_debug = False

# in this mode it will check 1 domain in each TLD
conf_debug_tld = (True and conf_debug)

# tries for domain, max whois queries = number of domains * conf_try_factor
conf_try_factor = 3

# report N days before domain expires
conf_days_left = 21

# get N domains from DB at a time
conf_db_limit = 1000

# how to retrieve whois data
conf_how = 'socket'  # socket|cli