import MySQLdb


def domains_from_db(connection_data: dict, at_a_time: int = 1000) -> list:
    domains = []
    for connect_params in connection_data:
        if 'charset' not in connect_params:
            connect_params['charset'] = 'utf8'
        db = MySQLdb.connect(**connect_params)
        cursor = db.cursor()
        
        cursor.execute("SELECT count(id) FROM domains")
        data = cursor.fetchall()
        max_i = int(data[0][0])
        if max_i > 0:
            for i in range(0, max_i, at_a_time):
                cursor.execute("SELECT name FROM domains ORDER BY id ASC LIMIT %d, %d" % (i, at_a_time))
                data = cursor.fetchall()
                for rec in data:
                    domain = rec[0]
                    if domain.count('.') == 1:  # no subdomains
                        domains.append(domain.lower().strip())
        
        db.close()
    return domains
