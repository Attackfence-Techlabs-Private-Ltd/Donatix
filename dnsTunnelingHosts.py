import os
import sqlite3
from datetime import datetime, timedelta
import dbasemgmt


def fetch_dns_hosts(start_time, end_time):
    tld_list = [".com", ".org", ".net", ".int", ".edu", ".gov", ".mil"]
    script_path = os.path.dirname(os.path.abspath(__file__))
    db = "networkdata.db"
    db_path = os.path.join(script_path, db)
    conn = dbasemgmt.create_connection(db_path)
    top_dga_hosts_table_name = "dgaHosts"
    dga_hosts_table = """
                    CREATE TABLE if not exists {}
                    (   
                        id integer Primary Key,
                        dgaHost text,
                        dgaCount integer
                    );
                    """.format(top_dga_hosts_table_name)
    dbasemgmt.create_table(conn, dga_hosts_table)
    dns_tunneling_table_name = "dnsTunneling"
    dns_tunneling_table = """
                    CREATE TABLE if not exists {}
                    (   
                        id integer Primary Key,
                        qname text,
                        queryCount integer,
                        nonZeroPayloadCount integer,
                        responseRatio integer
                    );
                    """.format(dns_tunneling_table_name)
    dbasemgmt.create_table(conn, dns_tunneling_table)
    cursor = conn.cursor()
    cursor1 = conn.cursor()

    dns_tunneling_query = """
                select qname, count(*) as query_count,
                sum(case when size is "" then 0 else 1 end) AS non_zero_payload_count,
                (sum(case when size is "" then 0 else 1 end) / count(*)) * 100 as response_ratio,
                time from dns_query_data where time >= '{}' and time <= '{}'  
                group by qname HAVING query_count >= 1000 and response_ratio >= 10;
                """.format(start_time, end_time)
    dga_hosts_query = """
                    select qname, count(*) as dga_count from dns_query_data 
                    where isDGA = 1 group by qname order by dga_count desc;
                    """

    dga_hosts_insert_query = """
                            insert into dgaHosts(dgaHost, dgaCount) 
                            VALUES(?, ?);
                            """
    
    dns_tunneling_insert_query = """
                            insert into dnsTunneling(qname, queryCount, 
                            nonZeroPayloadCount, responseRatio) 
                            VALUES(?, ?, ?, ?);
                            """
    tlds_dict = {}
    tlds_dict['.com'] = []
    tlds_dict['.org'] = []
    tlds_dict['.net'] = []
    tlds_dict['.int'] = []
    tlds_dict['.edu'] = []
    tlds_dict['.gov'] = []
    tlds_dict['.mil'] = []
    
    cursor.execute(dga_hosts_query)
    dga_hosts_data = cursor.fetchall()
    for x in dga_hosts_data:
        cursor.execute(dga_hosts_insert_query, x)
    
    cursor1.execute(dns_tunneling_query)
    dns_tunneling_data = cursor1.fetchall()
    for x in dns_tunneling_data:
        cursor1.execute(dns_tunneling_insert_query, x)
        if (x[0][-4::] == ".com"):
            tlds_dict[".com"].append(x[0])
        elif (x[0][-4::] == ".org"):
            tlds_dict[".org"].append(x[0])
        if (x[0][-4::] == ".net"):
            tlds_dict[".net"].append(x[0])
        if (x[0][-4::] == ".int"):
            tlds_dict[".int"].append(x[0])
        if (x[0][-4::] == ".edu"):
            tlds_dict[".edu"].append(x[0])
        if (x[0][-4::] == ".gov"):
            tlds_dict[".gov"].append(x[0])
        if (x[0][-4::] == ".mil"):
            tlds_dict[".mil"].append(x[0])
        else:
            pass
    print(tlds_dict)
    conn.commit()
    conn.close()
    
end_time = datetime.now()
start_time = end_time - timedelta(minutes=5)
print(start_time, end_time)

fetch_dns_hosts(start_time, end_time)
