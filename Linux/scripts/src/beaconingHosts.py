import os
import sqlite3
import dbasemgmt
from datetime import datetime, timedelta

def fetch_beaconing_hosts(start_time, end_time):
    script_path = os.path.dirname(os.path.abspath(__file__))
    db = "networkdata.db"
    db_path = os.path.join(script_path, db)
    conn = dbasemgmt.create_connection(db_path)
    cursor = conn.cursor()
    beaconing_hosts_table_name = "beaconingHosts"

    # Query to create the beaconing hosts table
    beaconing_hosts_table = """
                    CREATE TABLE if not exists {}
                    (   
                        id integer Primary Key,
                        srcIp text,
                        destIp text,
                        numQueries integer,
                        numResponses integer,
                        responsePercentage integer
                    );
                    """.format(beaconing_hosts_table_name)
    dbasemgmt.create_table(conn, beaconing_hosts_table)

    # Query to retrieve the beaconing hosts data from dns conversation summary table
    beaconing_hosts_query = """
                            select srcIp, destIp, count(*) AS total_requests,
                            sum(case when numResponses is not 0 then 1 else 0 end) AS total_responses,
                            (sum(case when numResponses is not 0 then 1 else 0 end) * 100) / COUNT(*) 
                            as response_percentage from dnsConversationSummary where 
                            time >= '{}' and time <= '{}' group by srcIp
                            having (COUNT(*) - SUM(CASE WHEN numResponses is not 0 THEN 1 
                            ELSE 0 END)) * 100 / COUNT(*) >= 95;
                            """.format(start_time, end_time)
    
    # Query to insert the beaconing hosts data into beaconing hosts table
    beaconing_hosts_insert_query = """
                                    insert into beaconingHosts(srcIp, destIp, numQueries, 
                                    numResponses, responsePercentage) VALUES(?, ?, ?, ?, ?);
                                   """
    cursor.execute(beaconing_hosts_query)
    beaconing_hosts_data = cursor.fetchall()
    for x in beaconing_hosts_data:
        cursor.execute(beaconing_hosts_insert_query, x)
    conn.commit()
    conn.close()



start_time = datetime.now() - timedelta(hours=24)
end_time = datetime.now()

fetch_beaconing_hosts(start_time, end_time)
