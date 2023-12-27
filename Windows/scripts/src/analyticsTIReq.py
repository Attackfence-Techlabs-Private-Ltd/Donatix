import os
import sys
import json
import sqlite3
import asyncio
import aiohttp
import datetime
import ipaddress

script_path = os.path.dirname(os.path.abspath(__file__))
db = r"networkdata.db"
DB_FILE_DIR = os.path.join(script_path, db)
ALERT_VERDICT_LIST = ['is_suspicious', 'is_malicious', 'malicious','suspicious']
TI_LIC_KEY = "410333-523719-003261-231036-408522-421738" 
TI_API = "https://3.109.79.47/new_feeds/?value={}&key={}"

def create_table(table_name):
    retval = {}
    data = []
    try:
        ret = 0
        query = None
        # =============================================================================================================
        #  last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
        # # Trigger for atf_local_ti_cache
        # attack_cursor.execute("""CREATE TRIGGER IF NOT EXISTS cache_updated_time 
        #             AFTER UPDATE ON atf_local_ti_cache 
        #             FOR EACH ROW 
        #             BEGIN 
        #                 UPDATE atf_local_ti_cache SET last_updated = CURRENT_TIMESTAMP WHERE id = OLD.id; 
        #         END;""")
        # =============================================================================================================
        if table_name == "dns_query_data":
            query = f"""CREATE TABLE IF NOT EXISTS dns_query_data (
                        id integer PRIMARY KEY, 
                        interface text,
                        time text,
                        dst text,
                        dport integer,
                        src text,
                        sport integer,
                        rcode integer,
                        qname text,
                        qlen integer,
                        labelcount integer,
                        qtype integer,
                        rname text,
                        rtype integer,
                        ttl integer,
                        rlen integer,
                        size integer,
                        dnsResponse text,
                        isDGA integer default 0,
                        tiVerdict JSON,
                        status default 0,
                        created_at TIMESTAMP DEFAULT (strftime('%s', 'now')))
                    """
        if table_name == "dns_query_data_req":
            query = f"""CREATE TABLE IF NOT EXISTS dns_query_data_req (
                        alert_id integer PRIMARY KEY, 
                        id text,
                        ioc TEXT,
                        created_at TIMESTAMP DEFAULT (strftime('%s', 'now')))
                    """
        elif table_name == "atf_local_ti_cache":
            query = f"""CREATE TABLE IF NOT EXISTS atf_local_ti_cache (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ioc TEXT,
                        ioc_type TEXT,
                        dga_score INTEGER DEFAULT 0,
                        mitre_ids TEXT,
                        verdict TEXT,
                        verdict_updated_at INTEGER,
                        created_at TIMESTAMP DEFAULT (strftime('%s', 'now')))
                    """
        if query:
            ans = execute_query(query)
            ret = ans['ret']
            if ans['ret'] == 0:
                print(f"TABLE_CREATED SUCCESSFULLY {table_name}")
            else:
                print(f"UNABLE TO CREATE TABLE {table_name}, Exit")
                        
    except Exception as errmsg:
        exc_type, exc_obj, exc_tb = sys.exc_info()   
        ret = -11
        print(
                ret, 
                """error_message : {}, 
                @ line number : {},
                in file : {}""".format(
                errmsg, 
                exc_tb.tb_lineno, 
                __file__
            )
        )

    retval['ret'] = ret
    retval['data'] = data
    return retval

def execute_query(query, raw_data = None, db_file = None):
    retval = {}
    data = []     
    try:
        ret = 0
        if not db_file:
            db_file = DB_FILE_DIR       
        connection = sqlite3.connect(db_file)
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        if raw_data:
            cursor.executemany(query, raw_data)
        else:
            cursor.execute(query)
        data = cursor.fetchall()
        if data:
            data = [dict(row_data) for row_data in data]
        connection.commit()
    except Exception as errmsg:
        exc_type, exc_obj, exc_tb = sys.exc_info()   
        ret = -22
        print(
                ret, 
                """error_message : {}, 
                query- {}, 
                @ line number : {},
                in file : {}""".format(
                errmsg, 
                query,
                exc_tb.tb_lineno, 
                __file__
            )
        )
    finally:
        connection.close()
    retval['ret'] = ret
    retval['data'] = data
    return retval

async def fetch_data(session, url, indicator, sqlite_db, attack_cursor):
    retval = {}
    data = []
    try:
        ret = 0
        # Make an asynchronous GET request to the provided URL with a timeout of 60 seconds
        async with session.get(url, timeout=60) as response:
            # Check if the response status is 200 (OK)
            if response.status == 200:
                # Parse the JSON data from the response
                ti_data = await response.json()
                # Check if the 'ret' key is present in the data and its value is 0
                if 'ret' in ti_data and ti_data['ret'] == 0:
                    # Remove unnecessary keys from the data
                    ti_data.pop("_id")
                    ti_data.pop("ret")
                    ti_data.pop("last_queried_utc_time")
                    ti_data['verdict_updated_at'] = ti_data.get('last_queried_epoch_time', None)
                    ti_data.pop("last_queried_epoch_time")
                    ti_data['mitre_ids'] = str(ti_data.get('ti_mitre_ids', '[]'))
                    try:
                        ti_data.pop("ti_mitre_ids")
                    except:
                        pass
                    ti_data['ioc_type'] = ti_data.get('ioc_type', 'N/A').lower()
                    ti_data['verdict'] = ti_data.get('ti_verdict', None)
                    ti_data.pop("ti_verdict")
                    
                    # Execute the query with the values
                    ti_query = """INSERT INTO atf_local_ti_cache (dga_score, ioc, ioc_type, verdict_updated_at, 
                                mitre_ids, verdict) VALUES (?, ?, ?, ?, ?, ?)"""
                    attack_cursor.execute(ti_query, tuple(ti_data.values()))

                    # Commit the changes to the database
                    sqlite_db.commit()

                    id_to_del = []
                    dga_score = ti_data.get('dga_score', 0)
                    ti_data.pop('dga_score')  
                    ti_data.pop('verdict_updated_at') 

                    fetch_records = attack_cursor.execute(f"select * from dns_query_data_req where ioc = '{indicator}'")
                    for row in fetch_records.fetchall():
                        id_to_del.append(str(row['alert_id']))
                        # if ti_data['verdict'] in ['is_suspicious', 'is_malicious', 'malicious','suspicious']:
                        # Filter records in the reader that match the indicator
                    
                        row_dict = dict(row) # Extract the values from the ti_data dictionary  
                        row_dict['ti_data'] = json.dumps([ti_data])

                        row_dict.pop('alert_id')
                        row_dict.pop('ioc')
                        row_dict.pop('created_at')

                        columns_list = row_dict.keys()
                        columns_string = ",".join(columns_list)
                        values = ','.join(['?' for _ in columns_list])
                        # check data exist for the record in table or not
                        check_record = attack_cursor.execute(f"select id, tiVerdict from dns_query_data where id = '{row['id']}'")
                        row = check_record.fetchone()
                        tmp_ti_data = ti_data.copy()
                        each = dict(row)
                        if each['tiVerdict']:
                            tmp_ti_data.extend(json.loads(each['tiVerdict']))
                        attack_cursor.execute("update dns_query_data set tiVerdict = ? where id = ?", (
                            tmp_ti_data['verdict'], row['id']))
                        print(f"TABLE TRANSACTION dns_query_data, OPERATION UPDATE  {attack_cursor.rowcount}")
                        sqlite_db.commit()
                    if id_to_del:
                        # delete the ioc(indicators)  
                        attack_cursor.execute("DELETE FROM dns_query_data_req WHERE alert_id in ({})".format(','.join(id_to_del)))
                        print(f"TABLE TRANSACTION dns_query_data_req, OPERATION DELETE  {attack_cursor.rowcount}")
                        sqlite_db.commit()
  
                else:
                    # Log the API status if 'ret' is not 0
                    print("Unknown Internal API Status for URL {}, message {}".format(url, ti_data))          
            else:
                ret = -33
                # Log a warning if the response status is not 200
                print("Response Status not good, Status code {}, url {}".format(response.status, response.reason))
    except asyncio.TimeoutError:
        ret = -33
        # Log a warning if a timeout error occurs
        print("Response Status not good, Status code {}, url {}".format("Time out Error", url))
    except aiohttp.ClientError as err:
        ret = -44
        # Log a warning if there's a client error during the request
        print("Error in Fetching url {}, message {}".format(sys.exc_info()[-1].tb_lineno, err))
    except Exception as errmsg:
        exc_type, exc_obj, exc_tb = sys.exc_info()   
        ret = -1
        print(
                ret, 
                """error_message : {}, 
                @ line number : {},
                in file : {}""".format(
                errmsg, 
                exc_tb.tb_lineno, 
                __file__,
            )
        )
    
    retval['ret'] = ret
    retval['data'] = data
    return retval

def check_ip(ip_address):
    ret = 0
    try:
        ip = ipaddress.ip_address(ip_address)
        if ip.is_private:
            ret = -2
    except ValueError:
        ret = -1
    return ret

async def main():
    retval = {}
    data = []
    try:
        ret = 0
        tasks, distinct_values = [], []

        ans = create_table("dns_query_data")
        if ans['ret'] != 0:
            return -1
        ans = create_table("dns_query_data_req")
        if ans['ret'] != 0:
            return -1
        ans = create_table("atf_local_ti_cache")
        if ans['ret'] != 0:
            return -1

        # Code for fetching public ip and domains from pcap_data and insert into pcap_data_req
        fetch_rawdata = execute_query("SELECT id, dnsResponse, qname FROM dns_query_data where status = 0")   # here argument should be pointer
        if fetch_rawdata['ret'] == 0 and fetch_rawdata['data']:
            id_to_update = ()
            for row_data in fetch_rawdata['data']:
                iocs = {}
                if row_data['dnsResponse']:
                    if not check_ip(row_data['dnsResponse']):
                        iocs.update({'dnsResponse': row_data['dnsResponse']})
                elif row_data['qname']:
                    iocs.update({'qname': row_data['qname']})

                columns_list = row_data.keys()
                columns_string = ",".join(columns_list)
                values = ','.join(['?' for _ in columns_list])
                
                for ioc_key, ioc in iocs.items():
                    query = f"""insert into dns_query_data_req (
                        id, ioc) values (?, ?)"""
                    ans = execute_query(query, [(row_data['id'], ioc)])
                    if ans['ret'] != 0:
                        print(f"TABLE TRANSACTION dns_query_data_req, OPERATION INSERT  {ans['ret']}")
                    else:
                        id_to_update += (row_data['id'],)

            update_query = f"update dns_query_data set status = 1 where id in {id_to_update}"
            ans = execute_query(update_query)
            if ans['ret'] != 0:
                print(f"TABLE TRANSACTION dns_query_data, OPERATION UPDATE  {ans['ret']}")

        # # Connect to the SQLite database
        sqlite_db = sqlite3.connect(DB_FILE_DIR)
        sqlite_db.row_factory = sqlite3.Row
        attack_cursor = sqlite_db.cursor()

        # # Fetch distinct values from the "indicator" column
        unique_indicator = attack_cursor.execute("SELECT * FROM dns_query_data_req group by ioc")
        
        distinct_values = [row['ioc'] for row in unique_indicator.fetchall()]
        if distinct_values:
            window_size = 999
            for i in range(0, len(distinct_values), window_size):
                window = distinct_values[i:i + window_size]
                # Now 'window' contains a subset of 999 records or less
            
                connector = aiohttp.TCPConnector(ssl=False)
                async with aiohttp.ClientSession(connector=connector) as session:
                    tasks = [fetch_data(session, 
                                        TI_API.format(indicator, TI_LIC_KEY), 
                                        indicator, 
                                        sqlite_db, 
                                        attack_cursor) 
                            for indicator in window]
                    await asyncio.gather(*tasks)
                # Add a 1-minute delay after each iteration
                await asyncio.sleep(60)

        sqlite_db.close()

    except Exception as errmsg:
        exc_type, exc_obj, exc_tb = sys.exc_info()   
        ret = -1
        print(
                ret, 
                """error_message : {}, 
                @ line number : {},
                in file : {}""".format(
                errmsg, 
                exc_tb.tb_lineno, 
                __file__
            )
        )
    
    retval['ret'] = ret
    retval['data'] = data
    return retval

def run():
    asyncio.run(main())

run()
