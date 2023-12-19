import os
import sqlite3
import time
import dbasemgmt
from datetime import datetime, timedelta


def fetch_and_print_data(start_time, end_time):
    # Connect to the SQLite3 database
    script_path = os.path.dirname(os.path.abspath(__file__))
    db = "networkdata.db"
    db_path = os.path.join(script_path, db)
    conn = dbasemgmt.create_connection(db_path)
    
    # Query to create dns conversation summary table 
    conversation_summary_table = "dnsConversationSummary"
    conv_comm = """
                CREATE TABLE if not exists {} 
                (
                    id integer Primary Key,
                    srcIp text,
                    destIp text,
                    numQueries integer,
                    numResponses integer,
                    time text
                );
                """.format(conversation_summary_table)
    dbasemgmt.create_table(conn, conv_comm)
    
    # Query to create query response summary table 
    query_response_summary = "queryResponseSummary"
    query_resp_comm = """
                      CREATE TABLE if not exists {} 
                      (
                          id integer Primary Key,
                          numQueries integer,
                          numResponses integer,
                          time text
                      );  
                      """.format(query_response_summary)
    dbasemgmt.create_table(conn, query_resp_comm)
    
    # Query to create tld conversation summary table 
    tld_conversation_summary = "tldConversationSummary"
    tld_conv_summary_comm = """
                            CREATE TABLE if not exists {} 
                            (
                                id integer Primary Key,
                                srcIp text,
                                tld text,
                                numQueries integer,
                                numResponses integer,
                                avgQueryLength integer,
                                maxQueryLength integer,
                                minQueryLength integer,
                                avgPayload integer,
                                maxPayload integer,
                                minPayload integer,
                                time text
                            );
                            """.format(tld_conversation_summary)
    dbasemgmt.create_table(conn, tld_conv_summary_comm)

    # Query to create dns query type breakup table 
    query_type_breakup = "queryTypeBreakUp"
    query_type_breakup_table = """
                                CREATE TABLE if not exists {}
                                (
                                    id integer Primary Key,
                                    Arecord integer,
                                    AAAArecord integer,
                                    OtherRecord integer,
                                    time text
                                )
                               """.format(query_type_breakup)
    dbasemgmt.create_table(conn, query_type_breakup_table)

    # Query to create dns response code breakup table 
    resp_code_breakup = "responseCodeBreakUp"
    resp_code_breakup_table = """
                            CREATE TABLE if not exists {}
                            (
                                id integer Primary Key,
                                rcodeZero integer,
                                rcodeOne integer,
                                rcodeTwo integer,
                                rcodeThree integer,
                                noResponse integer,
                                time text
                            )
                            """.format(resp_code_breakup)
    dbasemgmt.create_table(conn, resp_code_breakup_table)

    # Query to create dns query name length table 
    query_name_length = "queryNameLength"
    query_name_length_table = """
                                CREATE TABLE if not exists {}
                                (
                                    id integer Primary Key,
                                    averageQlen integer,
                                    maximumQlen integer,
                                    minimumQlen integer,
                                    time text
                                )
                              """.format(query_name_length)
    dbasemgmt.create_table(conn, query_name_length_table)

    # Query to create dns label count length table 
    label_count_length = "labelCountLength"
    label_count_length_table = """
                                CREATE TABLE if not exists {}
                                (
                                    id integer Primary Key,
                                    averageLabelLen integer,
                                    maximumLabelLen integer,
                                    minimumLabelLen integer,
                                    time text
                                )
                              """.format(label_count_length)
    dbasemgmt.create_table(conn, label_count_length_table)

    # Query to create dns ttl(time-to-live) value table 
    ttl_value = "ttlValue"
    ttl_value_table = """
                        CREATE TABLE if not exists {}
                        (
                            id integer Primary Key,
                            averageTtlValue integer,
                            maximumTtlValue integer,
                            minimumTtlValue integer,
                            time text
                        )
                      """.format(ttl_value)
    dbasemgmt.create_table(conn, ttl_value_table)

    # Query to create dga(Domain Generation Algorithm) Summary table 
    dga_summary = "dgaSummary"
    dga_summary_table = """
                        CREATE TABLE if not exists {}
                        (
                            id integer Primary Key,
                            src text,
                            isDGA integer,
                            numQueries integer,
                            time text
                        )
                      """.format(dga_summary)
    dbasemgmt.create_table(conn, dga_summary_table)

    cursor = conn.cursor()
    # Query to retrieve dns Conversation Summary from dns_query_data table
    conversation_query = """
                    Select src, dst, 
                    count(*) as 'Number of Queries',
                    sum(case when dnsResponse is "" then 0 else 1 end) as 'Number of Responses',
                    time from dns_query_data where time >= '{}' and time <= '{}' group by src;
                    """.format(start_time, end_time)

    # Query to retrieve tld Conversation Summary from dns_query_data table 
    tld_query = """
    SELECT 
        src as 'Source IP Address',
        qname,
        count(*) as 'Number of Queries',
        sum(case when dnsResponse is "" then 0 else 1 end) as 'Number of Responses',
        avg(qlen) as 'Average Query Length',
        max(qlen) as 'Maximum Query Length',
        min(qlen) as 'Minimum Query Length',
        avg(size) as 'Average Payload',
        max(size) as 'Maximum Payload',
        min(size) as 'Minimum Payload', time
    FROM dns_query_data
    where time >= '{}' and time <= '{}'
    GROUP BY src, substr(qname, -2);
    """.format(start_time, end_time)
    
    # Query to retrieve dns query type from dns_query_data table 
    dns_query_type = """
                        select qtype, time from dns_query_data where 
                        time >= '{}' and time <= '{}';
                     """.format(start_time, end_time)

    # Query to retrieve dns response code from dns_query_data table 
    dns_response_code = """
                            select rcode, time from dns_query_data where 
                            time >= '{}' and time <= '{}';
                        """.format(start_time, end_time)

    # Query to retrieve ttl value from dns_query_data table 
    ttl_value_query = """
                            select avg(ttl), max(ttl), min(ttl), time 
                            from dns_query_data where time >= '{}' and 
                            time <= '{}' group by src;
                        """.format(start_time, end_time)

    # Query to retrieve dns label count length from dns_query_data table 
    label_count_query = """
                            select avg(labelcount), max(labelcount), min(labelcount),
                            time from dns_query_data where time >= '{}' and time <= '{}' 
                            group by src;
                        """.format(start_time, end_time)
    
    # Query to retrieve dns query name length from dns_query_data table 
    query_name_length = """
                            select avg(qlen), max(qlen), min(qlen), time 
                            from dns_query_data where time >= '{}' and time <= '{}' 
                            group by src;
                        """.format(start_time, end_time)
    # Query to retrieve dns query response summary from dns_query_data table 
    query_response = """
                        select count(*) as 'Number of Queries',
                        sum(case when dnsResponse is "" then 0 else 1 end) 
                        as 'Number of Responses', time from dns_query_data 
                        where time >= '{}' and time <= '{}' group by src;
                    """.format(start_time, end_time)
    # Query to retrieve dga summary data from dns_query_data table 
    
    dga_summary_response = """
                        select src, sum(case when isDGA is not 0 then 1 else 0 end) as 
                        'Number of Responses', count(*) as 'Number of Queries',
                        time from dns_query_data where time >= '{}' and 
                        time <= '{}' group by src;
                    """.format(start_time, end_time)
    # Execute the query
    cursor.execute(tld_query)
    tld_results = cursor.fetchall()

    cursor.execute(conversation_query)
    conversation_results = cursor.fetchall()

    cursor.execute(dns_query_type)
    dns_query_type_results = cursor.fetchall()

    cursor.execute(ttl_value_query)
    ttl_value_results = cursor.fetchall()

    cursor.execute(dns_response_code)
    dns_response_code_results = cursor.fetchall()

    cursor.execute(label_count_query)
    label_count_results = cursor.fetchall()

    cursor.execute(query_name_length)
    query_name_length_results = cursor.fetchall()

    cursor.execute(query_response)
    query_response_results = cursor.fetchall()

    cursor.execute(dga_summary_response)
    dga_summary_results = cursor.fetchall()

    # Query to create dns Conversation Summary table 
    conv_summ_insert_query = """
                            insert into dnsConversationSummary(srcIp, destIp,
                            numQueries, numResponses, time) VALUES(?, ?, ?, ?, ?)
                            """

    # Query to create dns Conversation Summary table 
    tld_insert_query = """
                            insert into tldConversationSummary(srcIp, tld, 
                            numQueries, numResponses, avgQueryLength, 
                            maxQueryLength, minQueryLength, avgPayload,
                            maxPayload, minPayload, time) VALUES(?, ?, ?, ?, ?,
                            ?, ?, ?, ?, ?, ?)
                       """
    # Query to create dns Conversation Summary table 
    dns_query_type_insert = """
                                insert into queryTypeBreakUp(Arecord, AAAArecord, 
                                otherRecord, time) VALUES(?, ?, ?, ?)
                            """
    # Query to create dns Conversation Summary table 
    dns_query_response_summary_insert = """
                                            insert into queryResponseSummary(numQueries, 
                                            numResponses, time) VALUES(?, ?, ?)
                                        """
    # Query to create dns Conversation Summary table 
    dns_query_name_length_insert = """
                                        insert into queryNameLength(averageQlen, maximumQlen, 
                                        minimumQlen, time) VALUES(?, ?, ?, ?)
                                    """
    # Query to create dns Conversation Summary table 
    dns_label_count_length_insert = """
                                        insert into labelCountLength(averageLabelLen, 
                                        maximumLabelLen, minimumLabelLen, time) VALUES(?, ?, ?, ?)
                                    """
    # Query to create dns Conversation Summary table 
    dns_ttl_value_insert = """
                            insert into ttlValue(averageTtlValue, maximumTtlValue, 
                            minimumTtlValue, time) VALUES(?, ?, ?, ?)
                           """
    # Query to create dns Conversation Summary table 
    dns_response_code_insert = """
                            insert into responseCodeBreakUp(rcodeZero, rcodeOne, 
                            rcodeTwo, rcodeThree, noResponse, time) VALUES(?, ?, ?, ?, ?, ?)
                            """
    # Query to create dns Conversation Summary table 
    dga_summary_insert = """
                            insert into dgaSummary(src, isDGA, numQueries, time)
                            VALUES(?, ?, ?, ?)
                          """

    for row in tld_results:
        tld = row[1].split(".")[-1]
        cursor.execute(tld_insert_query, (row[0], tld, row[2], row[3],
            row[4], row[5], row[6], row[7], row[8], row[9], row[10]))


    for row in conversation_results:
        cursor.execute(conv_summ_insert_query, row)

    a_record_count = 0
    aaaa_record_count = 0
    other_record_count = 0
    for row in dns_query_type_results:
        if row[0] == 1:
            query_type = "A"
            a_record_count += 1
        elif row[0] == 28:
            query_type = "AAAA"
            aaaa_record_count += 1
        elif row[0] == 65:
            query_type = "HTTPS"
            other_record_count += 1
        elif row[0] == 12:
            query_type = "PTR"
            other_record_count += 1
        elif row[0] == 33:
            query_type = "SRV"
            other_record_count += 1
        elif row[0] == 64:
            query_type = "SVCB"
            other_record_count += 1
        else:
            other_record_count += 1
        cursor.execute(dns_query_type_insert, (a_record_count, 
            aaaa_record_count, other_record_count, row[-1]))
    
    for row in ttl_value_results:
        cursor.execute(dns_ttl_value_insert, row)

    rcode_zero_count = 0
    rcode_one_count = 0
    rcode_two_count = 0
    rcode_three_count = 0
    noresponse_count = 0
    for row in dns_response_code_results:
        if row[0] == 0:
            dns_response = "No Error"
            rcode_zero_count += 1
        elif row[0] == 1:
            dns_response = "Format Error"
            rcode_one_count += 1
        elif row[0] == 2:
            dns_response = "Server Failure"
            rcode_two_count += 1
        elif row[0] == 3:
            dns_response = "Non Existent Domain"
            rcode_three_count += 1
        else:
            dns_response = "No response"
            noresponse_count += 1
        cursor.execute(dns_response_code_insert, (rcode_zero_count, 
            rcode_one_count, rcode_two_count, rcode_three_count, 
            noresponse_count, row[-1]))
    for row in label_count_results:
        cursor.execute(dns_label_count_length_insert, row)

    for row in query_name_length_results:
        cursor.execute(dns_query_name_length_insert, row)
    
    for row in query_response_results:
        cursor.execute(dns_query_response_summary_insert, row)
    for row in dga_summary_results:
        print(row)
        cursor.execute(dga_summary_insert, row)
    
    # Close the database connection
    conn.commit()
    cursor.close()
    conn.close()



def fetch_dns_hosts(start_time, end_time):
    tld_list = [".com", ".org", ".net", ".int", ".edu", ".gov", ".mil"]
    script_path = os.path.dirname(os.path.abspath(__file__))
    db = "networkdata.db"
    db_path = os.path.join(script_path, db)
    conn = dbasemgmt.create_connection(db_path)
    top_dga_hosts_table_name = "dgaHosts"

    # Query to create the dga hosts data table
    dga_hosts_table = """
                    CREATE TABLE if not exists {}
                    (   
                        id integer Primary Key,
                        dgaHost text,
                        dgaCount integer
                    );
                    """.format(top_dga_hosts_table_name)
    dbasemgmt.create_table(conn, dga_hosts_table)

    # Query to create the dns tunneling data table
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

    # Query to retrieve the dns tunneling data from dns_query_data
    dns_tunneling_query = """
                select qname, count(*) as query_count,
                sum(case when size is "" then 0 else 1 end) AS non_zero_payload_count,
                (sum(case when size is "" then 0 else 1 end) / count(*)) * 100 as response_ratio,
                time from dns_query_data where time >= '{}' and time <= '{}'  
                group by qname HAVING query_count >= 1000 and response_ratio >= 10;
                """.format(start_time, end_time)

    # Query to retrieve the dga hosts data from dns_query_data
    dga_hosts_query = """
                    select qname, count(*) as dga_count from dns_query_data
                    where isDGA = 1 group by qname order by dga_count desc;
                    """

    # Query to insert the dga hosts data into dga hosts table
    dga_hosts_insert_query = """
                            insert into dgaHosts(dgaHost, dgaCount)
                            VALUES(?, ?);
                            """

    # Query to insert the dns tunneling data into dns tunneling hosts table
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

    cursor.execute(dns_tunneling_query)
    dns_tunneling_data = cursor.fetchall()
    for x in dns_tunneling_data:
        cursor.execute(dns_tunneling_insert_query, x)
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
    conn.commit()


if __name__ == "__main__":
    end_time = datetime.now()
    start_time = end_time - timedelta(minutes=5)
    print(start_time, end_time)
    fetch_and_print_data(start_time, end_time)
    fetch_dns_hosts(start_time, end_time)
