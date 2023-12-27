#!/usr/bin/env python3
import os
import sys
import dbasemgmt
from datetime import datetime

script_path = os.path.dirname(os.path.abspath(__file__))
db = r"networkdata.db"
db_path = os.path.join(script_path, db)
print(db_path)
conn = dbasemgmt.create_connection(db_path)

table_name = "dns_query_data"

sql_command = """
                    CREATE TABLE IF NOT EXISTS {} (
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
                        isDGA integer,
                        tiVerdict text,
                        status integer default 0
                    );
                """.format(table_name)

dbasemgmt.create_table(conn, sql_command)                        

count = 1
for row in sys.argv:
    if "frame.interface_name".casefold() in row.casefold() or "capturing on".casefold() in row.casefold():
        pass
    else:
        fields = [
            "interface",
            "time",
            "dst",
            "dport",
            "src",
            "sport",
            "rcode",
            "qname",
            "qlen",
            "labelcount",
            "qtype",
            "rname",
            "rtype",
            "ttl",
            "rlen",
            "size",
            "dnsResponse",
            ]
        entry = row.replace("\n", "").split(",")
        entry.insert(1, datetime.strftime(datetime.now(), format="%Y-%m-%d %H:%M:%S"))
        try:
            entry_row = dbasemgmt.create_entry(conn, table_name, fields, entry)
            print(entry_row, "=======================")
        except Exception as E:
            print(E)
            pass
            #tb = sys.exception().__traceback__
            #raise OtherException(...).with_traceback(tb)
        #dbasemgmt.select_all(conn, table_name)
