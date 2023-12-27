#!/usr/bin/env python3
import sqlite3
from sqlite3 import Error

def create_connection(db_file):
    """ Create a database connection to a SQLITE3 database """
    conn = sqlite3.connect(db_file, check_same_thread=False)
    conn.execute('pragma journal_mode=wal')
    print(sqlite3.version)
    return conn

def create_table(conn, create_table_sql):
    """ Create a table from the create_table_sql statement
        :param conn: Connection object
        :param create_table_sql: a CREATE TABLE statement
        :return:
    """
    try:
        cur = conn.cursor()
        cur.execute(create_table_sql)
    except Error as e:
        print(e)

def create_entry(conn, table_name, fields, entry):
    """ Create a new row into the identified table
        :param conn: Connection object
        :param table_name: Table name for inserts
        :param fields: The fields to add to the row
        :param entry: Values to enter
        :return: Last row of the table
    """
    column_names = ", ".join(fields)
    values = ", ".join(["?"]*len(fields))
    sql = "INSERT INTO {}({}) VALUES({}) ".format(table_name, column_names, values)
    new_entry = [entry[i] for i in range(len(entry)-4)] + [''.join(entry[-4:])]
    print(new_entry, "000000")
    cur = conn.cursor()
    #print(entry, "========", len(entry))
    cur.execute(sql, new_entry)
    conn.commit()
    return cur.lastrowid

def select_all(conn, table_name):
    """ Query all rows in the table
        :param conn: The connection object
        :param table_name: The table name
        :return:
    """
    cur = conn.cursor()
    cur.execute("SELECT * FROM {}".format(table_name))
    rows = cur.fetchall()
    for row in rows:
        print(row)
