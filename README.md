# EDRaser

## Usage Guide

EDRaser is a powerful tool for remotely deleting access logs, Windows event logs, databases, and other files on remote machines.
It offers two modes of operation: automated and manual.

### Automated Mode

In automated mode, EDRaser scans the C class of a given address space of IPs for vulnerable systems and attacks them automatically. 
The attacks in auto mode are:

- Remote deletion of webserver logs.
- SysLog deletion (on Linux).
- Local deletion of Windows Application event logs.
- Remote deletion of Windows event logs.
- VMX + VMDK deletion

To use EDRaser in automated mode, follow these steps:

```
python edraser.py --auto
```

### Manual Mode

In manual mode, you can select specific attacks to launch against a targeted system, giving you greater control.
Note that some attacks, such as VMX deletion, are for local machine only.

To use EDRaser in manual mode, you can use the following syntax:

```
python edraser.py --ip <ip_addr> --attack <attack_name> [--sigfile <signature file>]
```

Arguments:
- `--ip`: scan IP addresses in the specified range and attack vulnerable systems (default: localhost).
- `--sigfile`: use the specified encrypted signature DB (default: signatures.db).
- `--attack`: attack to be executed. The following attacks are available: ['vmx', 'vmdk', 'windows_security_event_log_remote',
                   'windows_application_event_log_local', 'syslog', 
                   'access_logs', 'remote_db', 'local_db', 'remote_db_webserver']

Optional arguments:
- `port` : port of remote machine
- `db_username`: the username of the remote DB.
- `db_password`: the password of the remote DB.
- `db_type`: type of the DB, EDRaser supports `mysql`, `sqlite`. (# Note that for sqlite, no username\password is needed)
- `db_name`: the name of remote DB to be connected to
- `table_name`: the name of remote table to be connected to
- `rpc_tools`: path to the VMware rpc_tools


Example:

```
python edraser.py --attack windows_event_log --ip 192.168.1.133 

python EDRaser.py -attack remote_db -db_type mysql -db_username test_user -db_password test_password -ip 192.168.1.10
```


### DB web server
You can bring up a web interface for inserting and viewing a remote DB.
it can be done by the following command:
EDRaser.py -attack remote_db_webserver -db_type mysql -db_username test_user -db_password test_password -ip 192.168.1.10

This will bring up a web server on the localhost:8080 address, it will allow you to view & insert data to a remote given DB.
This feature is designed to give an example of a "Real world" scenario where you have a website that you enter data into it and it keeps in inside a remote DB, You can use this feature to manually insert data into a remote DB.

### Available Attacks

In manual mode, EDRaser displays a list of available attacks. Here's a brief description of each attack:

1. Windows Event Logs: Deletes Windows event logs from the remote targeted system.
2. VMware Exploit: Deletes the VMX and VMDK files on the host machine. This attack works only on the localhost machine in a VMware environment by modifying the VMX file or directly writing to the VMDK files.
3. Web Server Logs: Deletes access logs from web servers running on the targeted system by sending a malicious string user-agent that is written to the access-log files.
4. SysLogs: Deletes syslog from Linux machines running Kaspersky EDR without being .
5. Database: Deletes all data from the remotely targeted database.

