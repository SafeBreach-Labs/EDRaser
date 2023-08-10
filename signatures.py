from collections.abc import Sequence
import sqlite3
import base64
from database import Database

XOR_KEY = 0xFF

class Signature:
    def __init__(self, sig_length, sig_charset_type, affected_edr, signature_data):
        self.sig_length = sig_length
        self.charset = sig_charset_type
        self.affected_edr = affected_edr
        self.signature_data = signature_data

    def __str__(self):
        return f"Signature:\nLength = {self.sig_length}\nCharset = {self.charset}\naffected_edr = {self.affected_edr}\nsignature_data = {self.signature_data}"

    def get_signature_as_dict(self):
        return {"Length": self.sig_length,
               "Charset": self.charset,
               "Affected_EDR": self.affected_edr,
               "data_xored_b64": _encrypt_data(self.signature_data),
               }
        
    def get_charset_type(self):
        return self.sig_charset_type
    
    def get_signature_data(self):        
        return self.signature_data

def _encrypt_data(raw_data: bytes):
    b64_data = base64.b64encode(raw_data.encode()).decode()
    data_xored_b64 = bytes([ord(c) ^ XOR_KEY for c in b64_data])
    return data_xored_b64

def detect_charset(input_string: str):
    if input_string.isalpha():
        return 'Alpha'
    elif input_string.isalnum():
        return 'Alphanumeric'
    elif all(character.isalnum() or character.isspace() for character in input_string):
        return 'SpacesAlphanumeric'
    else:
        return 'All'    
    
def create_new_signatureDB(signature_list: list, path_to_sigDB: str = "evilSignatures_new.db"):
    new_signatureDB = Database("sqlite", path_to_sigDB)
    new_signatureDB.create_table("EvilSignature", {"Length" : "int", 
                                                   "Charset": "varchar(255)",
                                                   "Affected_EDR": "varchar(255)",
                                                   "data_xored_b64": "varchar(65535)"
                                                })
    
    for signature in signature_list:
        new_signatureDB.insert("EvilSignature", signature.get_signature_as_dict())
        
def _decrypt_data(data_xored_b64: bytes):
        
        data_b64 = bytes([c ^ XOR_KEY for c in data_xored_b64]).decode()
        try:
            decoded_data = base64.b64decode(data_b64).decode('unicode_escape')
        except:
            decoded_data = base64.b64decode(data_b64).decode()
        return decoded_data

def load_malicous_signatureDB(path_to_sigDB: str = "evilSignatures.db"):
    """
    Loads the malicous DB into a list of Signature objects. 
    
    :param path_to_sigDB: The path to the signatureDB
    :return: Returns list of signatures.
    """

    signatures_list = []
    conn = sqlite3.connect(path_to_sigDB)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM EvilSignature")

    # Fetch all rows from the result set
    rows = cursor.fetchall()
    conn.close()

    for column in rows:
        current_sig = Signature(column[0], column[1], column[2], _decrypt_data(column[3]))
        signatures_list.append(current_sig)

    return signatures_list