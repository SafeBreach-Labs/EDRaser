import sys
import logging
 
class EDRaserLogger(logging.Formatter):
    def __init__(self) -> None:
         super().__init__("%(bullet)s %(message)s", None)
 
    def format(self, record):
        if record.levelno == logging.INFO:
            record.bullet = '[+]'
        elif record.levelno == logging.DEBUG:
            record.bullet = '[DEBUG]:'
        elif record.levelno == logging.ERROR:
            record.bullet = '[!]'
        else:
            record.bullet = '[~]'
     
        return logging.Formatter.format(self, record)
     
 
def init_logger():
     handler = logging.StreamHandler(sys.stdout)
     handler.setFormatter(EDRaserLogger())
     logging.getLogger().addHandler(handler)
     logging.getLogger().setLevel(logging.INFO)
     