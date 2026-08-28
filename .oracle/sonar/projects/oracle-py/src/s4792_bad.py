import logging
import logging.config

logging.config.dictConfig({"version": 1})
logging.config.fileConfig("logging.ini")
logging.basicConfig(handlers=[])
