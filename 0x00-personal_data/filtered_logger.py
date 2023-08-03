#!/usr/bin/env python3
"""A script to redact sensitive information.
"""
import os
import re
import logging
import mysql.connector
from typing import List


# Dictionary to hold the regex patterns
patterns = {
    'extract': lambda x, y: r'(?P<field>{})=[^{}]*'.format('|'.join(x), y),
    'replace': lambda x: r'\g<field>={}'.format(x),
}
PII_FIELDS = ("name", "email", "phone", "ssn", "password")
}

def filter_datum(
        fields: List[str], redaction: str, message: str, separator: str,
        ) -> str:
    """Redacts sensitive data from the log message.
    """
    extract, replace = (patterns["extract"], patterns["replace"])
    return re.sub(extract(fields, separator), replace(redaction), message)


def get_logger() -> logging.Logger:
    """Creates a logger to log user data to console.
    """
    logger = logging.getLogger("user_data_logger")
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(SENSITIVE_FIELDS))
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(stream_handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """Creates a connection to the database.
    """
    db_host = os.getenv("DB_HOST", "localhost")
    db_name = os.getenv("DB_NAME", "")
    db_user = os.getenv("DB_USERNAME", "root")
    db_pwd = os.getenv("DB_PASSWORD", "")
    connection = mysql.connector.connect(
        host=db_host,
        port=3306,
        user=db_user,
        password=db_pwd,
        database=db_name,
    )
    return connection


def main():
    """Fetches user records from the database and logs them to console.
    """
fields = "name,email,phone,ssn,password,ip,last_login,user_agent"
    columns = fields.split(',')
    query = "SELECT {} FROM users;".format(fields)
    info_logger = get_logger()
    connection = get_db()
    with connection.cursor() as cursor:
        cursor.execute(query)
        rows = cursor.fetchall()
        for row in rows:
            record = map(
                lambda x: '{}={}'.format(x[0], x[1]),
                zip(columns, row),
            )
            msg = '{};'.format('; '.join(list(record)))
            args = ("user_data", logging.INFO, None, None, msg, None, None)
            log_record = logging.LogRecord(*args)
            info_logger.handle(log_record)


class RedactingFormatter(logging.Formatter):
    """Custom log formatter to redact sensitive fields.
    """

    REDACTION = "***"
    FORMAT = "[MY_APP] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Formats a log record.
        """
        msg = super(RedactingFormatter, self).format(record)
        redacted_msg = redact_data(self.fields, self.REDACTION, msg, self.SEPARATOR)
        return redacted_msg


if __name__ == "__main__":
    main()
