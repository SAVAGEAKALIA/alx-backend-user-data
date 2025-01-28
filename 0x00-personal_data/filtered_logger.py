#!/usr/bin/env python3
"""
This script demonstrates the use of regex for replacing
occurrences of sensitive field values (PII)
in log records.
It connects to a MySQL database,
retrieves data from a users table, and logs the
information with sensitive fields redacted.
"""

import os
import logging
from typing import List
import mysql.connector
import re

PII_FIELDS = ("name", "email", "password", "ssn", "phone")  # Fields to redact


class RedactingFormatter(logging.Formatter):
    """Formatter class to redact sensitive fields in log messages."""

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s " \
             "%(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = "; "

    def __init__(self, fields: List[str]):
        """
        Initializes the formatter with fields to redact.

        Args:
            fields (List[str]): List of field names to redact.
        """
        super().__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Filters and formats log messages by redacting sensitive fields.

        Args:
            record (logging.LogRecord): Log record to format.

        Returns:
            str: The formatted log message with sensitive fields redacted.
        """
        return \
            filter_datum(self.fields,
                         self.REDACTION, super().format(record),
                         self.SEPARATOR)


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """
    Replaces occurrences of sensitive
    field values in a log message with a redaction string.

    Args:
        fields (List[str]): List of field names to redact.
        redaction (str): Replacement string for sensitive values.
        message (str): Log message to filter.
        separator (str): Field separator in the log message.

    Returns:
        str: The filtered log message with sensitive fields redacted.
    """
    # Create a single regex pattern to match and replace sensitive fields
    for field in fields:
        message = re.sub(f'{field}=(.*?){separator}',
                         f'{field}={redaction}{separator}',
                         message)
    return message


def get_logger() -> logging.Logger:
    """
    Configures and returns a Logger instance for handling log messages.

    Returns:
        logging.Logger: Configured Logger object.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    formatter = RedactingFormatter(PII_FIELDS)
    stream_handler.setFormatter(formatter)

    logger.addHandler(stream_handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Establishes and returns a connection to the MySQL database.

    Returns:
        mysql.connector.connection.MySQLConnection:
        Database connection object.
    """
    return mysql.connector.connect(
        user=os.getenv("PERSONAL_DATA_DB_USERNAME", "root"),
        password=os.getenv("PERSONAL_DATA_DB_PASSWORD", ""),
        host=os.getenv("PERSONAL_DATA_DB_HOST", "localhost"),
        database=os.getenv("PERSONAL_DATA_DB_NAME")
    )


def main() -> None:
    """
    Main function to:
    1. Connect to the database.
    2. Retrieve all rows from the users table.
    3. Log the retrieved rows with sensitive fields redacted.
    """
    db = get_db()
    cursor = db.cursor()

    try:
        cursor.execute("SELECT * FROM users;")
        headers = [desc[0] for desc in cursor.description]
        logger = get_logger()

        for row in cursor:
            message = "".join(
                f"{header}={value}{RedactingFormatter.SEPARATOR}"
                for header, value in zip(headers, row)
            )
            logger.info(message)

    finally:
        cursor.close()
        db.close()


if __name__ == "__main__":
    main()
