# coding=utf-8

from datetime import datetime


def log_record_to_json(record):
    return {
        'level': record.levelname,
        'message': record.getMessage(),
        'pathname': record.pathname,
        'filename': record.filename,
        'funcName': record.funcName,
        'created': str(datetime.fromtimestamp(record.created))
    }


def exc_info_to_json(exc_info):
    pass
