from __future__ import absolute_import, unicode_literals

from celery import shared_task


@shared_task()
def extract_data_from_elastic():
    from greedybear.crons import extract_data_from_elastic

    extract_data_from_elastic()
