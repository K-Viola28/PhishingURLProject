#!/bin/bash

cd /workspaces/PhishingURLProject

if ! pgrep -f "manage.py runserver 0.0.0.0:8000" > /dev/null; then
    nohup .venv/bin/python manage.py runserver 0.0.0.0:8000 \
        > /tmp/django-server.log 2>&1 < /dev/null &
fi