#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
python3 -m venv $DIR/.env && source $DIR/.env/bin/activate && pip install --upgrade pip && pip install wheel && pip install -r $DIR/requirements-linux.txt && deactivate
