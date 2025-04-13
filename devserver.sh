#!/bin/sh
source .venv/bin/activate || source .venv/Scripts/activate
pip install -r requirements.txt
python -m flask --app main run --debug