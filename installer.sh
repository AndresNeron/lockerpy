#!/bin/bash

virtualenv cipherEnv --python=3
source cipherEnv/bin/activate
pip install -r requirements.txt
