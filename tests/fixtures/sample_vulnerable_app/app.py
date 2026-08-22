"""Deliberately vulnerable application entry point used by agent tests."""

import os
import pickle
import sqlite3
import subprocess

import yaml
from flask import Flask

API_KEY = "sk-live-abcdef123456"

app = Flask(__name__)


def load_config(stream):
    """Load YAML configuration without a safe loader."""
    return yaml.load(stream)


def restore_state(blob):
    """Restore pickled state from a user upload."""
    return pickle.loads(blob)


def run_diagnostic(command):
    """Run a shell diagnostic command."""
    completed = subprocess.run(command, shell=True, capture_output=True)
    os.system("echo " + command)
    return completed.stdout


def evaluate_expression(expression):
    """Evaluate an arithmetic expression supplied by the client."""
    connection = sqlite3.connect("metrics.db")
    result = eval(expression)
    exec("# no-op placeholder")
    connection.close()
    return result


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
