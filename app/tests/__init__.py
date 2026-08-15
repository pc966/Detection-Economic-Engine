# Test suite for Detection Economics Engine

import os
import sys

# Add the project root to the Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Set test environment
os.environ['FLASK_ENV'] = 'testing'
os.environ['DEBUG'] = 'False'
os.environ['MAIL_SUPPRESS_SEND'] = 'True'
