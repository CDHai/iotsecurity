#!/usr/bin/env python3
"""
WSGI entry point for IoT Security Framework
"""

import os
from app import create_app

# Create Flask application instance
app = create_app()

if __name__ == "__main__":
    # For development
    app.run(host='0.0.0.0', port=5000, debug=False)
