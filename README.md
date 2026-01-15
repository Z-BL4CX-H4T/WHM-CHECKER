# WHM-CHECKER

**Tool Capabilities:**

Performs automated WHM login credential verification using the official WHM authentication endpoint.

Supports bulk account checking with threaded execution to maintain application responsiveness.

Accurately classifies authentication results based on server responses (VALID, INVALID, 2FA, BLOCKED, ERROR).

Handles network-related exceptions such as timeouts, HTTP errors, and access restrictions.

Provides real-time progress tracking and statistical reporting through a graphical user interface.

Supports data import and export for efficient result management.

Built as a stable desktop GUI application for structured and controlled usage.

**instalation:**
sudo python3 -m venv venv
source venv/bin/activate
