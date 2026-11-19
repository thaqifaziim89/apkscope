"""Kill switch: lets the user abort cleanly with Ctrl+C.

First Ctrl+C  -> sets an abort flag. The scan stops at the next check and
                 the partial results are saved and labelled "ABORTED".
Second Ctrl+C -> exits immediately with no further work.
"""

import signal
import sys

EXIT_ABORTED = 130  # conventional exit code for "terminated by Ctrl+C"


class KillSwitch:
    def __init__(self):
        self.triggered = False

    def _handler(self, signum, frame):
        if self.triggered:
            print("\n[!] Second Ctrl+C received. Exiting immediately.")
            sys.exit(EXIT_ABORTED)
        self.triggered = True
        print("\n[!] Kill switch activated. Stopping after the current check "
              "(press Ctrl+C again to exit now)...")

    def arm(self):
        signal.signal(signal.SIGINT, self._handler)

    def check(self):
        """Raise AbortScan if the user pressed Ctrl+C."""
        if self.triggered:
            raise AbortScan()


class AbortScan(Exception):
    """Raised inside the scan loop when the kill switch is triggered."""
