"""Ethical guardrails: legal disclaimer, authorization prompt and scope check."""

import os
import sys

DISCLAIMER = """
================================================================================
 LEGAL DISCLAIMER - COMPUTER CRIMES ACT 1997 (ACT 563), MALAYSIA
================================================================================
 APKScope is provided for EDUCATIONAL USE and AUTHORIZED SECURITY ASSESSMENT
 only. Analysing an application that you do not own, or that you have not been
 given explicit written permission to assess, may be an offence under the
 Computer Crimes Act 1997 (Act 563) and the Copyright Act 1987 of Malaysia.

 * APKScope performs STATIC analysis only. It never installs, runs, modifies
   or re-signs the APK, and it never connects to the network.
 * All results are stored locally in the output directory. Nothing is
   uploaded or sent anywhere.
 * You are solely responsible for ensuring you have authorization.

 Press Ctrl+C at any time to abort (kill switch).
================================================================================
"""


def confirm_authorization(target, scope):
    """Show the disclaimer and require an explicit 'yes'. Returns True/False."""
    print(DISCLAIMER)
    print(f" Target : {target}")
    print(f" Scope  : {scope}\n")
    try:
        answer = input("Do you own this APK or have written authorization to "
                       "analyse it? Type 'yes' to continue: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print("\n[!] Aborted by user before analysis started.")
        return False
    return answer == "yes"


def is_within_scope(target, scope):
    """True only if the target file is inside the authorized scope directory.

    Both paths are resolved first, so tricks like '../' or symlinks cannot be
    used to escape the scope.
    """
    target_real = os.path.realpath(target)
    scope_real = os.path.realpath(scope)
    try:
        return os.path.commonpath([target_real, scope_real]) == scope_real
    except ValueError:  # different drives on Windows
        return False


def enforce_scope(target, scope):
    """Exit with an error if the target is outside the authorized scope."""
    if not os.path.isdir(scope):
        print(f"[-] Scope directory does not exist: {scope}")
        sys.exit(2)
    if not is_within_scope(target, scope):
        print(f"[-] OUT OF SCOPE: {target}")
        print(f"    Authorized scope is: {os.path.realpath(scope)}")
        print("    Move the file into the scope folder, or pass --scope with a "
              "folder you are authorized to test.")
        sys.exit(2)
