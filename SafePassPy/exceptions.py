"""
This code or file is part of 'SafePassPy' project
copyright (c) 2023, Aymen Brahim Djelloul, All rights reserved.
use of this source code is governed by MIT License that can be found on the project folder.


@author : Aymen Brahim Djelloul
date : 14.08.2023
version : 0.0.1
License : MIT

"""

# IMPORTS
import sys


class PasswordInvalid(BaseException):

    def __init__(self, pwd: str):
        self.pwd = pwd

    def __str__(self):
        return f"The password you have been insert '{self.pwd}' is not valid\n" \
               f"the password must be ASCII characters and not separated with space"


class CodePINLengthTooShort(BaseException):

    def __str__(self):
        return f"The PIN length is too short. PIN code can't be less than 3 digits"


if __name__ == "__main__":
    sys.exit()