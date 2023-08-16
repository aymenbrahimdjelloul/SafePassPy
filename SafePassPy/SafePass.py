"""
This code or file is part of 'SafePassPy' project
copyright (c) 2023, Aymen Brahim Djelloul, All rights reserved.
use of this source code is governed by MIT License that can be found on the project folder.


@author : Aymen Brahim Djelloul
date : 14.08.2023
version : 0.0.1
License : MIT


    // SafePassPy is a light-weight python library used for increase your password code unpredictability
     and strength by using multiple measures and technics

    // What SafePassPy can do ?
        - calculate password strength percentage
        - calculate time complexity of crack your password using brute force attack
        - check your Password breach
        - Generating strong and customize password
        - Password salting

    // sources :
    - https://support.microsoft.com/en-us/windows/create-and-use-strong-passwords-c5cebb49-8c53-4f5e-2bc4-fe357ca048eb
    - https://support.google.com/accounts/answer/32040?hl=en\
    - https://www.proxynova.com/tools/brute-force-calculator/

"""

# IMPORT
import sys
import os
import gzip
import string
import linecache
import secrets
from hashlib import sha256
from time import perf_counter
from threading import Thread
from math import ceil
from exceptions import PasswordInvalid, CodePINLengthTooShort

# Declare variables
__AUTHOR__ = "Aymen Brahim Djelloul"
__VERSION__ = "1.0"
__CURRENT_PATH__ = os.getcwd()


def _collect_database(chunk_prefix: str = "hashes\\hashes_db", output_file: str = "hashes\\hashes_db.gz"):
    """ This function will collect the chunks of the database and return the original database archive"""

    # Define chunk count variable
    chunk_count = 0

    with open(output_file, 'wb') as f:

        while True:
            chunk_file = f"{chunk_prefix}{chunk_count}.bin"
            try:
                with open(chunk_file, 'rb') as chunk:
                    f.write(chunk.read())

            except FileNotFoundError:
                break

            chunk_count += 1


def _decompress_hashes_database(input_file: str = f"{__CURRENT_PATH__}\\hashes\\hashes_db.gz",
                                 output_file: str = f"{__CURRENT_PATH__}\\hashes\\hashes.txtdb"):
    """ This function will decompress the .gz file that's contain hashes database"""

    with gzip.open(input_file, 'rb') as f_in:
        with open(output_file, 'wb') as f_out:
            f_out.writelines(f_in)


def password_generator(length: int = 10, allow_digits: bool = True, allow_upper: bool = True,
                       allow_symbols: bool = False) -> str:
    """ This function will generate strong password using custom parameters"""

    # Define variables
    generated_pass: str = ""
    chars: str = string.ascii_lowercase
    if allow_digits:
        chars = chars + string.digits
    if allow_upper:
        chars = chars + string.ascii_uppercase
    if allow_symbols:
        chars = chars + "!@#$%^&*_-+='\"\|?><~"

    # Generate random password
    for _ in range(length):
        # Choose random character using secrets module
        generated_pass = generated_pass + secrets.choice(chars)

    # Clear memory
    del length, allow_digits, allow_upper, allow_symbols, chars, _

    # Return generated password
    return generated_pass


def PIN_generator(length: int = 6):
    """ This function will generate a random and secure PIN code"""

    # Check the length parameter
    if length < 4:
        raise CodePINLengthTooShort()

    # Define generated variable
    pin_code: str = ""

    # Generate pin code
    for x in range(length):
        pin_code = pin_code + secrets.choice(('0', '1', '2', '3', '4',
                                              '5', '6', '7', '8', '9'))

    # Clear memory
    del x, length

    # Return the code pin result
    return pin_code


class SafePass:

    __database_update: str

    def __init__(self, password: str):

        # Check the given password if ASCII
        if not self.__is_valid(password):
            raise PasswordInvalid(password)

        # hash the given password using SHA-256
        self.__password = password
        self.__hashed_password = self.__password_hashing(password)

        # Collect database files
        _collect_database()
        # Decompress the database archive
        _decompress_hashes_database()

        # Load hashes database
        self.__hashes = self.__load_hashes_db("hashes.txtdb")

        # Delete the decompressed file
        os.system(f"del {__CURRENT_PATH__}\\hashes\\hashes.txtdb")
        # Delete the .gz archive file
        os.system(f"del {__CURRENT_PATH__}\\hashes\\hashes_db.gz")

    @property
    def get_password_strength_percent(self) -> int:
        """ This method will analyze and calculate the password strength percentage"""

        # First get Define variables to get password specifications
        password_specs = {
            "password_length": len(self.__password) * 2,
            "uppercase_count": self.__uppercase_count(),
            "lowercase_count": self.__lowercase_count(),
            "digits_count": self.__digits_count(),
            "symbols_count": self.__symbols_count(),
            "is_blank_spaced": self.__is_blank_spaced(),
        }

        # Declare variable
        max_score_factor: int = 120
        password_score: int = 0

        # Calculate password score
        for k, v in password_specs.items():
            # Check if it's a question spec type
            if k.startswith('is'):
                if v:
                    password_score += 2
                    continue

            password_score += v

        # Clear memory
        del password_specs, k, v

        # Return strength percentage
        return ceil(password_score * 100.0 / max_score_factor) if password_score < max_score_factor else 100

    def estimate_brute_force_time(self, friendly_format: bool = True, attempts_per_seconds: int = 10**6) -> int | str:
        """ This method will calculate the time will last to crack the given password in seconds"""

        # Define variables
        estimated_time_seconds: int
        password_length = len(self.__password)
        chars_set_size: int = 0

        # Get characters set
        if self.__digits_count() > 0:
            chars_set_size += 10     # add 10 for present digits
        if self.__uppercase_count() > 0:
            chars_set_size += 26     # add 26 for present Uppercase
        if self.__lowercase_count() > 0:
            chars_set_size += 26     # add 26 for present lowercase
        if self.__symbols_count() > 0:
            chars_set_size += 18     # add 18 for present symbols

        # Get the possible combinations
        possible_combinations: int = chars_set_size ** password_length
        estimated_time_seconds = int(possible_combinations / attempts_per_seconds)

        # Clear memory
        del password_length, chars_set_size, possible_combinations
        # Return the estimated time in seconds or in friendly time format
        return self.__adjust_estimated_time(estimated_time_seconds) if friendly_format else estimated_time_seconds

    @property
    def check_password_breaches(self) -> dict:
        """ This method will check the given password through a large breached password database and check if exists"""

        # Define start time variable
        start_time: float = perf_counter()

        # Define empty dict as a result variable
        result: dict = {
            "password": self.__password,
            "is_password_breached": False,
            "check_time": None,
            "passwords_check_through": len(self.__hashes),
            "db_latest_update": self.__database_update,
            "hash": self.__hashed_password
        }

        # Check if there is match in hashes database
        if self.__hashed_password in self.__hashes:
            result["is_password_breached"] = True

        # Set the checking time
        result["check_time"] = round(perf_counter() - start_time, 4)

        # Clear memory
        del start_time

        # Return checking result
        return result

    def password_salting(self, max_length: int = 16,
                         salting_chars: tuple = tuple(char for char in string.ascii_uppercase + string.ascii_lowercase +
                                                      string.digits)) -> str:
        """ This method will salt the given password to make it more strength"""

        password_length: int = len(self.__password)
        # Check password length
        if password_length >= max_length:
            return self.__password

        # Generate the password salt
        salt: str = ""
        for x in range(max_length - password_length):
            salt = salt + secrets.choice(salting_chars)

        # Return salted password
        return f"{self.__password}{salt}"

    def update_password(self, password: str):
        """ This method will update the given password"""
        self.__password = password
        self.__hashed_password = self.__password_hashing(password)

    @staticmethod
    def __is_valid(pwd: str) -> bool:
        """ This method will check the password validity """

        # Check if it's ascii
        if not pwd.isascii():
            return False

        # Check if it's one word
        if len(pwd.split()) != 1:
            return False

        # Return that the password is valid
        return True

    @staticmethod
    def __password_hashing(pwd: str) -> str:
        """ This method will hash the given password using SHA-256 algorithm"""
        return sha256(pwd.encode("UTF-8")).hexdigest()

    def __uppercase_count(self) -> int:
        """ This method will check if the given password contain Upper cases"""

        # Define uppercase count variable
        uppercase_count: int = 0

        for char in self.__password:

            if char.isupper():
                uppercase_count += 2

        return uppercase_count

    def __lowercase_count(self) -> int:
        """ This method will check if the given password contain lower cases"""

        # Define uppercase count variable
        lowercase_count: int = 0

        for char in self.__password:

            if char.islower():
                lowercase_count += 1

        return lowercase_count

    def __digits_count(self) -> int:
        """ This method will check if the given password contain digits"""

        # Define count variable
        count: int = 0

        for char in self.__password:

            if char.isdigit():
                count += 1

        return count

    def __symbols_count(self) -> int:
        """ This method will check if the given password contain symbols"""

        # Define Symbols tuple
        count: int = 0
        symbols = (".", ",", "?", "!", "@", "#", "$", "%", "^",
                   "&", "*", "(", ")", "_", "-", "+", "=", "|")

        for char in self.__password:

            if char in symbols:
                count += 1

        # Clear memory
        del symbols

        return count

    def __is_blank_spaced(self) -> bool:
        """ This method will check if the given password starts or ends with blank space"""
        return True if self.__password.startswith(" ") or self.__password.endswith(" ") else False

    @staticmethod
    def __adjust_estimated_time(time_seconds: int) -> str:
        """ This method will return the adjusted and human-readable format """

        if time_seconds < 1:
            return "instantly"
        elif time_seconds < 60:
            return f"{time_seconds:.0f} minutes"
        elif time_seconds < 3600:
            return f"{time_seconds / 60:.0f} hour"
        elif time_seconds < 86400:
            return f"{time_seconds / 3600:.0f} days"
        elif time_seconds < 2900000:
            return f"{time_seconds / 2629746:.0f} months"
        else:
            return f"{time_seconds / 31536000:.0f} years"

    def __load_hashes_db(self, filename: str) -> list:
        """ This method will load the passwords database data and return it"""

        # Define database empty list
        hashes_database: list = []
        database_file: str = f"{__CURRENT_PATH__}\\hashes\\{filename}"

        # Read the hashes database file
        with open(database_file, 'r', encoding="UTF-8") as file:

            # Set the latest update date using linecache module
            self.__database_update = linecache.getline(database_file, 6).split()[-1]

            # Iter each line of the txtdb file
            for line in file:

                # Clean the line
                _hash = line.strip()

                # Remove comments
                if _hash.startswith("#"):
                    continue

                # Remove empty lines
                if _hash == "":
                    continue

                # Append hash into the hashes db variable
                hashes_database.append(_hash)

        # The file will be automatically closed when the 'with' block is exited

        # Clear memory
        del filename, line, file, _hash

        # Return the hashes in list
        return hashes_database


if __name__ == "__main__":
    sys.exit()
