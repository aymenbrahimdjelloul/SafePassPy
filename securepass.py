"""
This code or file is part of 'SecurePass' project
copyright (c) 2023-2025, Aymen Brahim Djelloul, All rights reserved.
use of this source code is governed by MIT License that can be found on the project folder.


@author : Aymen Brahim Djelloul
date : 14.08.2023 -> 19.05.2025 (Updated version)
version : 1.1
License : MIT


    // SecurePass is a light-weight python module used for increase your password code unpredictability
     and strength by using multiple measures and technics

    // What SecurePass can do ?
        - calculate password strength score
        - calculate time complexity of crack your password using brute force attack
        - check your Password breach
        - Generating strong and customize password
        - Password salting

    // sources :
    - https://support.microsoft.com/en-us/windows/create-and-use-strong-passwords-c5cebb49-8c53-4f5e-2bc4-fe357ca048eb
    - https://support.google.com/accounts/answer/32040?hl=en
    - https://www.proxynova.com/tools/brute-force-calculator
    - https://github.com/berzerk0/Probable-Wordlists


"""
# IMPORTS
import sys
import re
import os
import socket
import string
import secrets
import colorama
import requests
from math import ceil
from collections import Counter
from time import perf_counter, sleep
from typing import Dict, Optional, List, Tuple
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter


# Define Coloring sets
try:

    import colorama
    from colorama import Fore, Style

    class __Colors__:
        """ Define colors variable using colorama """

        CYAN = Fore.CYAN
        GREEN = Fore.GREEN
        YELLOW = Fore.YELLOW
        RED = Fore.RED
        WHITE = Fore.WHITE
        BLUE = Fore.BLUE
        MAGNETA = Fore.MAGENTA
        BRIGHT = Style.BRIGHT
        RESET_ALL = Style.RESET_ALL

except ImportError:

    # Set colorama as None
    colorama: bool = None

    # Define ANSI Coloros
    class __Colors__:
        """ Define ANSI colors code as exception in case not 'colorama' presence"""

        CYAN: str = '\033[96m'
        GREEN: str = '\033[92m'
        YELLOW: str = '\033[93m'
        RED: str = '\033[91m'
        WHITE: str = '\033[37m'
        BLUE: str = '\033[94m'
        MAGNETA: str = '\033[95m'
        BRIGHT: str = '\033[1m'
        RESET_ALL: str = '\033[0m'


class __Core__:
    # DEFINE ALL SecurePass constant in Core parent class
    # DEFINE GLOBAL VARIABLES
    # AUTHOR: str = "Aymen Brahim Djelloul"
    VERSION: float = 1.1
    DATE: str = "19.05.2025"

    # Character sets
    _LOWERCASE: str = string.ascii_lowercase
    _UPPERCASE: str = string.ascii_uppercase
    _DIGITS: str = string.digits
    _SPECIAL: str = "!@#$%^&*()-_=+[]{}|;:,.<>?/"

    SEQUENCES: dict = {
        'alphabetic': 'abcdefghijklmnopqrstuvwxyz',
        'numeric': '0123456789',
        'qwerty': 'qwertyuiopasdfghjklzxcvbnm'
    }


class PasswordGenerator(__Core__):
    """
    PasswordGenerator is a simple integrated tool for password generating

    Features:
    - Configurable password length and character sets
    - Custom exclusion patterns
    - Memorable password generation
    """

    # Default word lists for memorable passwords
    DEFAULT_ADJECTIVES: tuple[str] = (
        "happy", "brave", "calm", "swift", "bright", "wise", "keen",
        "bold", "fair", "kind", "smart", "proud", "grand", "fresh"
    )

    DEFAULT_NOUNS: tuple[str] = (
        "tiger", "river", "cloud", "ocean", "eagle", "dream", "planet",
        "forest", "castle", "dragon", "sunset", "mountain", "garden", "thunder"
    )

    def __init__(self) -> None:
        # Default configuration
        # self.config = {
        #     "length": 16,
        #     "use_lowercase": True,
        #     "use_uppercase": True,
        #     "use_digits": True,
        #     "use_special": True,
        #     "min_lowercase": 1,
        #     "min_uppercase": 1,
        #     "min_digits": 1,
        #     "min_special": 1,
        #     "avoid_similar": False,  # Avoid similar characters like 'l', '1', 'I', '0', 'O'
        #     "exclude_chars": "",  # Characters to exclude
        #     "exclude_patterns": [],  # Regular expressions for patterns to avoid
        # }

        self.config: dict = {
            "length": 16,
            "use_lowercase": True,
            "use_uppercase": True,
            "use_digits": True,
            "use_special": True,
            "min_lowercase": 1,
            "min_uppercase": 1,
            "min_digits": 1,
            "min_special": 1,
            "avoid_similar": False,  # Avoid similar characters like 'l', '1', 'I', '0', 'O'
            "exclude_chars": "",  # Characters to exclude
            "exclude_patterns": [],  # Regular expressions for patterns to avoid
            "memorable": {
                "adjectives": self.DEFAULT_ADJECTIVES,
                "nouns": self.DEFAULT_NOUNS,
                "num_digits": 2,
                "num_special": 1
            }}

        # Similar looking characters
        self.similar_chars: str = "il1IoO0"

    def configure(self, **kwargs) -> None:
        """Update configuration with provided parameters."""
        for key, value in kwargs.items():
            if key in self.config:
                self.config[key] = value
            else:
                raise ValueError(f"Unknown configuration option: {key}")

        # Validate configuration
        self._validate_config()

    def _validate_config(self) -> None:
        """Validate the current configuration."""
        # Check if length is enough to satisfy minimum requirements
        min_chars: tuple = (
                (self.config["min_lowercase"] if self.config["use_lowercase"] else 0) +
                (self.config["min_uppercase"] if self.config["use_uppercase"] else 0) +
                (self.config["min_digits"] if self.config["use_digits"] else 0) +
                (self.config["min_special"] if self.config["use_special"] else 0)
        )

        if min_chars > self.config["length"]:
            raise ValueError(
                f"Password length ({self.config['length']}) is insufficient to meet "
                f"minimum character requirements ({min_chars})"
            )

        # Check if any character set is selected
        if not any([
            self.config["use_lowercase"],
            self.config["use_uppercase"],
            self.config["use_digits"],
            self.config["use_special"]
        ]):
            raise ValueError("At least one character set must be enabled")

    def _get_allowed_chars(self) -> str:
        """Get allowed characters based on current configuration."""
        allowed: str = ""

        if self.config["use_lowercase"]:
            allowed += self._LOWERCASE
        if self.config["use_uppercase"]:
            allowed += self._UPPERCASE
        if self.config["use_digits"]:
            allowed += self._DIGITS
        if self.config["use_special"]:
            allowed += self._SPECIAL

        # Remove excluded characters
        for char in self.config["exclude_chars"]:
            allowed = allowed.replace(char, "")

        # Remove similar looking characters if enabled
        if self.config["avoid_similar"]:
            for char in self.similar_chars:
                allowed = allowed.replace(char, "")

        return allowed

    def _meets_requirements(self, password: str) -> bool:
        """Check if the password meets all specified requirements."""

        # Count character types
        counts: dict = {
            "lowercase": sum(1 for c in password if c in self._LOWERCASE),
            "uppercase": sum(1 for c in password if c in self._UPPERCASE),
            "digits": sum(1 for c in password if c in self._DIGITS),
            "special": sum(1 for c in password if c in self._SPECIAL),
        }

        # Check minimum requirements
        if self.config["use_lowercase"] and counts["lowercase"] < self.config["min_lowercase"]:
            return False
        if self.config["use_uppercase"] and counts["uppercase"] < self.config["min_uppercase"]:
            return False
        if self.config["use_digits"] and counts["digits"] < self.config["min_digits"]:
            return False
        if self.config["use_special"] and counts["special"] < self.config["min_special"]:
            return False

        # Check for excluded patterns
        for pattern in self.config["exclude_patterns"]:
            if re.search(pattern, password):
                return False

        return True

    def generate_password(self) -> str:
        """ This method will generate random password"""

        """Generate a password based on the current configuration."""
        allowed_chars: str = self._get_allowed_chars()

        if not allowed_chars:
            raise ValueError("No valid characters available with current configuration")

        # Use cryptographically secure random generator
        for _ in range(100):  # Limit attempts to avoid infinite loop
            # Generate initial password
            password = ''.join(secrets.choice(allowed_chars) for _ in range(self.config["length"]))

            # Check if it meets requirements
            if self._meets_requirements(password):
                return password

        # If we get here, we need a different approach - build character by character
        return self._generate_constrained_password()

    def generate_memorable(self) -> str:
        """Generate a memorable password using words combined with digits and special characters.

        Format: Adjective + Noun + Digits + Special (e.g., HappyTiger42!)
        """
        # Get adjective and noun from configured lists
        adjective: str = secrets.choice(self.config["memorable"]["adjectives"])
        noun: str = secrets.choice(self.config["memorable"]["nouns"])

        # Capitalize first letter of each word for readability and security
        adjective: str = adjective[0].upper() + adjective[1:]
        noun: str = noun[0].upper() + noun[1:]

        # Add random digits
        num_digits = self.config["memorable"]["num_digits"]
        digits = ''.join(secrets.choice(self._DIGITS) for _ in range(num_digits))

        # Add random special characters
        num_special: str = self.config["memorable"]["num_special"]
        special_chars: str = self._SPECIAL
        special: str = ''.join(secrets.choice(special_chars) for _ in range(num_special))

        # Combine all parts
        password: str = adjective + noun + digits + special

        return password

    @staticmethod
    def generate_pin(length: int = 4) -> str:
        """This method will generate a random and unpredictable PIN of the given length"""
        return ''.join(str(secrets.randbelow(10)) for _ in range(length))


class SecurePass(__Core__):
    """
    A class used to represent a secure password and estimate the time
     it would take to crack the password using brute-force .

    Attributes:
        password (str): The password string to be analyzed.

    Methods:
        estimate_brute_force(friendly_format: bool = True, attempts_per_seconds: int = 10**6) -> int | str:

            Estimates the time required to crack the password using brute-force techniques, either
            in raw seconds or in a human-readable format.


    Usage Example:
        # >>> secure_pass = SecurePass("MyS3cureP@ssw0rd!")
        # >>> secure_pass.estimate_brute_force()
        "approximately 5 days"
    """

    # Define constants
    __MIN_PASSWORD_LEN: int = 8
    __REQUEST_TIMEOUT: int = 5

    # Default performance-optimized headers
    __DEFAULT_HEADERS: dict = {
        'User-Agent': 'OptimizedRequester/1.0',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Cache-Control': 'max-age=3600'
    }

    # DEFINE 3 WORDLIST URL TO GET
    __SEARCH_WORDLIST: str = "https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/refs/heads/master/Real-Passwords/Top12Thousand-probable-v2.txt"
    __DEEP_SEARCH_WORDLIST: str = "https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/refs/heads/master/Real-Passwords/Top304Thousand-probable-v2.txt"

    def __init__(self, password: str | bytes, wordlist: str | None = None, deep_search: bool = False) -> None:

        # Initialize values
        self.password: str = password if isinstance(password, str) else password.decode("UTF-8")
        self._custom_wordlist: str = wordlist
        self._deep_search: bool = deep_search
        self._wordlist: set = {}
        self._is_offline: bool = False

        # Check for online connection
        if self.__is_connected():
            self._wordlist = self.__load_wordlists()

        self.breaches_count: int = len(self._wordlist)
        # self.breaches_count: int = 300000 if deep_search else 12000
        # print(self.__wordlist)

    def update(self, password: str | bytes) -> None:
        """ This method will update the password to SecurePass object"""
        self.password: str = password if isinstance(password, str) else password.decode("UTF-8")

    @property
    def password_analysis(self) -> dict:
        """ This method will return the result of all test provide in SecurePass"""
        return {"password": self.password,
                "entropy_value": self.password_entropy,
                "score": self.password_strength_score,
                "estimated_brute_force": self.estimate_brute_force(),
                "breaches_check": self.check_password_breaches,
                "feedback": self.get_feedback,
                "securepass_version": self.VERSION
                }

    @property
    def password_entropy(self) -> float:
        """Calculate password entropy in bits."""

        # Count the character set size based on the characters used
        char_sets: dict = {
            "lowercase": any(c in self._LOWERCASE for c in self.password),
            "uppercase": any(c in self._UPPERCASE for c in self.password),
            "digits": any(c in self._DIGITS for c in self.password),
            "special": any(c in self._SPECIAL for c in self.password),
        }

        charset_size = 0
        if char_sets["lowercase"]:
            charset_size += len(self._LOWERCASE)
        if char_sets["uppercase"]:
            charset_size += len(self._UPPERCASE)
        if char_sets["digits"]:
            charset_size += len(self._DIGITS)
        if char_sets["special"]:
            charset_size += len(self._SPECIAL)

        # Calculate entropy: log2(charset_size^length)
        return len(self.password) * (charset_size.bit_length() - 1)

    @property
    def password_strength_score(self) -> int:
        """ This method will analyze and calculate the password strength percentage"""

        # First get Define variables to get password specifications
        password_specs: dict = {
            "password_length": len(self.password) * 2,
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

        # Return strength percentage
        return ceil(password_score * 100.0 / max_score_factor) if password_score < max_score_factor else 100

    @property
    def check_password_breaches(self) -> bool:
        """ This method check the password if there is breaches"""
        return True if self.password in self._wordlist else False

    def estimate_brute_force(self, friendly_format: bool = True, attempts_per_seconds: int = 10 ** 6) -> int | str:
        """ This method will calculate the time it will take to crack the given password in seconds"""

        try:
            # Validate the password
            if not self.password or not isinstance(self.password, str):
                raise ValueError("Password must be a non-empty string.")

            password_length: int = len(self.password)

            if password_length == 0:
                raise ValueError("Password length cannot be zero.")

            # Validate attempts_per_seconds
            if not isinstance(attempts_per_seconds, int) or attempts_per_seconds <= 0:
                raise ValueError("Attempts per second must be a positive integer greater than zero.")

            chars_set_size: int = 0

            # Calculate the character set size based on the password's character types
            if self.__digits_count() > 0:
                chars_set_size += 10  # Digits (0-9)
            if self.__uppercase_count() > 0:
                chars_set_size += 26  # Uppercase letters (A-Z)
            if self.__lowercase_count() > 0:
                chars_set_size += 26  # Lowercase letters (a-z)
            if self.__symbols_count() > 0:
                chars_set_size += 32  # Symbols (more extensive set of special characters)

            # Avoid division by zero error
            if chars_set_size == 0:
                raise ValueError("Password contains no valid characters to brute-force.")

            # Calculate the number of possible combinations and estimated time
            possible_combinations: int = chars_set_size ** password_length
            estimated_time_seconds: int = possible_combinations // attempts_per_seconds  # Integer division

            # Return the estimated time in a human-readable format or in raw seconds
            return self.__readable_time(estimated_time_seconds) if friendly_format else estimated_time_seconds

        except (ValueError, Exception) as e:
            raise Exception(e)

    def password_salt(self, max_length: int = 16,
                      salting_chars: tuple = tuple(
                          char for char in string.ascii_letters + string.digits + string.punctuation)) -> str:
        """This method will salt the given password to make it stronger."""

        password_length: int = len(self.password)
        # Check password length
        if password_length >= max_length:
            return self.password

        # Generate the password salt
        salt: list = [secrets.choice(salting_chars) for _ in range(max_length - password_length)]

        # Return salted password
        return f"{self.password}{''.join(salt)}"

    @property
    def get_feedback(self) -> str:
        """ This method will get string feedback to the user to improve their password"""

        feedback: list = []
        password: str = self.password

        # Check length - quick and high impact
        if len(password) < 8:
            feedback.append("Password is too short. Use at least 8 characters.")
        elif len(password) < 12:
            feedback.append("at least 12 characters for security.")

        # Character variety checks - use regex for efficiency
        has_lowercase: bool = bool(re.search(r'[a-z]', password))
        has_uppercase: bool = bool(re.search(r'[A-Z]', password))
        has_digit: bool = bool(re.search(r'\d', password))
        has_special: bool = bool(re.search(r'[^a-zA-Z0-9]', password))

        # Calculate variety score
        variety_score: int = sum([has_lowercase, has_uppercase, has_digit, has_special])

        # Variety feedback
        if variety_score < 4:
            missing: list = []

            if not has_lowercase:
                missing.append("lowercase letters")

            if not has_uppercase:
                missing.append("uppercase letters")

            if not has_digit:
                missing.append("numbers")

            if not has_special:
                missing.append("special characters")

            feedback.append(f"Add {', '.join(missing)} to improve strength.")

        # Check for repetitive patterns more efficiently
        char_counts = Counter(password)
        most_common = char_counts.most_common(1)
        if most_common and most_common[0][1] > len(password) / 3:
            feedback.append(f"Character '{most_common[0][0]}' is used too frequently.")

        # Check for repeated sequences using regex
        if re.search(r'(.)\1{2,}', password):
            feedback.append("Avoid repeating characters (like 'aaa' or '111').")

        # Check for sequential patterns more efficiently
        lower_pwd: str = password.lower()

        for seq_type, seq in self.SEQUENCES.items():
            for i in range(len(seq) - 2):
                if seq[i:i + 3] in lower_pwd:
                    feedback.append(f"Avoid {seq_type} sequences (like '{seq[i:i + 3]}').")
                    break

        # if lower_pwd in self.__wordlist or any(common in lower_pwd for common in self.__wordlist):
        #     feedback.append("Your password contains common words or patterns.")

        # Check for personal info if available
        if hasattr(self, 'user_name') and self.user_name and len(self.user_name) > 2:
            if self.user_name.lower() in lower_pwd:
                feedback.append("Avoid using your name in your password.")

        # Get feedback using entropy
        entropy = self.password_entropy

        # Assign strength rating
        if entropy < 35:
            strength_msg = f"Weak (entropy ~{entropy:.1f} bits)"
        elif entropy < 60:
            strength_msg = f"Moderate (entropy ~{entropy:.1f} bits)"
        elif entropy < 80:
            strength_msg = f"Strong (entropy ~{entropy:.1f} bits)"
        else:
            strength_msg = f"Very strong (entropy ~{entropy:.1f} bits)"

        feedback.append(f"Password strength: {strength_msg}")

        # Return appropriate message
        if not feedback or (len(feedback) == 1 and "Very strong" in feedback[0]):
            return "Password is excellent! It's strong, unique, and follows best practices."

        return feedback

    @staticmethod
    def __readable_time(time_seconds: int) -> str:
        """ This method will return the adjusted and human-readable format """

        if time_seconds < 1:
            return "instantly"

        units: list[tuple] = [
            (60, "second", "seconds"),
            (60, "minute", "minutes"),
            (24, "hour", "hours"),
            (365, "day", "days"),
            (12, "month", "months"),
            (float('inf'), "year", "years"),
        ]

        for factor, singular, plural in units:
            if time_seconds < factor:
                return f"{time_seconds} {singular if time_seconds == 1 else plural}"
            time_seconds //= factor

        return f"{time_seconds} {singular if time_seconds == 1 else plural}"

    @staticmethod
    def __is_connected(timeout: int = 3) -> bool:
        """Check internet connection using socket for optimized performance."""

        try:
            # Attempt to connect to Google's public DNS server (8.8.8.8) on port 53 (DNS service)
            with socket.create_connection(("8.8.8.8", 53), timeout=timeout):
                return True
        except (socket.timeout, socket.gaierror, socket.error):
            # Handle any errors, including timeouts or network issues
            return False

    def __uppercase_count(self) -> int:
        """Count uppercase characters in the password (2 points each)."""
        return sum(2 for char in self.password if char.isupper())

    def __lowercase_count(self) -> int:
        """Count lowercase characters in the password (1 point each)."""
        return sum(1 for char in self.password if char.islower())

    def __digits_count(self) -> int:
        """Count digits in the password (1 point each)."""
        return sum(1 for char in self.password if char.isdigit())

    def __symbols_count(self) -> int:
        """Count symbol characters in the password (1 point each)."""
        symbols: set[str] = set(".,?!@#$%^&*()_-+=|")
        return sum(1 for char in self.password if char in symbols)

    def __is_blank_spaced(self) -> bool:
        """Check if password starts or ends with blank space."""
        return self.password.startswith(" ") or self.password.endswith(" ")

    def __load_wordlists(self) -> set:
        """
        Load the appropriate wordlist according to given parameters.

        Returns:
            set: A set of words loaded from the selected wordlist source.

        Raises:
            ConnectionError: If unable to connect to the wordlist URL.
            ValueError: If the custom wordlist URL is invalid or inaccessible.
            IOError: If there are issues reading the wordlist content.
        """

        try:
            # Determine which wordlist URL to use
            if self._deep_search:
                url: str = self.__DEEP_SEARCH_WORDLIST

            elif self._custom_wordlist:
                url: str = self._custom_wordlist

            else:
                url: str = self.__SEARCH_WORDLIST

            # Attempt to fetch and process the wordlist
            response: str = self.__get_request(url=url).text.split()

            # Check if the request was successful
            # if response.status_code != 200:
            #     raise ConnectionError(f"Failed to retrieve wordlist from {url}. Status code: {response.status_code}")

            # Process and return the wordlist
            # Using a set comprehension for better performance
            return set(response)

        except (ConnectionError, ValueError, Exception) as e:
            print(e)
            return {}

    def __get_request(self, url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 10) -> requests.Response:
        """
        This method is a highly optimized requests get function to get requests with performance

        Args:
            url: The URL to request
            headers: Optional headers dictionary
            timeout: Request timeout in seconds

        Returns:
            Response object
        """

        # Merge provided headers with defaults
        merged_headers: dict = self.__DEFAULT_HEADERS.copy()
        if headers:
            merged_headers.update(headers)

        # Create a session with connection pooling
        session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=3,  # Maximum number of retries
            backoff_factor=0.3,  # Backoff factor for retries
            status_forcelist=[429, 500, 502, 503, 504],  # Retry on these status codes
            allowed_methods=["GET", "HEAD", "OPTIONS"]  # Retry only for these methods
        )

        # Apply retry strategy to both HTTP and HTTPS requests
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            # pool_connections=10,  # Number of connection pools to cache
            # pool_maxsize=10  # Maximum number of connections per pool
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Make the request through the session
        response = session.get(
            url,
            headers=merged_headers,
            timeout=timeout,
            stream=True  # Use streaming mode for large responses
        )

        # Close the session to free resources
        session.close()

        return response


class CLI:
    """
    Command Line Interface for SecurePass application.

    This class handles all terminal-based user interactions, including displaying
    password security analysis results, processing user input, and providing
    a colorful, user-friendly interface for the SecurePass tool.

    The CLI class provides methods to format and display security check results
    with appropriate colors and layouts based on severity levels. It handles
    different output formats for various data types and provides visual cues
    to help users quickly understand security information.
    """

    # IMPORTS
    import shutil

    # Define global constants
    APP_CAPTION: str = f"SecurePass - v{__Core__.VERSION}"
    TERMINAL_WIDTH: int = shutil.get_terminal_size(fallback=(80, 20)).columns
    WAIT_TIME: int = 1
    CURRENT_PLATFORM: str = sys.platform

    def __init__(self) -> None:

        # Check if colorama is present
        if colorama:
            colorama.init(autoreset=True)

        # Set title
        self._set_terminal_title()

        # Create SecurePass object
        self.securepass = SecurePass("", deep_search=True)

    def _clear_screen(self) -> None:
        """ This method will clear screen"""
        os.system("cls" if self.CURRENT_PLATFORM == "win32" else "clear")

    def _set_terminal_title(self) -> None:
        """ This method will set a terminal title """
        os.system(F"title {self.APP_CAPTION}") if self.CURRENT_PLATFORM == "win32"\
            else sys.stdout.write(f"\33]0;{self.APP_CAPTION}\a"); sys.stdout.flush()

    def _set_separator(self) -> None:
        """ This method will set a separator """
        print(f"{__Colors__.WHITE}{'─' * self.TERMINAL_WIDTH}{__Colors__.RESET_ALL}\n")

    def _center_text(self, text: str) -> str:
        """ This method will center text using terminal width"""
        return text.center(self.TERMINAL_WIDTH)

    def _print_header(self) -> None:
        """ This method will print the app header"""

        # Print header
        print(f"\n{__Colors__.BRIGHT}{__Colors__.WHITE}{self._center_text(f"Welcome to {self.APP_CAPTION}")}\n")
        # Set separator
        self._set_separator()

    @staticmethod
    def _show_version() -> None:
        """Display version information."""
        print(f"\n  {__Colors__.BRIGHT}{__Colors__.CYAN}VERSION INFO:{__Colors__.RESET_ALL}")
        print(f"  {__Colors__.GREEN}SecurePass v{__Core__.VERSION}")
        print(f"  {__Colors__.GREEN}Build date: {__Core__.DATE}")

    @staticmethod
    def _get_user_input() -> str:
        """ This method will return the captured user input"""
        return str(input(f"{__Colors__.BRIGHT}  Your password : "))

    def _wait_user_input(self) -> None:
        """ This method will wait for user input"""

        # wait enter input
        input("\nPress enter to continue...\n")
        # Sleep for 1 second
        sleep(self.WAIT_TIME)

    @staticmethod
    def _show_help() -> None:
        """Display help information."""

        help_text = f"""
        {__Colors__.BRIGHT}{__Colors__.CYAN}AVAILABLE COMMANDS:{__Colors__.RESET_ALL}

        {__Colors__.WHITE}\\help{__Colors__.GREEN} - Show this help message
        {__Colors__.WHITE}\\version{__Colors__.GREEN} - Show version information
        {__Colors__.WHITE}\\about{__Colors__.GREEN} - Show information about HashRipper
        {__Colors__.WHITE}\\exit, \\quit, \\q{__Colors__.GREEN} - Exit the application
        """

        print(help_text)

    @staticmethod
    def _show_about() -> None:
        """Display information about the application."""

        about_text = f"""
        {__Colors__.BRIGHT}{Fore.CYAN}ABOUT SecurePass:{__Colors__.RESET_ALL}

        {__Colors__.GREEN}Securepass is a powerful password checking software designed for
        security, researchers, and system administrators.

        {__Colors__.GREEN}Created by: Aymen Brahim Djelloul
        look  : https://github.com/aymenbrahimdjelloul/Securepass
        License : MIT
            """

        print(about_text)

    def _show_result(self, result: dict) -> None:
        """
        Display the result of the securepass check in a clean, colorful, and readable format.

        Args:
            result (dict): Dictionary containing security check results
        """

        # Set separator
        self._set_separator()

        # Print header
        print(f"{__Colors__.BRIGHT}{__Colors__.BLUE} SecurePass Security Check Results {__Colors__.RESET_ALL}\n")

        # Show breach count with appropriate color
        breach_count = self.securepass.breaches_count
        count_color = __Colors__.RED if breach_count > 0 else __Colors__.GREEN
        count_status = "VULNERABLE" if breach_count > 0 else "SECURE"
        print(f"{__Colors__.BRIGHT}Breached count: {count_color}{breach_count} {count_status}{__Colors__.RESET_ALL}")

        # Display details section
        if result:
            print(f"\n{__Colors__.BRIGHT}{__Colors__.BLUE}Details:{__Colors__.RESET_ALL}")

            # Process each entry with appropriate formatting and coloring
            for key, value in result.items():
                # Transform key names for better readability
                display_key = key

                if key == "password":
                    display_key = "Key"
                    key_color = __Colors__.CYAN
                    value_color = __Colors__.WHITE

                elif key == "entropy_value":
                    display_key = "Entropy"
                    key_color = __Colors__.CYAN
                    if value < 40:
                        value_color = __Colors__.RED
                    elif value < 60:
                        value_color = __Colors__.YELLOW
                    else:
                        value_color = __Colors__.GREEN
                elif key == "score" or "risk" in key:
                    display_key = "Score" if key == "score" else "Risk"
                    key_color = __Colors__.CYAN
                    if value >= 7:
                        value_color = __Colors__.RED
                    elif value >= 4:
                        value_color = __Colors__.YELLOW
                    else:
                        value_color = __Colors__.GREEN

                elif key == "estimated_brute_force":
                    display_key = "Estimated Brute Force"
                    key_color = __Colors__.CYAN
                    if "instantly" in str(value).lower() or "seconds" in str(value).lower() or "minutes" in str(
                            value).lower():
                        value_color = __Colors__.RED
                    elif "hours" in str(value).lower() or "days" in str(value).lower():
                        value_color = __Colors__.YELLOW
                    else:
                        value_color = __Colors__.GREEN

                elif key == "breaches_check":
                    display_key = "Breaches Check"
                    key_color = __Colors__.CYAN
                    value_color = __Colors__.RED if value else __Colors__.GREEN
                elif key == "feedback":

                    display_key = "Feedback"
                    key_color = __Colors__.CYAN
                    value_color = __Colors__.YELLOW

                elif key == "securepass_version":
                    # Replace securepass_version with timestamp
                    from datetime import datetime
                    display_key = "Report Time"
                    key_color = __Colors__.CYAN
                    value_color = __Colors__.WHITE
                    # Generate current timestamp
                    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    value = current_time

                else:
                    key_color = __Colors__.CYAN
                    value_color = __Colors__.WHITE

                # Format and print key-value pair
                print(f"  {key_color}{display_key:<20} : {__Colors__.RESET_ALL} {value_color}", end="")

                # Handle list values specially - print each item on a new line with bullets
                if isinstance(value, list):
                    print()
                    if not value:
                        print("[]")
                    else:
                        print()
                        for item in value:
                            if "weak" in str(item).lower() or "too short" in str(item).lower():
                                item_color = __Colors__.RED
                            elif "avoid" in str(item).lower() or "add" in str(item).lower():
                                item_color = __Colors__.YELLOW
                            else:
                                item_color = __Colors__.WHITE
                            print(f"    • {item_color}{item}{__Colors__.RESET_ALL}")
                else:
                    print(f"{value}{__Colors__.RESET_ALL}")
        else:
            print(f"\n{__Colors__.YELLOW}No detailed results available.{__Colors__.RESET_ALL}")

        # Print footer
        self._set_separator()

    def run(self) -> None:
        """ This method will run the entire CLI"""

        while True:

            # Clear screen
            self._clear_screen()

            # Set header
            self._print_header()

            # Set description text
            print(f"{__Colors__.MAGNETA}Enter your password to get check report.{__Colors__.RESET_ALL}\n")
            # Wait for user input
            user_input: str = self._get_user_input()

            # Check for commands
            if user_input.lower() in ("?", "help", "\\help"):
                self._show_help()

                # Wait for user input
                self._wait_user_input()
                self.run()

            elif user_input.lower() == "\\version":
                self._show_version()

                # Wait for user input
                self._wait_user_input()
                self.run()

            elif user_input.lower() == "\\about":
                self._show_about()

                # Wait for user input
                self._wait_user_input()
                self.run()

            elif user_input.lower() in ("quit", "exit", "q", "bye"):
                print(f"{__Colors__.GREEN}{self.APP_CAPTION} is exiting.{__Colors__.RESET_ALL}")

                # Wait for 1 second
                sleep(self.WAIT_TIME)
                sys.exit(0)

            else:
                # Other-wise if there is no command entered check the input as password
                # Update password to SecurePass
                self.securepass.update(user_input)

                result: dict = self.securepass.password_analysis
                self._show_result(result)

                # Wait for input
                self._wait_user_input()
                # Wait for 1 second
                sleep(self.WAIT_TIME)

                self.run()


def __main__() -> None:
    """ This function will run the CLI"""

    try:
        cli = CLI()
        cli.run()

    except KeyboardInterrupt:
        sys.exit(0)

    # except Exception as exception:
    #     print(exception)
    #     sys.exit(1)


if __name__ == "__main__":
    __main__()
