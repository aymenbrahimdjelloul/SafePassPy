"""
This code or file is part of 'SecurePass' project
copyright (c) 2023-2025, Aymen Brahim Djelloul, All rights reserved.
use of this source code is governed by MIT License that can be found on the project folder.

@author : Aymen Brahim Djelloul
version : 1.1
date    : 19.05.2025
license : MIT

   // This is a full test for SecurePass with improved output formatting

"""

# IMPORTS
import time
import random
import string
from securepass import SecurePass, PasswordGenerator


try:

    from colorama import Fore, Style, init

    # Initialize colorama
    init(autoreset=True)

    class Colors:
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

    class Colors:
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





def print_header(title):
    """Print a visually appealing header for test sections."""
    print(f"\n{Colors.CYAN}{Colors.BRIGHT}{'═' * 80}")
    print(f"{Colors.CYAN}{Colors.BRIGHT}║ {title}")
    print(f"{Colors.CYAN}{Colors.BRIGHT}{'═' * 80}{Colors.RESET_ALL}")


def print_subheader(title):
    """Print a subsection header."""
    print(f"\n{Colors.YELLOW}{Colors.BRIGHT}▶ {title}{Colors.RESET_ALL}")


def print_result(label, value, success=None):
    """Print a test result with optional success indicator."""
    # Format the label with fixed width for alignment
    formatted_label = f"{label}:".ljust(25)

    # Determine color based on success parameter if provided
    if success is None:
        color = Colors.WHITE
    elif success:
        color = Colors.GREEN
    else:
        color = Colors.RED

    print(f"  {Colors.BLUE}{formatted_label} {color}{value}{Colors.RESET_ALL}")


def print_password_info(label, password, details=None):
    """Print password information in a consistent format."""
    print(f"\n  {Colors.MAGNETA}{Colors.BRIGHT}{label}:{Colors.RESET_ALL} '{password}'")
    if details:
        for key, value in details.items():
            print(f"    {Colors.WHITE}▸ {key}: {value}")


def test_password_generator():
    """Test PasswordGenerator functionality with various configurations."""
    print_header("PASSWORD GENERATOR TESTS")

    generator = PasswordGenerator()

    # Basic generation tests
    print_subheader("Basic Generation")

    password = generator.generate_password()
    print_result("Default password", password)
    print_result("Length", len(password))

    pin = generator.generate_pin()
    print_result("Default PIN", pin)
    print_result("Length", len(pin))

    memorable = generator.generate_memorable()
    print_result("Memorable password", memorable)

    # Test different lengths
    print_subheader("Length Configuration")

    test_lengths = [8, 16, 32]
    for length in test_lengths:
        generator.configure(length=length)
        password = generator.generate_password()
        success = len(password) == length
        print_result(f"Password (length={length})", password, success)

    # Character set configuration
    print_subheader("Character Sets")

    # Only lowercase
    generator.configure(length=12, use_uppercase=False, use_digits=False, use_special=False)
    password = generator.generate_password()
    print_result("Lowercase only", password)

    # Mixed character types
    generator.configure(length=12, use_uppercase=True, use_lowercase=True,
                        use_digits=True, use_special=True)
    password = generator.generate_password()
    print_result("All character types", password)


def test_securepass():
    """Test SecurePass functionality with various passwords."""
    print_header("SECUREPASS TESTS")

    # Test passwords of varying strength
    passwords = {
        "Weak": "password",
        "Medium": "Password123",
        "Strong": "P@$$w0rd!123&XYZ"
    }

    print_subheader("Password Analysis")

    for label, password in passwords.items():
        secure = SecurePass(password=password)

        # Use color to indicate strength visually
        if label == "Weak":
            strength_color = Colors.RED
        elif label == "Medium":
            strength_color = Colors.YELLOW
        else:
            strength_color = Colors.GREEN

        details = {
            "Entropy": f"{secure.password_entropy:.2f} bits",
            "Strength score": f"{strength_color}{secure.password_strength_score}/100{Colors.RESET_ALL}",
            "Salt example": secure.password_salt()
        }

        # Add specific tests for different password types
        if label == "Weak":
            details["Feedback"] = secure.get_feedback
        elif label == "Medium":
            breach_result = secure.check_password_breaches
            breach_status = f"{Colors.RED}Found in breaches" if breach_result else f"{Colors.GREEN}Not found"
            details["Breach check"] = breach_status

        print_password_info(label, password, details)


def performance_test():
    """Performance tests with improved visual presentation."""
    print_header("PERFORMANCE TESTS")

    generator = PasswordGenerator()
    iterations = 500

    # Test password generation speed
    print_subheader("Generation Speed")

    start_time = time.perf_counter()
    for _ in range(iterations):
        generator.generate_password()
    duration = time.perf_counter() - start_time

    print_result("Generated passwords", iterations)
    print_result("Total time", f"{duration:.3f} seconds")
    print_result("Rate", f"{iterations/duration:.1f} passwords/second")

    # Test entropy calculation speed
    print_subheader("Analysis Speed")

    passwords = [
        "password",
        "".join(random.choices(string.ascii_letters + string.digits, k=16)),
        "".join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=32))
    ]

    password_types = ["Simple", "Medium complexity", "High complexity"]

    for pwd_type, pwd in zip(password_types, passwords):
        start_time = time.perf_counter()
        secure = SecurePass(password=pwd)

        analyses = 50
        for _ in range(analyses):
            _ = secure.password_entropy
            _ = secure.password_strength_score

        duration = time.perf_counter() - start_time

        # Display truncated password or full if short
        display_pwd = pwd if len(pwd) <= 10 else f"{pwd[:10]}..."
        print_result(f"{pwd_type} ({display_pwd})", f"{duration:.3f}s ({analyses/duration:.1f} analyses/s)")

    # Breach check performance
    print_subheader("Breach Check Speed")

    # Standard search
    secure = SecurePass(password="password123")
    start_time: float = time.perf_counter()
    result: bool = secure.check_password_breaches

    if result:
        duration: float = time.perf_counter() - start_time

    else:
        duration: int = -1

    print_result("Standard search", f"{duration:.3f} seconds")

    # Deep search
    secure = SecurePass(password="password123", deep_search=True)
    start_time: float = time.perf_counter()
    result: bool = secure.check_password_breaches

    if result:
        duration: float = time.perf_counter() - start_time

    else:
        duration: int = -1

    print_result("Deep search", f"{duration:.3f} seconds")


def consistency_check():
    """Consistency verification with visual indicators."""
    print_header("CONSISTENCY CHECK")

    generator = PasswordGenerator()
    iterations = 100

    print_subheader("Password Uniqueness")

    passwords = set()
    for _ in range(iterations):
        passwords.add(generator.generate_password())

    uniqueness_percentage = len(passwords)/iterations*100
    success = uniqueness_percentage > 99  # Consider success if >99% unique

    print_result("Generated passwords", iterations)
    print_result("Unique passwords", len(passwords))
    print_result("Uniqueness percentage", f"{uniqueness_percentage:.1f}%", success)


def run_all_tests():
    """Run all tests with timing."""
    total_start_time = time.perf_counter()

    print(f"\n{Colors.GREEN}{Colors.BRIGHT}{'▓' * 80}")
    print(f"{Colors.GREEN}{Colors.BRIGHT}▓{'SECUREPASS TEST SUITE':^78}▓")
    print(f"{Colors.GREEN}{Colors.BRIGHT}{'▓' * 80}{Colors.RESET_ALL}")

    # Run individual tests
    test_password_generator()
    test_securepass()
    performance_test()
    consistency_check()

    total_duration = time.perf_counter() - total_start_time

    # Final summary
    print(f"\n{Colors.GREEN}{Colors.BRIGHT}{'▓' * 80}")
    print(f"{Colors.GREEN}{Colors.BRIGHT}▓{'TEST SUMMARY':^78}▓")
    print(f"{Colors.GREEN}{Colors.BRIGHT}{'▓' * 80}{Colors.RESET_ALL}")
    print(f"\n{Colors.WHITE}All tests completed in {Colors.CYAN}{total_duration:.2f} seconds{Colors.RESET_ALL}")
    print(f"{Colors.WHITE}SecurePass version: 1.1{Colors.RESET_ALL}")


if __name__ == "__main__":
    run_all_tests()
