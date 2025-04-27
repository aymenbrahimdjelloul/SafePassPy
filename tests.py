"""
@author : Aymen Brahim Djelloul
date : 27.04.2025
license : MIT

  This is a full test for SecurePass 

"""

# IMPORTS
from securepass import SecurePass, PasswordGenerator
import time
import random
import string


def header(title):
    """Print a simple header for test sections."""
    print(f"\n{'=' * 50}\n{title}\n{'=' * 50}")

def test_password_generator():
    """Test PasswordGenerator functionality with various configurations."""
    header("PASSWORD GENERATOR TESTS")
    
    generator = PasswordGenerator()
    
    # Basic generation tests
    print("\n1. Basic Generation:")
    password = generator.generate_password()
    print(f"Default password: {password} (length: {len(password)})")
    
    pin = generator.generate_pin()
    print(f"Default PIN: {pin} (length: {len(pin)})")
    
    memorable = generator.generate_memorable()
    print(f"Memorable password: {memorable}")
    
    # Test different lengths
    print("\n2. Length Configuration:")
    for length in [8, 16, 32]:
        generator.configure(length=length)
        password = generator.generate_password()
        print(f"Password (length={length}): {password}")
        assert len(password) == length
    
    # Character set configuration - condensed version
    print("\n3. Character Sets:")
    # Only lowercase
    generator.configure(length=12, include_uppercase=False, include_digits=False, include_symbols=False)
    print(f"Lowercase only: {generator.generate_password()}")
    
    # Mixed character types
    generator.configure(length=12, include_uppercase=True, include_lowercase=True, 
                        include_digits=True, include_symbols=True)
    print(f"All character types: {generator.generate_password()}")

def test_securepass():
    """Test SecurePass functionality with various passwords."""
    header("SECUREPASS TESTS")
    
    # Test passwords of varying strength
    passwords = {
        "weak": "password",
        "medium": "Password123", 
        "strong": "P@$$w0rd!123&XYZ"
    }
    
    print("\n1. Password Analysis:")
    for label, password in passwords.items():
        secure = SecurePass(password=password, deep_search=False)
        print(f"\n{label.title()} password: '{password}'")
        print(f"Entropy: {secure.password_entropy}")
        print(f"Strength score: {secure.password_strength_score}")
        print(f"Salt example: {secure.password_salt()}")
        
        # Just test a few methods, no need to test them all for every password
        if label == "weak":
            print(f"Feedback: {secure.get_feedback()}")
        elif label == "medium":
            breach_result = secure.check_password_breaches()
            print(f"Breach check: {'Found in breaches' if breach_result else 'Not found'}")

def performance_test():
    """Simplified performance tests focusing on key metrics."""
    header("PERFORMANCE TESTS")
    
    generator = PasswordGenerator()
    iterations = 500  # Reduced number of iterations
    
    # Test password generation speed
    print("\n1. Generation Speed:")
    start_time = time.perf_counter()
    for _ in range(iterations):
        generator.generate_password(length=16)
    duration = time.perf_counter() - start_time
    print(f"Generated {iterations} passwords in {duration:.3f}s ({iterations/duration:.1f} per second)")
    
    # Test entropy calculation speed
    print("\n2. Analysis Speed:")
    passwords = [
        "password",
        "".join(random.choices(string.ascii_letters + string.digits, k=16)),
        "".join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=32))
    ]
    
    for pwd in passwords:
        start_time = time.perf_counter()
        secure = SecurePass(password=pwd, deep_search=False)
        for _ in range(50):  # Fewer iterations for analysis
            _ = secure.password_entropy
            _ = secure.password_strength_score
        duration = time.perf_counter() - start_time
        print(f"Password '{pwd[:10]}...' analysis: {duration:.3f}s ({50/duration:.1f} analyses/s)")
    
    # Quick breach check performance (minimal testing)
    print("\n3. Breach Check Speed:")
    secure = SecurePass(password="password123", deep_search=False)
    start_time = time.perf_counter()
    result = secure.check_password_breaches()
    duration = time.perf_counter() - start_time
    print(f"Breach check completed in {duration:.3f}s")
    
    # One deep search test
    secure = SecurePass(password="password123", deep_search=True)
    start_time = time.perf_counter()
    result = secure.check_password_breaches()
    duration = time.perf_counter() - start_time
    print(f"Deep search breach check completed in {duration:.3f}s")

def consistency_check():
    """Quick consistency verification."""
    header("CONSISTENCY CHECK")
    
    generator = PasswordGenerator()
    
    # Quick uniqueness check
    iterations = 100  # Significantly reduced
    passwords = set()
    for _ in range(iterations):
        passwords.add(generator.generate_password(length=12))
    
    print(f"Generated {iterations} passwords, {len(passwords)} unique ({len(passwords)/iterations*100:.1f}%)")


if __name__ == "__main__":
    # Run all tests in sequence
    test_password_generator()
    test_securepass()
    performance_test()
    consistency_check()
    print("\nAll tests completed.")
  
