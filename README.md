# **SecurePass: A pure-python module for password security**

**SecurePass** is a Python library designed to enhance password security by providing tools to assess password strength, detect breaches, and improve security through password salting, random generation, and more. It's simple to integrate into your projects, making it easy to ensure that your passwords are secure.

## **Key Features:**
- **Password Strength Assessment**: Evaluates your password’s strength and provides a percentage rating based on established security metrics.
- **Breach Detection**: Checks your password against a large, constantly updated database of breached passwords.
- **Password Crack Time Estimation**: Estimates how long it would take for a password to be cracked through brute-force or other methods.
- **Password Salting**: Adds a random string (salt) to your password before hashing to prevent rainbow table attacks.
- **Random Password Generator**: Generates strong, random passwords with a specified level of complexity.

## **Installation**

SecurePass is easy to install via **pip**. To get started, simply run the following command:

~~~
pip install securepass
~~~

## How It Works:
- [x] SecurePass uses a variety of well-established methods recommended by leading cybersecurity experts (e.g., Google, Avast) to ensure the security of your passwords:

- [x] Strength Assessment: The library analyzes password length, complexity, and entropy (randomness) to provide a percentage score indicating its strength. The higher the score, the more secure the password.

- [x] Breach Detection: SecurePass uses an extensive database of passwords exposed in data breaches to check if your password has been compromised. It compares your password against hashes stored in the database to determine if it has been leaked in any known breach.

- [x] Crack Time Estimation: SecurePass calculates how long it would take an attacker to crack your password using brute-force methods, based on its length and complexity.

- [x] Password Salting: By applying a unique salt to each password before hashing, SecurePass prevents attackers from using precomputed hash databases (rainbow tables) to quickly crack passwords.

- [x] Random Password Generation: SecurePass includes a built-in function to generate secure passwords with customizable length and complexity requirements, ensuring they are strong and resistant to attacks.


## Simple Usage Example:

~~~python
# import the SecurePass class
from securepass import SecurePass

password = "YourPassword"

# Create SecurePass object
secure_pass = SecurePass(password)

strength = secure_pass.password_strength_score
print(f"Password Strength: {strength}")

~~~


