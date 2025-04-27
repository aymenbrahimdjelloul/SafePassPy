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
# Import SecurePass class from securepass module
from securepass import SecurePass

my_password = "MyPassword"

# Create SecurePass object
secure_pass = SecurePass(my_password)

strength = secure_pass.password_strength_score
print(f"Password Strength: {strength}")

~~~

## Advanced Usage Example:

~~~python
# Import SecurePass class from securepass module
from securepass import SecurePass

my_password = "MyPassword"

# Create SecurePass object
secure_pass = SecurePass(my_password, deep_sarch=True)
# NOTE : Use the 'deep_search' to go through hunderds of thousand of checks

if secure_pass.check_password_breaches():
    print("Your password has been compromised in a data breach!")
else:
    print("Your password is safe.")
~~~

## Generate Secure Passwords

~~~python

from securepass import PasswordGenerator

# Create Password Generator object
generator = PasswordGenerator()

# Generate a random secured password
password = generator.generate_password()
print(password)

# Generate memorable secure password
password = generator.generate_memorable()
print(password)

~~~

### License :

~~~
MIT License

Copyright (c) 2023 Aymen Brahim Djelloul

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

~~~

## Why Use SecurePass?
Comprehensive Security: SecurePass covers all critical aspects of password security, from strength assessment to breach detection.
Ease of Use: With an intuitive and simple API, SecurePass is straightforward to integrate into any project.
Robust Features: SecurePass offers strong password salting, random generation, and secure password checking to ensure your passwords are as safe as possible.

## Contribute

We welcome contributions to SecurePass! Whether you're reporting a bug, suggesting a feature, or submitting code, your contributions are valuable. To get started:
Fork the repository.
Create a new branch for your changes.
Make your changes and ensure the tests pass.
Submit a pull request with a detailed description of your changes.
We appreciate your help in improving the project!

## Thanks

We would like to thank the following individuals and organizations for their contributions to this project:
Cybersecurity Experts: For providing guidelines and best practices that SecurePass follows.
Open Source Contributors: Who have contributed their time and expertise to enhance the security of this library.
Thank you for using SecurePass! Stay safe and secure online!


