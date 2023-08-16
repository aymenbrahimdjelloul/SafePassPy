<h1 align="center">SafePassPy</h1>
<br>
<p>SafePassPy is a pure-python library used to secure passwords and determine the strength percentage of password also check the passwords breachs, and much more tools</p>

<h3 align="center">Features</h3>

- [x] Determine Password strength percentage
- [x] Check your password for password breach through large passwords database 
- [x] Estimated the time to crack your password
- [x] Make your password more secure and complex with Password salting feature
- [x] Generate a strong random passwords for you

<h3 align="center">How It's work ?</h3>
<p>SafePassPy uses multiple methods to make you satisfied and feel secure, it uses multiple password measures that have been authorized from specialists in IT and Cyber-Security
like Avast and Google, also SafePassPy uses a large passwords database to check password breachs through it</p>

<h3 align="center">Simple Usage</h3>

~~~python
# First import SafePass module from SafePassPy
from SafePassPy import SafePass

# Create class object named 'password_checker'
# insert the password you'd like to check
password_checker = SafePass.SafePass("1234567890")

# Print out your password strength precentage
print(f"{password_checker.get_password_strength_percent} %")

~~~

<h6>OUTPUT</h6>

~~~
 25 %
~~~

<h3 align="center">Advanced Usage</h3>

~~~python

# First import SafePass module from SafePassPy
from SafePassPy import SafePass

# Create class object named 'password_checker'
# insert the password you'd like to check
password_checker = SafePass.SafePass("1234567890")

# Print out the short answer from the returned output
# NOTE : 'check_password_breaches' return a dictionary. check the examples directory 
print(password_checker.check_password_breaches["is_password_breached"])

# print out the crack time for your password in a human-readable format
print(password_checker.estimate_brute_force_time())

~~~

<h6>OUTPUT</h6>

~~~
 True

 3 days
~~~

<h3 align="center">License</h3>
<h6>This project is published under MIT License </h6>

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

