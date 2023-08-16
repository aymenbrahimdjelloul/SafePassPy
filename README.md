<h1 align="center">SafePassPy</h1>
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

<h3 align="center">Usage</h3>

~~~python
# First import SafePass module from SafePassPy
from SafePassPy import SafePass

# Create class object named 'password_checker'
# insert the password you'd like to check
password_checker = SafePass.SafePass("1234567890")

# Print out your password strength precentage
print(f"{password_checker.get_password_strength_percent} %")

~~~

~~~
# OUTPUT : 25 %
~~~


