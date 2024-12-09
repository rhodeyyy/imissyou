import bcrypt

# Your desired password for the admin account
password = 'imissher'  # Change this to the password you want for the admin

# Generate the hashed password
hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Print the hashed password
print(hashed_password.decode('utf-8'))
