#!/bin/bash

credentials_file="data/credentials.txt"

# Function to prompt for credentials
get_credentials() {
   # Prompt the user to enter their username
    read -p "Enter your username: " username

    # Prompt the user to enter their password (hide input)
    read -s -p "Enter your password: " password
    echo

    # Display the input received
    echo "Username: $username"
    echo "Password: $**********"
    # Write code read the user username and password 
    # The password must be invisible while typing to ensure that no one can read it while inserting it 
    return 0
}

# Function to generate a salted hash of the password
hash_password() {
    local salt=$(openssl rand -hex 8)
    local hashed_pass=$(echo -n "$1$salt" | sha256sum | awk '{print $1}')
    echo "$hashed_pass:$salt"
}

# Function to register new credentials
register_credentials() {
    # Prompt the user to enter their username
    read -p "Enter your username: " username

    # Prompt the user to enter their password (hide input)
    read -s -p "Enter your password: " password
    echo

    # Display the input received
    echo "Username: $username"
    echo "Password: ********"

    # Append the username and password to the credentials.txt file
    echo "Username: $username" >> credentials.txt
    echo "Password: $password" >> credentials.txt
    # Insert code to register add the created user to a file called credentials.txt
    # Write your code here
    echo -e "Registration successful. You can now log in.\n"
}

# Function to verify credentials and privileges
verify_credentials() {
    local stored_cred=$(grep "^$user:" "$credentials_file" | cut -d ':' -f 2-)
    if [[ -n "$stored_cred" ]]; then
        local stored_pass=$(echo "$stored_cred" | cut -d ':' -f 1)
        local salt=$(echo "$stored_cred" | cut -d ':' -f 2)
        local hashed_pass=$(echo -n "$pass$salt" | sha256sum | awk '{print $1}')
        # check whether the credentials provided are accurate 
        	# Write here
		       if [[ "$stored_pass" == "$hashed_pass" ]]; then
            # On successful login remember to update the credentials.txt file for login status to 1
	    # if the credentials provided are correct, check the role. If the role is admin, call the admin menu
                # write here
            sed -i "s/^$user:$stored_cred$/$user:$stored_cred:1/" "$credentials_file"

            # if the credentials provided are correct, check the role. If the role is admin, call the admin menu
            local role=$(echo "$stored_cred" | cut -d ':' -f 3)
            if [[ "$role" == "admin" ]]; then
                admin_menu
            else
                # Otherwise call user menu
		 # Write your code here
                user_menu
            fi

            return 0 # Successful login
        fi
    fi

    echo -e "Unsuccessful login. Incorrect username or password. Please try again.\n"
    return 1
}
 

# Function for the admin menu
admin_menu() {
    while true; do
        echo -e "\nAdmin Menu:"
        echo "1. Create User Account"
        echo "2. Logout"

        read -p "Enter your choice: " choice

        case $choice in
            1)
                read -p "Enter the username for the new user: " new_user
                read -p "Enter the password for the new user: " new_pass
                read -p "Enter the role for the new user (e.g., 'user' or 'admin'): " new_role

                # Check if the new_user already exists in the credentials file
                if grep -q "^$new_user:" "$credentials_file"; then
                    echo "Username '$new_user' already exists. Please choose a different username."
                else
                    # Generate a random salt for the new user's password
                    new_salt=$(openssl rand -hex 16)

                    # Hash the new user's password with the salt
                    new_hashed_pass=$(echo -n "$new_pass$new_salt" | sha256sum | awk '{print $1}')

                    # Append the new user's credentials to the credentials file
                    echo "$new_user:$new_hashed_pass:$new_salt:$new_role" >> "$credentials_file"

                    echo "User account created successfully for '$new_user'."
                fi
                ;;
            2)
                # Logout
                # Update the credentials.txt file for login status to 0 (logged out)
                sed -i "s/^$user:$stored_cred:1$/$user:$stored_cred:0/" "$credentials_file"
                echo "Logged out successfully."
                return 0
                ;;
            *)
                echo "Invalid choice. Please try again."
                ;;
        esac
    done
}
# Function to handle user login
user_login() {
    echo "Enter your username:"
    read username
    echo "Enter your password:"
    read -s password

    # Check if the username and password are correct (you may have a database or some other method for validation)
    # For this example, we will assume a predefined username and password.
    if [[ $username == "user" && $password == "password" ]]; then
        echo "Login successful!"
        user_menu
    else
        echo "Invalid username or password. Please try again."
        user_login
    fi
}
return 0;
# Function to handle user registration (dummy implementation)
user_register() {
    echo "Enter your desired username:"
    read new_username
    echo "Enter your desired password:"
    read -s new_password

    # You may have a database or some other method to save the new user information.
    # For this example, we will just assume the registration is successful.
    echo "Registration successful!"
    user_menu
}

# Function to handle user logout
user_logout() {
    echo "Logging out..."
    echo "Logged out successfully."
    exit 0
}

# Function for the user menu
user_menu() {
    echo "==============================="
    echo "1. Login"
    echo "2. Register"
    echo "3. Logout"
    echo "4. Exit"
    echo "==============================="
    echo "Enter your choice (1/2/3/4):"
    read choice

    case $choice in
        1) user_login ;;
        2) user_register ;;
        3) user_logout ;;
        4) echo "Exiting the authentication system. Goodbye!"; exit 0 ;;
        *) echo "Invalid choice. Please try again." ;;
    esac

    # Show the menu again after completing an action
    user_menu
}

# Main script execution starts here
echo "Welcome to the authentication system."
user_menu

# Function for the user menu
user_menu() {
    echo "This is a normal user menu..."
    exit 0
}

# Main script execution starts here
echo "Welcome to the authentication system."
# write a script that allows a system user to login, register, logout and exit from the system

