# Flask Application with User Authentication

This is a Flask-based web application that provides user authentication features, including registration, login, user role management, and secure session management. The application also includes an admin dashboard where administrators can manage users.

## Features

### User Registration
- Users can register by providing a valid username, full name, email, and password.
- Passwords are securely hashed using bcrypt before being stored in the database.

### User Login
- Registered users can log in with their credentials.
- Passwords are checked securely using bcrypt for validation.

### Admin Dashboard
- Only accessible to users with an `admin` role.
- Admins can view, create, edit, or delete users.
- Admins can manage user roles and ensure user management is performed securely.

### Regular Dashboard
- Accessible to users who have logged in, but only users with an `admin` role can access the admin dashboard.
  
### Secure Session Management
- The application uses Flask's session management system to manage user sessions securely.
- Sessions have a timeout to prevent unauthorized access.
- Session data is protected against theft using secure cookies.
  
## Security Features

### 1. **Input Validation**
   - Validates username, password, full name, and email using regular expressions to prevent malicious input and ensure proper formatting.

### 2. **Password Security**
   - Passwords are hashed using bcrypt before being stored in the database to prevent plaintext password storage.

### 3. **Hashed Passwords**
   - The passwords in the database are securely hashed using bcrypt.

### 4. **Security Headers**
   - The application includes HTTP security headers like `Strict-Transport-Security` (HSTS) to enforce HTTPS connections and prevent downgrade attacks.

### 5. **Parameterized Queries**
   - All SQL queries use parameterized statements to protect against SQL Injection attacks.

### 6. **Rate Limiting**
   - The application limits login attempts to prevent brute force attacks using Flask-Limiter.

### 7. **Session Fixation Prevention**
   - Session IDs are regenerated after login to prevent session fixation attacks.

### 8. **Session Expiry and Secure Session Management**
   - Sessions expire after 30 minutes of inactivity, and session data is cleared upon logout to prevent unauthorized access.
   - The session cookie is configured to be secure, HTTP-only, and with a "SameSite" attribute to prevent cross-site request forgery (CSRF).

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/murazyusifov/user-management-system.git
   cd user-management-system
   ```

2. Create log file
    ```bash
    add app.log file
    ```

3. Configure database settings
    ```bash
    mysql -u root -p
    run code in dump.sql file
    ```

4. Install dependencies
    ```bash
    pip install flask flask-mysqldb 
    pip install bcrypt
    pip install bleach
    pip install flask-login
    pip install Flask-Limiter
    ```

5. Run the application
    ```bash
    python app.py
    ```

