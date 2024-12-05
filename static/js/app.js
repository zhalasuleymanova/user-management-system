// static/js/app.js

document.addEventListener('DOMContentLoaded', function () {
    // Toggle password visibility for password field
    const togglePassword = document.getElementById("togglePassword");
    const passwordField = document.getElementById("password");

    // Toggle password visibility for password confirmation field
    const togglePasswordConfirmation = document.getElementById("togglePasswordConfirmation");
    const passwordConfirmationField = document.getElementById("password_confirmation");

    togglePassword.addEventListener("click", function () {
        const type = passwordField.type === "password" ? "text" : "password";
        passwordField.type = type;

        if (passwordField.type === "password") {
            this.querySelector("i").classList.replace("bi-eye-slash", "bi-eye");
        } else {
            this.querySelector("i").classList.replace("bi-eye", "bi-eye-slash");
        }
    });

    togglePasswordConfirmation.addEventListener("click", function () {
        const type = passwordConfirmationField.type === "password" ? "text" : "password";
        passwordConfirmationField.type = type;

        if (passwordConfirmationField.type === "password") {
            this.querySelector("i").classList.replace("bi-eye-slash", "bi-eye");
        } else {
            this.querySelector("i").classList.replace("bi-eye", "bi-eye-slash");
        }
    });
});
