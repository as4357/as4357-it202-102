<?php
require(__DIR__ . "/partials/nav.php");

// as4357//////
require_once(__DIR__ . "/lib/db.php");
require_once(__DIR__ . "/lib/helpers.php");

// Initialize session
session_start();

// Handle user registration
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST["register"])) {
    $email = se($_POST, "email", "", false);
    $username = se($_POST, "username", "", false);
    $password = se($_POST, "password", "", false);
    $confirmPassword = se($_POST, "confirm_password", "", false);

    // Validate form fields
    $errors = [];
    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Invalid email address";
    }
    if (empty($username)) {
        $errors[] = "Username must not be empty";
    }
    if (empty($password) || strlen($password) < 8) {
        $errors[] = "Password must be at least 8 characters long";
    }
    if ($password !== $confirmPassword) {
        $errors[] = "Passwords do not match";
    }

    if (empty($errors)) {
        // Hash the password
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

        // Insert user data into the database
        $db = getDB();
        $stmt = $db->prepare("INSERT INTO Users (username, email, password) VALUES (:username, :email, :password)");
        $r = $stmt->execute([
            ":username" => $username,
            ":email" => $email,
            ":password" => $hashedPassword
        ]);

        if ($r) {
            echo "User registered successfully";
        } else {
            echo "Error registering user";
        }
    } else {
        foreach ($errors as $error) {
            echo $error . "<br>";
        }
    }
}

// Handle user login
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST["login"])) {
    $emailOrUsername = se($_POST, "email_or_username", "", false);
    $password = se($_POST, "password", "", false);

    // Find user by email or username
    $db = getDB();
    $stmt = $db->prepare("SELECT id, username, email, password FROM Users WHERE email = :email OR username = :username");
    $stmt->execute([
        ":email" => $emailOrUsername,
        ":username" => $emailOrUsername
    ]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($password, $user["password"])) {
        // Store user details in session
        $_SESSION["user"] = [
            "id" => $user["id"],
            "username" => $user["username"],
            "email" => $user["email"]
        ];
        header("Location: home.php");
        exit();
    } else {
        echo "Invalid email/username or password";
    }
}
?>

<!-- Registration form -->
<form method="POST">
    <div>
        <label for="email">Email</label>
        <input type="email" name="email" required />
    </div>
    <div>
        <label for="username">Username</label>
        <input type="text" name="username" required />
    </div>
    <div>
        <label for="password">Password</label>
        <input type="password" name="password" required minlength="8" />
    </div>
    <div>
        <label for="confirm_password">Confirm Password</label>
        <input type="password" name="confirm_password" required minlength="8" />
    </div>
    <input type="submit" name="register" value="Register" />
</form>

<!-- Login form -->
<form method="POST">
    <div>
        <label for="email_or_username">Email or Username</label>
        <input type="text" name="email_or_username" required />
    </div>
    <div>
        <label for="password">Password</label>
        <input type="password" name="password" required />
    </div>
    <input type="submit" name="login" value="Login" />
</form>
