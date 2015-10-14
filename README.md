# Auth [![Build Status](https://travis-ci.org/objectiveweb/auth.svg?branch=master)](https://travis-ci.org/objectiveweb/auth)

Authentication Library 

## Setup

Setup the auth dependency on your project's composer.json, then run `composer update`


       "require": {
           "objectiveweb/auth": "~0.1"
       }

### Auth initialization

Create a new $auth instance, passing the appropriate parameters

    // Auth depends on PDO
    $pdo = new PDO($dsn);

    $auth = new Auth($pdo, [
        'session_key' => 'ow_auth',
        'table' => 'ow_auth',
        'id' => 'id',
        'username' => 'username',
        'password' => 'password',
        'token' => NULL,
        'created' => NULL,
        'last_login' => NULL
    ]);

#### Parameters
* 'session_key'

    Key used for $_SESSION storage, defaults to 'ow_auth'

* 'table'

    Database table which stores users, defaults to 'ow_auth'

* 'id'

    Primary key of the user table, defaults to 'id'

* 'username'

    Username field on the user table, defaults to 'username'

* 'password'

    Password field on the user table, defaults to 'password',

* 'token'

    Optional CHAR(32) field to store a random token

* 'created'

    Optional DATETIME field to store the accounts creation date

* 'last_login'

    Optional DATETIME field to store the last successful login date

## Usage

    # register user
    try {
        $user = $auth->register('username', 'password');
    }
    catch(\Exception $ex) {
        printf('DB Error creating user: %s', $ex->getMessage());
    }

    # login user
    try {
        $user = $auth->login('username', 'password');
    }
    catch(PasswordMismatchException $ex) {
        printf("Password mismatch");
    }
    catch(UserException $ex) {
        printf("Error logging in: %s", $ex->getMessage());
    }

    # check if the user is logged in
    if($auth->check()) {
        // user is logged in
    }
    else {
        // user is not logged in
    };

    # retrieve the current user from the session
    try {
        $user = $auth->user();
    }
    catch(UserException $ex) {
        printf("User not logged in");
    }

    # logout user
    $auth->logout();

### Store additional data when registering a user

    $user = $auth->register('username', 'password', [
        'email' => 'someone@somewhere',
        'displayName' => 'Test User'
    ]);

### Generating a password reset token

When the `token` parameter is enabled in initialization

    $token = $auth->update_token($username);

    // send $token to user, then later
    try {
        $auth->passwd_reset($token, $new_password);
    }
    catch(UserException $ex) {
        printf('Invalid token provided');
    }

### Updating user data

    $auth->update($username, [ 'email' => 'new@email.com' ]);

