is_email()
Copyright 2008-2011 Dominic Sayers <dominic@sayers.cc>
http://isemail.info
BSD License (http://www.opensource.org/licenses/bsd-license.php)

How to use `EmailValidator` ?
-----------------------------
1. Add the downloaded file `EmailValidator.php` to your project
2. In your scripts use it like this:

	require_once 'EmailValidator.php';

    $validator = new EmailValidator;
    if ($validator->isValid($email)) {
        echo "$email is a valid email address<br>";
    }

3. If you want to return detailed diagnostic error codes then you can ask
`EmailValidator` to do so. Something like this should work:

    require_once 'EmailValidator.php';

    $validator = new EmailValidator;
	$email = 'dominic@sayers.cc';
	$result = $validator->isValid($email);

	if ($result) {
    	echo $email . ' is a valid email address';
	} else if ($validator->hasWarnings()) {
		echo 'Warning! ' . $email . ' has unusual features (result code ' . var_export($validator->getWarnings(), true) . ')';
	} else {
		echo $email . ' is not a valid email address (result code ' . var_export($validator->getErrors(), true) . ')';
	}

4. Example scripts are in the extras folder
