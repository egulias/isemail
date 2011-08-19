EmailValidator (old is_email)
=============================

How to use ?
------------

Simple example:

```php
<?php

require_once 'EmailValidator.php';

$validator = new EmailValidator;
if ($validator->isValid($email)) {
	echo $email . ' is a valid email address';
}
```

More advanced example (returns detailed diagnostic error codes):

```php
<?php

require_once 'EmailValidator.php';

$validator = new EmailValidator;
$email = 'dominic@sayers.cc';
$result = $validator->isValid($email);

if ($result) {
	echo $email . ' is a valid email address';
} else if ($validator->hasWarnings()) {
	echo 'Warning! ' . $email . ' has unusual/deprecated features (result code ' . var_export($validator->getWarnings(), true) . ')';
} else {
	echo $email . ' is not a valid email address (result code ' . var_export($validator->getErrors(), true) . ')';
}
```

Copyright
---------

Copyright (c) 2008-2011 Dominic Sayers <dominic@sayers.cc>

Contributors
------------

* Josepf Bielawski [stloyd](http://github.com/stloyd)
* Dominic Sayers [dominicsayers](http://github.com/dominicsayers)

License
-------

BSD License (http://www.opensource.org/licenses/bsd-license.php)