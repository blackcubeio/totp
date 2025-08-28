Totp
=======

Installation
------------

If you use Packagist for installing packages, then you can update your composer.json like this :

``` json
{
    "require": {
        "blackcube/totp": "*"
    }
}
```

Testing
-------

To run the tests:

``` bash
composer install
./vendor/bin/codecept build
./vendor/bin/codecept run
```

To check coverage report:

``` bash
./vendor/bin/codecept run --coverage --coverage-html
```

Usage
-----

Totp class allows you to generate and verify TOTP codes.

Generating TOTP Codes

``` php
use blackcube\totp\Totp;

$totp = new Totp();
$registerKey = 'JBSWY3DPEHPK3PXP'; // Base 32 encoded Key used to generate the TOTP codes
$lostPasswordKey = 'JBSWY3DPEHPK3PXA'; // Base 32 encoded Key used to generate the TOTP codes for lost password service
// Define a key for register service
$totp->setKey('register', $registerKey);
// Define a key for lost password service
$totp->setKey('lostPassword', $lostPasswordKey);

// we can force the time step (default is 30 seconds) and the window (default is 10)
$totp->setWindow(10); // Allow codes to be valid for 10 time steps
$totp->setStep(30); // Each time step is 30 seconds
// codes are valid for 5 minutes in this case
$registerTotpCode = $totp->generate('register'); // Generate a TOTP code for register service
$lostPasswordTotpCode = $totp->generate('lostPassword'); // Generate a TOTP code for lost password service
```

Verifying TOTP Codes

```php
use blackcube\totp\Totp;

$totpChcecker = new Totp(
    step: 30,
    window: 10
);
$registerKey = 'JBSWY3DPEHPK3PXP'; // Base 32 encoded Key used to generate the TOTP codes
$lostPasswordKey = 'JBSWY3DPEHPK3PXA'; // Base 32 encoded Key used to generate the TOTP codes for lost password service
// Define a key for register service
$totpChcecker->setKey('register', $registerKey);
// Define a key for lost password service
$totpChcecker->setKey('lostPassword', $lostPasswordKey);

// Verify the TOTP code for register service
$isRegisterValid = $totp->verify('register', $registerTotpCode);
// Verify the TOTP code for lost password service
$isLostPasswordValid = $totp->verify('lostPassword', $lostPasswordTotpCode);
```

Contributing
------------

All code contributions - including those of people having commit access -
must go through a pull request and approved by a core developer before being
merged. This is to ensure proper review of all the code.

Fork the project, create a [feature branch ](http://nvie.com/posts/a-successful-git-branching-model/), and send us a pull request.