JWT (JSON Web Token) Creation and Decoding Library
====================

This library allows for the creation and decoding of JWT (JSON Web Tokens).

### Example Usage

```php
<?php

require_once 'vendor/autoload.php';

$key = "example_key";

$header = new \Psecio\Jwt\Header();
$header->setKey($key);

$jwt = new \Psecio\Jwt\Jwt($header);

$jwt
    ->issuer('http://example.org')
    ->audience('http://example.com')
	->issuedAt(1356999524)
	->notBefore(1357000000);

$result = $jwt->encode($key);
echo 'ENCODED: '.print_r($result)."\n\n";
echo 'DECODED: '.var_export($jwt->decode($result, $key), true);

?>
```