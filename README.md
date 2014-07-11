JWT (JSON Web Token) Creation and Decoding Library
====================

This library allows for the creation and decoding of JWT (JSON Web Tokens).

### Example Usage

In the example below, the `JWT` object is created and a `Header` instance is assigned (required). The `JWt` object is then
assigned several claims: issuer, audience, issued at and not before to define data and how it could be processed. The `encode`
method is then called with the `key` and a resulting JWT-formatted string is returned.

**NOTE:** The JWT token will be generated in the order the claims are provided. No sorting is done in the background.

The `decode` method can then be called on the data along with the `key` to return an object matching the state of the `jwt` object.

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

### Encryption via OpenSSL

The JWT Library also supports encryption of the resulting JWT-formatted string. Here's an example of it in use:

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
	->notBefore(1357000000)
	->setEncryptionAlgorithm('AES-256-CBC')
	->setEncryptionIv('1234567812345678');

$result = $jwt->encode($key);
?>
```

You can use any of the OpenSSL cypher methods provided by the [openssl_get_cipher_methods](http://us3.php.net/openssl_get_cipher_methods) on your system.

### Supported Claim Types

- Audience (aud)
- Expire Time (exp)
- Issued At (iat)
- Issuer (iss)
- JwtId (jit)
- Not Before (nbf)
- Subject (sub)

### Documentation for JSON Web Tokens

- [Draft IETF](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html)