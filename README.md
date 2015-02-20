JWT (JSON Web Token) Creation and Decoding Library
====================

[![Build Status](https://travis-ci.org/psecio/jwt.svg?branch=master)](http://travis-ci.org/psecio/jwt)

This library allows for the creation and decoding of JWT (JSON Web Tokens).

### Installation

This tool can be installed via Composer:

```
{
	"require": {
		"psecio/jwt": "1.*"
	}
}
```

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

$header = new \Psecio\Jwt\Header($key);
$jwt = new \Psecio\Jwt\Jwt($header);

$jwt
    ->issuer('http://example.org')
    ->audience('http://example.com')
	->issuedAt(1356999524)
	->notBefore(1357000000)
	->expireTime(time()+3600)
	->jwtId('id123456')
	->type('https://example.com/register');

$result = $jwt->encode();
echo 'ENCODED: '.print_r($result)."\n\n";
echo 'DECODED: '.var_export($jwt->decode($result), true);

?>
```

### Encryption via OpenSSL

The JWT Library also supports encryption of the resulting JWT-formatted string. Here's an example of it in use:

```php
<?php

require_once 'vendor/autoload.php';

$key = 'example_key';
$encryptKey = 'my-encryption-key';

$header = new \Psecio\Jwt\Header($key);
$jwt = new \Psecio\Jwt\Jwt($header);

$jwt
    ->issuer('http://example.org')
    ->audience('http://example.com')
	->issuedAt(1356999524)
	->notBefore(1357000000)
	->expireTime(time()+3600)
	->jwtId('id123456')
	->type('https://example.com/register');

$result = $jwt->encrypt('AES-256-CBC', '1234567812345678', $encryptKey);

echo 'ENCRYPTED: '.var_export($result, true)."\n";
echo "DECRYPTED: ".var_export($jwt->decrypt($result, 'AES-256-CBC', '1234567812345678', $encryptKey), true)."\n";

?>
```

### Custom Claim values

You can also add your own custom claim values to the JWT payload using the `custom` method. The first paramater is the value and the second is the claim "type" (key):

```php
<?php
require_once 'vendor/autoload.php';

$key = "example_key";

$header = new \Psecio\Jwt\Header($key);

$jwt = new \Psecio\Jwt\Jwt($header);
$jwt->custom('foobar', 'custom-claim');

// Or, you can add more than one at the same time with an array
$jwt->custom(array(
    'custom-claim' => 'foorbar',
    'key1' => 'value1'
));

$result = $jwt->encode();
echo 'ENCODED: '.print_r($result)."\n\n";
echo 'DECODED: '.var_export($jwt->decode($result), true);
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
- Private

### Hashing types

By default this JWT tool uses `HMAC` hashing (HS256) to generate the signature for the request. There are other options for this that will use the OpenSSL functionality to let you use public and private keys for these methods:

- HS256
- HS384
- HS512
- ES256
- ES384
- ES512
- RS256
- RS384
- RS512

You cannot use a simple text string for the key like you can with `HMAC` hashing, so you must provide a valid key instance for the library to use. Here's an example using a `.pem` private key file and the `RS256` hashing:

```php
<?php
$key = openssl_pkey_get_private('file://'.__DIR__.'/private.pem', 'test1234');

$header = new \Psecio\Jwt\Header($key);
$header->setAlgorithm('RS256');

// or you can define the hash algorithm on the init too:
$header = new \Psecio\Jwt\Header($key, 'RS256');
?>
```

An exception (`\Psecio\Jwt\Exception\InvalidKeyException`) will be thrown if the key is invalid and cannot be used in signing the request. If there is an error during the actual signing of the message, you will be thrown a `\Psecio\Jwt\Exception\SignatureErrorException`.

### Documentation for JSON Web Tokens

- [JWT Draft IETF](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html)
- [JWS Draft](https://tools.ietf.org/html/draft-ietf-jose-json-web-signature)
- [JWE Draft](https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption)
