<?php

namespace PsecioTest\Jwt;

use Psecio\Jwt\Header;
use Psecio\Jwt\Jwt;

class JwtTest extends \PHPUnit_Framework_TestCase
{
    private $jwt;

    public function setUp()
    {
        $key = 'foobarbaz';
        $header = new Header($key);
        $this->jwt = new Jwt($header);
    }

    public function tearDown()
    {
        unset($this->jwt);
    }

    public function testEncodeDecode()
    {
        $time = time();
        $before = $time-1;
        $expire = $time+30;
        $this->jwt
             ->issuer('http://example.org')
             ->audience('http://example.com')
             ->issuedAt($time)
             ->notBefore($before)
             ->expireTime($expire)
             ->jwtId('12345')
             ->type('https://example.com/register');
        $result = $this->jwt->encode();
        $decode = $this->jwt->decode($result);

        $this->assertEquals((array) $decode, array(
            'iss' => 'http://example.org',
            'aud' => 'http://example.com',
            'iat' => $time,
            'nbf' => $before,
            'exp' => $expire,
            'jti' => '12345',
            'typ' => 'https://example.com/register',
        ));
    }

    public function testEncryptDecrypt()
    {
        $cipher = 'AES-256-CBC';
        $key    = 'my-encryption-key';
        $iv     = '1234567812345678';

        $time = time();
        $before = $time-1;
        $expire = $time+30;
        $this->jwt
             ->issuer('http://example.org')
             ->audience('http://example.com')
             ->issuedAt($time)
             ->notBefore($before)
             ->expireTime($expire)
             ->jwtId('12345')
             ->type('https://example.com/register');
        $result = $this->jwt->encrypt($cipher, $iv, $key);
        $decode = $this->jwt->decrypt($result, $cipher, $iv, $key);

        $this->assertEquals((array) $decode, array(
            'iss' => 'http://example.org',
            'aud' => 'http://example.com',
            'iat' => $time,
            'nbf' => $before,
            'exp' => $expire,
            'jti' => '12345',
            'typ' => 'https://example.com/register',
        ));
    }
}
