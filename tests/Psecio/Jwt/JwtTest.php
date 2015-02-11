<?php

namespace Psecio\Jwt;

require_once "ClaimStub.php";

class JwtTest extends \PHPUnit_Framework_TestCase
{
    /**
     * Test the getter/setter for the Header instance
     */
    public function testGetSetHeader()
    {
        $header = new Header('test');
        $jwt = new Jwt($header);
        $this->assertSame($jwt->getHeader(), $header);

        $header = new Header('test', 'HS384');
        $jwt->setHeader($header);
        $this->assertSame($jwt->getHeader(), $header);
    }

    /**
     * Testing the getter/setter for the Claims data
     */
    public function testGetSetClaimsCollection()
    {
        $claims = new ClaimsCollection();
        $claim = new \Psecio\Jwt\ClaimStub('test1234');
        $claims->add($claim);

        $header = new Header('test');
        $jwt = new Jwt($header, $claims);

        $this->assertEquals(count($claims), 1);
        $this->assertSame($jwt->getClaims(), $claims);
    }

    /**
     * Testing the addition of a claim via the JWT class
     */
    public function testAddClaim()
    {
        $header = new Header('test');
        $jwt = new Jwt($header);

        $claim = new \Psecio\Jwt\ClaimStub('test1234');
        $jwt->addClaim($claim);

        $this->assertEquals(count($jwt->getClaims()), 1);
    }

    /**
     * Testing the custom base64 encoding
     */
    public function testBase64Encode()
    {
        $string = 'this is my + string !@#$';
        $header = new Header('test');
        $jwt = new Jwt($header);

        $result = $jwt->base64Encode($string);
        $this->assertEquals($result, 'dGhpcyBpcyBteSArIHN0cmluZyAhQCMk');
    }

    /**
     * Testing the custom base64 decoding
     */
    public function testBase64Decode()
    {
        $string = 'dGhpcyBpcyBteSArIHN0cmluZyAhQCMk';
        $header = new Header('test');
        $jwt = new Jwt($header);

        $result = $jwt->base64Decode($string);
        $this->assertEquals($result, 'this is my + string !@#$');
    }

    /**
     * Testing the results of the custom hash_equals function
     */
    public function testHashEquals()
    {
        $hash1 = md5(mt_rand());
        $header = new Header('test');
        $jwt = new Jwt($header);

        $this->assertTrue($jwt->hash_equals($hash1, $hash1));
        $this->assertFalse($jwt->hash_equals($hash1, 'badhash'));
    }

    /**
     * Test the encoding of some data into the JWT format
     */
    public function testEncodeJwtData()
    {
        $header = new Header('test');
        $jwt = new Jwt($header);

        $jwt
            ->issuer('http://example.org')
            ->audience('http://example.com')
            ->issuedAt(1356999524)
            ->notBefore(1357000000)
            ->expireTime(time()+3600)
            ->jwtId('id123456')
            ->type('https://example.com/register')
            ->custom('test', 'claim1');

        $result = $jwt->encode();
        $parts = explode('.', $result);

        $this->assertEquals($parts[0], 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9');
        $this->assertTrue(strstr($parts[1], 'eyJpc3MiOiJodHRwOi8vZXhhbXBsZS5vcmciLCJhdWQiOiJodHRwOi8v') !== false);
    }

    /**
     * Test the decoding of a valid JWT token
     */
    public function testDecodeJwtDataValid()
    {
        $header = new Header('test');
        $jwt = new Jwt($header);

        $jwt
            ->issuer('http://example.org')
            ->audience('http://example.com')
            ->issuedAt(1356999524)
            ->notBefore(1357000000)
            ->expireTime(time()+3600)
            ->jwtId('id123456')
            ->type('https://example.com/register')
            ->custom('test', 'claim1');

        $result = $jwt->encode();
        $decoded = $jwt->decode($result);

        $this->assertEquals($decoded->iss, 'http://example.org');
        $this->assertEquals($decoded->typ, 'https://example.com/register');
    }

    /**
     * Test the decoding of an invalid token signature
     * @expectedException \Psecio\Jwt\Exception\BadSignatureException
     */
    public function testDecodeJwtDataInvalidSignature()
    {
        $header = new Header('test');
        $jwt = new Jwt($header);

        $jwt
            ->issuer('http://example.org')
            ->audience('http://example.com');

        $result = $jwt->encode();
        $result = substr($result, 0, strlen($result) - 10);

        $decoded = $jwt->decode($result);
    }

        /**
     * Test the decoding of an invalid token
     * @expectedException \Psecio\Jwt\Exception\DecodeException
     */
    public function testDecodeJwtDataInvalidSections()
    {
        $header = new Header('test');
        $jwt = new Jwt($header);

        $jwt
            ->issuer('http://example.org')
            ->audience('http://example.com');

        $result = $jwt->encode();
        $result = substr($result, 0, strlen($result) - 100);

        $decoded = $jwt->decode($result);
    }
}