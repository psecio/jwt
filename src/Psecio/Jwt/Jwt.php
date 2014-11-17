<?php

namespace Psecio\Jwt;

class Jwt
{
	/**
	 * Set of claims for the current JWT object
	 * @var \Psecio\Jwt\ClaimsCollection
	 */
	private $claims;

	/**
	 * Current header for JWT object
	 * @var \Psecio\Jwt\Header
	 */
	private $header;

	/**
	 * Initialize the object and set the header and claims collection
	 *  Empty claims collection is set if none is given
	 *
	 * @param \Psecio\Jwt\Header $header Header instance to set on JWT object
	 * @param \Psecio\Jwt\ClaimsCollection $collection Claims collection [optional]
	 */
	public function __construct(\Psecio\Jwt\Header $header = null, \Psecio\Jwt\ClaimsCollection $collection = null)
	{
		if (!is_null($header)) {
			$this->setHeader($header);
		}

		if ($collection == null) {
			$collection = new \Psecio\Jwt\ClaimsCollection();
		}
		$this->setClaims($collection);
	}

	/**
	 * Set the header instance
	 *
	 * @param \Psecio\Jwt\Header $header [description]
	 * @return \Psecio\Jwt\Jwt Current Jwt instance
	 */
	public function setHeader(\Psecio\Jwt\Header $header)
	{
		$this->header = $header;
		return $this;
	}

	/**
	 * Get the currently assigned header instance
	 *
	 * @return \Psecio\Jwt\Header Header object instance
	 */
	public function getHeader()
	{
		return $this->header;
	}

	/**
	 * Add a Claim to the current collection
	 *
	 * @param \Psecio\Jwt\Claim $claim Claim instance to add
	 * @return \Psecio\Jwt\Jwt Current Jwt instance
	 */
	public function addClaim(\Psecio\Jwt\Claim $claim)
	{
		$this->claims->add($claim);
		return $this;
	}

	/**
	 * Get the current claims collection
	 *
	 * @return \Psecio\Jwt\ClaimsCollection instance
	 */
	public function getClaims()
	{
		return $this->claims;
	}

	/**
	 * Set the claims collection
	 *
	 * @param \Psecio\Jwt\ClaimsCollection $collection Claims collection instance
	 * @return \Psecio\Jwt\Jwt Current Jwt instance
	 */
	public function setClaims(\Psecio\Jwt\ClaimsCollection $collection)
	{
		$this->claims = $collection;
		return $this;
	}

	/**
	 * Encode the data, either given or from current object
	 *
	 * @param string $claims Claims string to encode [optional]
	 * @return string Encoded data, appended by periods
	 */
	public function encode($claims = null)
	{
		$header = $this->getHeader();

		$claims = ($claims !== null)
			? $claims
			: $this->base64Encode(
				json_encode($this->getClaims()->toArray(), JSON_UNESCAPED_SLASHES)
			);

		$sections = array(
			$this->base64Encode(json_encode($header->toArray(), JSON_UNESCAPED_SLASHES)),
			$claims
		);

		$signWith = implode('.', $sections);
		$signature = $this->sign(
			$signWith,
			$header->getKey(),
			$header->getAlgorithm()
		);

		if ($signature !== null) {
			$sections[] = $this->base64Encode($signature);
		}

		$result = implode('.', $sections);

		return $result;
	}

	/**
	 * Decode the data with the given key
	 *
	 * @throws Exception\DecodeException If invalid number of sections
	 * @throws Exception\BadSignatureException If signature doesn't verify
	 *
	 * @param string $data Data to decode (entire JWT data string)
	 * @param string $key
	 * @param boolean $verify Verify the signature on the data, defaults to true [optional]
	 * @param boolean $check Check all the claims are correct, defaults to true [optional]
	 * @return \stdClass Decoded claims data
	 */
	public function decode($data, $key, $verify = true, $check = true)
	{
		$sections = explode('.', $data);
		if (count($sections) < 3) {
			throw new Exception\DecodeException('Invalid number of sections (<3)');
		}

		list($header, $claims, $signature) = $sections;
		$signWith = $header . '.' . $claims;

		$header = json_decode($this->base64Decode($header));
		$claims = json_decode($this->base64Decode($claims));
		$signature = $this->base64Decode($signature);

		if ($verify === true) {
			$this->verify($signWith, $signature, $header, $key);
		}

		if ($check === true) {
			$this->check($claims);
		}

		return $claims;
	}

	/**
	 * Encrypt the data with the given key (and algorithm/IV)
	 *
	 * @param string $algorithm Algorithm to use for encryption
	 * @param string $iv IV for encrypting data
	 * @param string $key
	 * @throws \RuntimeException If OpenSSL is not enabled
	 * @return string Encrypted string
	 */
	public function encrypt($algorithm, $iv, $key)
	{
		if (!function_exists('openssl_encrypt')) {
			throw new \RuntimeException('Cannot encrypt data, OpenSSL not enabled');
		}

		$data = json_encode($this->getClaims()->toArray(), JSON_UNESCAPED_SLASHES);

		$claims = $this->base64Encode(openssl_encrypt(
			$data, $algorithm, $key, false, $iv
		));

		return $this->encode($claims, $key);
	}

	/**
	 * Decrypt given data wtih given key (and algorithm/IV)
	 *
	 * @throws \RuntimeException If OpenSSL is not installed
	 * @throws Exception\DecodeException If incorrect number of sections is provided
	 *
	 * @param string $data Data to decrypt
	 * @param string $algorithm Algorithm to use for decrypting the data
	 * @param string $iv
	 * @param string $key
	 * @return \stdClass Decrypted data
	 */
	public function decrypt($data, $algorithm, $iv, $key)
	{
		if (!function_exists('openssl_decrypt')) {
			throw new \RuntimeException('Cannot decrypt data, OpenSSL not enabled');
		}

		// First check the signature.
		$valid = $this->decode($data, $key, true, false);

		// Now decrypt the claims and check them (we can assume that data is valid now!)
		$sections = explode('.', $data);
		$claims = json_decode(openssl_decrypt(
			$this->base64Decode($sections[1]), $algorithm, $key, false, $iv
		));

		if ($this->check($claims)) {
			return $claims;
		}
	}

	/**
	 * Verifies that the data of the token matches the signature.
	 *
	 * @throws Exception\DecodeException If no algorithm is specified
	 *
	 * @param string $data
	 * @param strign $signature
	 * @param \stdClass $header
	 * @param string $key
	 * @return string
	 */
	public function verify($data, $signature, $header, $key)
	{
		if (empty($header->alg)) {
			throw new Exception\DecodeException('Invalid header: no algorithm specified');
		}

		// Create a Header class from the token header (if required)
		if (is_null($this->getHeader())) {
			$this->setHeader(new Header($key, $header->alg));
		}

		// Do the signatures match?
		if ($this->equals($signature, $this->sign($data, $key))) {
			return true;
		} else {
			throw new Exception\BadSignatureException('Signature did not verify');
		}
	}

	/**
	 * Check the claims to ensure the token is still valid.
	 *
	 * @throws Exception\ExpiredException If the message has expired
	 * @throws Exception\DecodeException If Audience is not defined
	 * @throws Exception\DecodeException Processing before time not allowed
	 *
	 * @param \stdClass $claims Set of claims
	 * @return boolean Pass/fail of verification
	 */
	public function check($claims)
	{
		if (!isset($claims->aud) || empty($claims->aud)) {
			throw new Exception\DecodeException('Audience not defined [aud]');
		}

		// If "expires at" defined, check against time
		if (isset($claims->exp) && $claims->exp <= time()) {
			throw new Exception\ExpiredException('Message has expired');
		}

		// If a "not before" is provided, validate the time
		if (isset($claims->nbf) && $claims->nbf > time()) {
			throw new Exception\DecodeException(
				'Cannot process prior to '.date('m.d.Y H:i:s', $claims->nbf).' [nbf]'
			);
		}

		return true;
	}

	/**
	 * Base64 encode data and prepare for the URL
	 *  NOTE: The "=" is removed as it's just padding in base64
	 *  and not needed.
	 *
	 * @param string $data Data string
	 * @return string Formatted data
	 */
	public function base64Encode($data)
	{
		return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
	}

	/**
	 * Base64 decode (and url decode) the given data
	 *
	 * @param string $data Data to decode
	 * @return string Decoded data
	 */
	public function base64Decode($data)
	{
		$decoded = str_pad(
			$data,
			4 - (strlen($data) % 4),
			'='
		);
		return base64_decode(strtr($decoded, '-_', '+/'));
	}

	/**
	 * Generate the signature with the given data, key and algorithm
	 *
	 * @param string $signWith Data to sign hash with
	 * @param string $key Key for signing
	 * @return string Generated signature hash
	 */
	public function sign($signWith, $key)
	{
		$signature = hash_hmac(
			$this->getHeader()->getAlgorithm(true),
			$signWith,
			$key,
			true
		);

		return $signature;
	}

	/**
     * A constant time equals function.
     *
     * @link https://github.com/firebase/php-jwt/blob/master/Authentication/JWT.php
	 * @param string $known
	 * @param string $generated
	 * @return boolean
	 */
	private function equals($known, $generated)
	{
		$len = min(strlen($known), strlen($generated));
		$status = 0;
		for ($i = 0; $i < $len; $i++) {
			$status |= (ord($known[$i]) ^ ord($generated[$i]));
		}
		$status |= (strlen($known) ^ strlen($generated));

		return $status === 0;
	}

	/**
	 * Magic method for setting claims by name
	 *  Ex. "issuedAt()" calls Claims\IssuedAt
	 *
	 * @throws \InvalidArgumentException If invalid claim type
	 *
	 * @param string $name Function name
	 * @param array $args Arguments to pass
	 * @return \Psecio\Jwt\Jwt instance
	 */
	public function __call($name, $args)
	{
		// see if it matches one of our claim types
		$className = "\\Psecio\\Jwt\\Claim\\".ucwords($name);
		if (class_exists($className)) {
			$type = (isset($args[1])) ? $args[1] : null;
			$claim = new $className($args[0], $type);
			$this->addClaim($claim);
			return $this;
		} else {
			throw new \InvalidArgumentException('Invalid claim type "'.$name.'"');
		}
	}
}
