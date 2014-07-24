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

	private $encryptAlgorithm;
	private $encryptIv;

	/**
	 * Initialize the object and set the header and claims collection
	 * 	Empty claims collection is set if none is given
	 *
	 * @param \Psecio\Jwt\Header $header Header instance to set on JWT object
	 * @param \Psecio\Jwt\ClaimsCollection $collection Claims collection [optional]
	 */
	public function __construct(\Psecio\Jwt\Header $header, \Psecio\Jwt\ClaimsCollection $collection = null)
	{
		$this->setHeader($header);
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

	public function getEncryptAlgorithm()
	{
		return $this->encryptAlgorithm;
	}

	public function getEncryptIv()
	{
		return $this->encryptIv;
	}

	public function setEncryptionAlgorithm($algorithm)
	{
		$this->encryptAlgorithm = $algorithm;
		return $this;
	}

	public function setEncryptionIv($iv)
	{
		$this->encryptIv = $iv;
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
			? $claims : $this->base64Encode(json_encode($this->getClaims()->toArray()));

		$sections = array(
			$this->base64Encode(json_encode($header->toArray())),
			$claims
		);
		$key = $this->getHeader()->getKey();

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
	 * 	Optional "verify" parameter validates the signature as well (default is on)
	 *
	 * @param string $data Data to decode (entire JWT data string)
	 * @param boolean $verify Verify the signature on the data [optional]
	 * @throws \InvalidArgumentException If invalid number of sections
	 * @throws \DomainException If signature doesn't verify
	 * @return \stdClass Decoded claims data
	 */
	public function decode($data, $verify = true)
	{
		$sections = explode('.', $data);
		if (count($sections) < 3) {
			throw new \InvalidArgumentException('Invalid number of sections (<3)');
		}

		list($header, $claims, $signature) = $sections;
		$header = json_decode($this->base64Decode($header));
		$claims = json_decode($this->base64Decode($claims));
		$signature = $this->base64Decode($signature);
		$key = $this->getHeader()->getKey();

		if ($verify === true) {
			if ($this->verify($key, $header, $claims, $signature) === false){
				throw new \DomainException('Signature did not verify');
			}
		}

		return $claims;
	}

	/**
	 * Encrypt the data with the given key (and algorithm/IV)
	 *
	 * @param string $algorithm Algorithm to use for encryption
	 * @param string $iv IV for encrypting data
	 * @throws \DomainException If OpenSSL is not enabled
	 * @return string Encrypted string
	 */
	public function encrypt($algorithm, $iv)
	{
		if (!function_exists('openssl_encrypt')) {
			throw new \DomainException('Cannot encrypt data, OpenSSL not enabled');
		}

		$key = $this->getHeader()->getKey();
		$data = json_encode($this->getClaims()->toArray());

		$claims = $this->base64Encode(openssl_encrypt(
			$data, $algorithm, $key, false, $iv
		));

		return $this->encode($claims);
	}

	/**
	 * Decrypt given data wtih given key (and algorithm/IV)
	 *
	 * @param string $data Data to decrypt
	 * @param string $algorithm Algorithm to use for decrypting the data
	 * @param string $iv
	 * @throws \DomainException If OpenSSL is not installed
	 * @throws \InvalidArgumentException If incorrect number of sections is provided
	 * @return string Decrypted data
	 */
	public function decrypt($data, $algorithm, $iv)
	{
		if (!function_exists('openssl_encrypt')) {
			throw new \DomainException('Cannot encrypt data, OpenSSL not enabled');
		}

		// Decrypt just the claims
		$sections = explode('.', $data);
		if (count($sections) < 3) {
			throw new \InvalidArgumentException('Invalid number of sections (<3)');
		}

		$key = $this->getHeader()->getKey();
		$claims = openssl_decrypt(
			$this->base64Decode($sections[1]), $algorithm, $key, false, $iv
		);

		return json_decode($claims);
	}

	/**
	 * Verify the signature on the JWT message
	 *
	 * @param string $key Key used for hashing
	 * @param \stdClass $header Header data (object)
	 * @param \stdClass $claims Set of claims
	 * @param string $signature Signature string
	 * @throws \InvalidArgumentException If no algorithm is specified
	 * @throws \InvalidArgumentException If the message has expired
	 * @throws \DomainException If Audience is not defined
	 * @throws \DomainException Processing before time not allowed
	 * @return boolean Pass/fail of verification
	 */
	public function verify($key, $header, $claims, $signature)
	{
		if (empty($header->alg)) {
			throw new \InvalidArgumentException('Invalid header: no algorithm specified');
		}

		if (!isset($claims->aud) || empty($claims->aud)) {
			throw new \DomainException('Audience not defined [aud]');
		}

		// If "expires at" defined, check against time
		if (isset($claims->exp) && $claims->exp <= time()) {
			throw new \InvalidArgumentException('Message has expired');
		}

		// If a "not before" is provided, validate the time
		if (isset($claims->nbf) && $claims->nbf > time()) {
			throw new \DomainException(
				'Cannot process prior to '.date('m.d.Y H:i:s', $claims->nbf).' [nbf]'
			);
		}

		$algorithm = $header->alg;
		$signWith = implode('.', array(
			$this->base64Encode(json_encode($header)),
			$this->base64Encode(json_encode($claims))
		));
		return ($this->sign($signWith, $key, $algorithm) === $signature);
	}

	/**
	 * Base64 encode data and prepare for the URL
	 * 	NOTE: The "=" is removed as it's just padding in base64
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
	 * @param string $algorithm Algorithm type
	 * @return string Generated signature hash
	 */
	public function sign($signWith, $key, $algorithm)
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
	 * Magic method for setting claims by name
	 * 	Ex. "issuedAt()" calls Claims\IssuedAt
	 *
	 * @param string $name Function name
	 * @param array $args Arguments to pass
	 * @throws \InvalidArgumentException If invalid claim type
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