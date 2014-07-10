<?php

namespace Psecio\Jwt;

class Jwt
{
	private $claims;
	private $header;
	private $hashMethod = 'hmac';

	public function __construct(\Psecio\Jwt\Header $header, \Psecio\Jwt\ClaimsCollection $collection = null)
	{
		$this->setHeader($header);
		if ($collection == null) {
			$collection = new \Psecio\Jwt\ClaimsCollection();
		}
		$this->setClaims($collection);
	}

	public function setHeader(\Psecio\Jwt\Header $header)
	{
		$this->header = $header;
		return $this;
	}
	public function getHeader()
	{
		return $this->header;
	}

	public function addClaim(\Psecio\Jwt\Claims $claim)
	{
		$this->claims->add($claim);
		return $this;
	}
	public function getClaims()
	{
		return $this->claims;
	}
	public function setClaims(\Psecio\Jwt\ClaimsCollection $collection)
	{
		$this->claims = $collection;
		return $this;
	}

	public function encode($key)
	{
		$header = $this->getHeader();
		$sections = array(
			$this->base64Encode(json_encode($header->toArray())),
			$this->base64Encode(json_encode($this->getClaims()->toArray()))
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

		return implode('.', $sections);
	}

	public function decode($data, $key, $verify = true)
	{
		$sections = explode('.', $data);
		if (count($sections) < 3) {
			throw new \InvalidArgumentException('Invalid number of sections (<3)');
		}

		list($header, $claims, $signature) = $sections;

		$header = json_decode($this->base64Decode($header));
		$signature = $this->base64Decode($signature);
		$claims = json_decode($this->base64Decode($claims));

		if ($verify === true) {
			if ($this->verify($key, $header, $claims, $signature) === false){
				throw new \DomainException('Signature did not verify');
			}
		}

		return $claims;
	}

	public function verify($key, $header, $claims, $signature)
	{
		if (empty($header->alg)) {
			throw new \InvalidArgumentException('Invalid header: no algorithm specified');
		}
		if (isset($claims->exp) && $claims->exp <= time()) {
			throw new \InvalidArgumentException('Message has expired');
		}

		$algorithm = $header->alg;
		$signWith = implode('.', array(
			$this->base64Encode(json_encode($header)),
			$this->base64Encode(json_encode($claims))
		));
		return ($this->sign($signWith, $key, $algorithm) === $signature);
	}

	public function base64Encode($data)
	{
		return urlencode(str_replace('=', '', base64_encode($data)));
	}

	public function base64Decode($data)
	{
		$decoded = urldecode($data);

		// pad it out to a multiple of 4
		$decoded = str_pad(
			$decoded,
			4 - (strlen($decoded) % 4),
			'='
		);
		return base64_decode($decoded);
	}

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

	public function findAlgorithm($algorithm)
	{
		foreach ($this->hashTypes as $type => $hashAlgorithm) {
			if ($type == $algorithm) {
				return $hashAlgorithm;
			}
		}
		return false;
	}

	public function __call($name, $args)
	{
		// see if it matches one of our claim types
		$className = "\\Psecio\\Jwt\\Claims\\".ucwords($name);
		if (class_exists($className)) {
			$claim = new $className($args[0]);
			$this->addClaim($claim);
			return $this;
		} else {
			throw new \InvalidArgumentException('Invalid claim type "'.$name.'"');
		}
	}
}