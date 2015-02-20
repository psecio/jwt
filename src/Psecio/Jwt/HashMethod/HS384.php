<?php

namespace Psecio\Jwt\HashMethod;

class HS384 extends \Psecio\Jwt\HashMethod
{
	protected $keyType = 'HMAC';

	public function getAlgorithm()
	{
		return 'SHA384';
	}
}