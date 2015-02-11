<?php

namespace Psecio\Jwt\Claim;

/**
 * Claim type Expire Time (exp)
 *
 * @package Jwt
 */
class ExpireTime extends \Psecio\Jwt\Claim
{
	protected $type = 'exp';
	protected $name = 'expireTime';

	/**
	 * Validate the Issued At data
	 *
	 * @param string $value Claim data
	 * @return boolean Pass/fail of validation
	 */
	public function validate($value)
	{
		if (!is_numeric($value)) {
			return false;
		}
		return true;
	}
}