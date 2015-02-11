<?php

namespace Psecio\Jwt\Claim;

/**
 * Claim type Issued At (iat)
 *
 * @package Jwt
 */
class IssuedAt extends \Psecio\Jwt\Claim
{
	protected $type = 'iat';
	protected $name = 'issuedAt';

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