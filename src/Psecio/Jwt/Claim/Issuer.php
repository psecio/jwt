<?php

namespace Psecio\Jwt\Claim;

/**
 * Claim type Issuer (iss)
 *
 * @package Jwt
 */
class Issuer extends \Psecio\Jwt\Claim
{
	protected $type = 'iss';
    protected $name = 'issuer';
}