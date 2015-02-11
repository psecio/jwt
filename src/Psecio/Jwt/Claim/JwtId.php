<?php

namespace Psecio\Jwt\Claim;

/**
 * Claim type JwtId (jti)
 *
 * @package Jwt
 */
class JwtId extends \Psecio\Jwt\Claim
{
	protected $type = 'jti';
    protected $name = 'jwtId';
}