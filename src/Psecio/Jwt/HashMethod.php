<?php

namespace Psecio\Jwt;

abstract class HashMethod
{
    abstract public function getAlgorithm();

    public function isValidKey($key)
    {
        // If it's a resource, ensure we can get the key from it
        if (is_resource($key) === false) {
            $key = openssl_pkey_get_public($key) ?: openssl_pkey_get_private($key);
            if (!$key) {
               return false;
            }
        }
        $details = openssl_pkey_get_details($key);
        return (isset($details['key'])) ? $this->getKeyType() === $details['type'] : false;
    }

    public function getKeyType()
    {
        return $this->keyType;
    }
}