<?php

namespace SpomkyLabs\JOSE\Tests\Stub;

use SpomkyLabs\JOSE\JWKSet as Base;
use SpomkyLabs\JOSE\JWKInterface;

/**
 * Class representing a JWK Set.
 */
class JWKSet extends Base
{
    private $keys = array();

    public function getKeys()
    {
        return $this->keys;
    }

    /**
     * Set keys in the Key Set
     * @param array $keys An array with JWKInterface objects
     */
    public function setKeys(array $keys)
    {
        $this->keys = $keys;

        return $this;
    }

    /**
     * Set keys in the Key
     * @param JWKInterface $key A JWKInterface objects
     */
    public function addKey(JWKInterface $key)
    {
        $this->keys[] = $key;

        return $this;
    }

    public function isEmpty()
    {
        return count($this->keys) === 0;
    }
}
