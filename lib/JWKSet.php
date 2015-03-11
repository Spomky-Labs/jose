<?php

namespace SpomkyLabs\Jose;

use Jose\JWKSet as Base;
use Jose\JWKInterface;

/**
 * Class JWKSet.
 */
class JWKSet extends Base
{
    /**
     * @var array
     */
    protected $keys = array();

    /**
     * @return array
     */
    public function getKeys()
    {
        return $this->keys;
    }

    /**
     * Set keys in the Key.
     *
     * @param JWKInterface $key A JWKInterface objects
     */
    public function addKey(JWKInterface $key)
    {
        $this->keys[] = $key;

        return $this;
    }

    /**
     * @param $key
     *
     * @return $this
     */
    public function removeKey($key)
    {
        if (isset($this->keys[$key])) {
            unset($this->keys[$key]);
        }

        return $this;
    }
}
