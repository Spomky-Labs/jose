<?php

namespace SpomkyLabs\JOSE;

class JWKSet implements JWKSetInterface
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
        return count($this->getKeys()) === 0;
    }

    public function __toString()
    {
        $keys = $this->getKeys();
        $result = array(
            'keys'=>array(),
        );
        foreach ($keys as $key) {
            $result['keys'][] = $key->getValues();
        }

        return json_encode($result);
    }
}
