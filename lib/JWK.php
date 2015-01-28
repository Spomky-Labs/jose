<?php

namespace SpomkyLabs\Jose;

use Jose\JWK as Base;

/**
 * Class JWK
 * @package SpomkyLabs\Jose
 */
class JWK extends Base
{
    /**
     * @var array
     */
    protected $values = array();

    /**
     * @return array
     */
    public function jsonSerialize()
    {
        return $this->getValues();
    }

    /**
     * @param  string $key
     * @return null
     */
    public function getValue($key)
    {
        return array_key_exists($key, $this->getValues()) ? $this->values[$key] : null;
    }

    /**
     * @return array
     */
    public function getValues()
    {
        return $this->values;
    }

    /**
     * @param  string $key
     * @param  mixed  $value
     * @return $this
     */
    public function setValue($key, $value)
    {
        $this->values[$key] = $value;

        return $this;
    }

    /**
     * @param  array $values
     * @return $this
     */
    public function setValues(array $values)
    {
        $this->values = $values;

        return $this;
    }
}
