<?php

namespace SpomkyLabs\JOSE\Tests\Algorithm;

trait JWK
{
    protected $values = array();
    
    public function getValue($key)
    {
        return isset($this->values[$key]) ? $this->values[$key] : null;
    }

    public function setValue($key, $value)
    {
        $this->values[$key] = $value;

        return $this;
    }

    public function getValues()
    {
        return $this->values;
    }

    public function setValues(array $values)
    {
        $this->values = $values;

        return $this;
    }
}
