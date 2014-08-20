<?php

namespace SpomkyLabs\JOSE;

trait JWK
{
    /**
     * @param string $key
     */
    public function getValue($key)
    {
        return isset($this->values[$key]) ? $this->values[$key] : null;
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

    /**
     * @param string $key
     * @param string|false $value
     */
    public function setValue($key, $value)
    {
        $this->values[$key] = $value;

        return $this;
    }
}
