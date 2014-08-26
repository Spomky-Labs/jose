<?php

namespace SpomkyLabs\JOSE\Tests\Algorithm;

trait JWK
{
    public function getValue($key)
    {
        return isset($this->values[$key]) ? $this->values[$key] : null;
    }

    public function setValue($key, $value)
    {
        if ($key === 'kty') {
            return $this;
        }
        $this->values[$key] = $value;

        return $this;
    }

    public function getValues()
    {
        return $this->values;
    }

    public function setValues(array $values)
    {
        if (isset($values['kty'])) {
            unset($values['kty']);
        }
        foreach ($values as $key => $value) {
            $this->setValue($key, $value);
        }

        return $this;
    }
}
