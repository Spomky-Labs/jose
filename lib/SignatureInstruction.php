<?php

namespace SpomkyLabs\Jose;

use Jose\JWKInterface;
use Jose\SignatureInstructionInterface;

/**
 * Class SignatureInstruction
 * @package SpomkyLabs\Jose
 */
class SignatureInstruction implements SignatureInstructionInterface
{
    /**
     * @var null|\Jose\JWKInterface
     */
    protected $key = null;
    /**
     * @var array
     */
    protected $protected_header = array();
    /**
     * @var array
     */
    protected $unprotected_header = array();

    /**
     * @param  JWKInterface $key
     * @return $this
     */
    public function setKey(JWKInterface $key)
    {
        $this->key = $key;

        return $this;
    }

    /**
     * @return null
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * @param  array $protected_header
     * @return $this
     */
    public function setProtectedHeader(array $protected_header)
    {
        $this->protected_header = $protected_header;

        return $this;
    }

    /**
     * @return array
     */
    public function getProtectedHeader()
    {
        return $this->protected_header;
    }

    /**
     * @param  array $unprotected_header
     * @return $this
     */
    public function setUnprotectedHeader(array $unprotected_header)
    {
        $this->unprotected_header = $unprotected_header;

        return $this;
    }

    /**
     * @return array
     */
    public function getUnprotectedHeader()
    {
        return $this->unprotected_header;
    }
}
