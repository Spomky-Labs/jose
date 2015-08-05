<?php

namespace SpomkyLabs\Jose;

use Jose\JWAManager as Base;
use Jose\JWAInterface;

/**
 * Class JWAManager.
 */
class JWAManager extends Base
{
    /**
     * @var array
     */
    protected $algorithms = array();

    /**
     * {@inheritdoc}
     */
    public function getAlgorithms()
    {
        return $this->algorithms;
    }

    /**
     * {@inheritdoc}
     */
    public function listAlgorithms()
    {
        return array_keys($this->getAlgorithms());
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithm($algorithm)
    {
        return array_key_exists($algorithm, $this->algorithms) ? $this->algorithms[$algorithm] : null;
    }

    /**
     * @param JWAInterface $algorithm
     *
     * @return $this
     */
    public function addAlgorithm(JWAInterface $algorithm)
    {
        if (!$this->isAlgorithmSupported($algorithm->getAlgorithmName())) {
            $this->algorithms[$algorithm->getAlgorithmName()] = $algorithm;
        }

        return $this;
    }

    /**
     * @param string $algorithm
     *
     * @return $this
     */
    public function removeAlgorithm($algorithm)
    {
        if ($algorithm instanceof JWAInterface) {
            $name = $algorithm->getAlgorithmName();
        } elseif (is_string($algorithm)) {
            $name = $algorithm;
        } else {
            throw new \InvalidArgumentException('Argument must be a string or a JWAInterface object.');
        }
        if (array_key_exists($name, $this->algorithms)) {
            unset($this->algorithms[$name]);
        }

        return $this;
    }
}
