<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Test\Stub;

use Psr\Log\LoggerInterface;

/**
 */
class FakeLogger implements LoggerInterface
{
    /**
     * @var array
     */
    private $messages = [];

    /**
     * {@inheritdoc}
     */
    public function emergency($message, array $context = array())
    {
        $this->log('emergency', $message, $context);
    }

    /**
     * {@inheritdoc}
     */
    public function alert($message, array $context = array())
    {
        $this->log('alert', $message, $context);
    }

    /**
     * {@inheritdoc}
     */
    public function critical($message, array $context = array())
    {
        $this->log('critical', $message, $context);
    }

    /**
     * {@inheritdoc}
     */
    public function error($message, array $context = array())
    {
        $this->log('error', $message, $context);
    }

    /**
     * {@inheritdoc}
     */
    public function warning($message, array $context = array())
    {
        $this->log('warning', $message, $context);
    }

    /**
     * {@inheritdoc}
     */
    public function notice($message, array $context = array())
    {
        $this->log('notice', $message, $context);
    }

    /**
     * {@inheritdoc}
     */
    public function info($message, array $context = array())
    {
        $this->log('info', $message, $context);
    }

    /**
     * {@inheritdoc}
     */
    public function debug($message, array $context = array())
    {
        $this->log('debug', $message, $context);
    }

    /**
     * {@inheritdoc}
     */
    public function log($level, $message, array $context = array())
    {
        $this->messages[] = [
            'timestamp' => microtime(true),
            'level'     => $level,
            'message'   => $message,
            'context'   => $context,
        ];
    }

    /**
     * @return array
     */
    public function getMessages()
    {
        return $this->messages;
    }
}
