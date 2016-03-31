<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Behaviour;

use Psr\Log\LoggerInterface;

trait HasLogger
{
    /**
     * @var \Psr\Log\LoggerInterface
     */
    private $logger;

    /**
     * @return \Psr\Log\LoggerInterface
     */
    private function getLogger()
    {
        return $this->logger;
    }

    /**
     * @param \Psr\Log\LoggerInterface $logger
     */
    private function setLogger(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    /**
     * Logs with an arbitrary level.
     *
     * @param mixed  $level
     * @param string $message
     * @param array  $context
     *
     * @return null
     */
    private function log($level, $message, array $context = [])
    {
        if (null !== $this->logger) {
            $this->getLogger()->log($level, $message, $context);
        }
    }
}
