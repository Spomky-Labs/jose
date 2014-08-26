<?php

namespace SpomkyLabs\JOSE;

/**
 * This interface is used by all compression methods
 */
interface CompressionInterface
{
    /**
     * @return string
     */
    public function getMethod();

    /**
     * @return string
     */
    public function compress($data);

    /**
     * @return string
     */
    public function uncompress($data);
}
