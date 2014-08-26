<?php

namespace SpomkyLabs\JOSE;

/**
 * This interface is used by all compression methods
 */
interface CompressionManagerInterface
{
    /**
     * @param  string               $name The name of the compression method
     * @return CompressionInterface
     */
    public function getCompressionMethod($name);
}
