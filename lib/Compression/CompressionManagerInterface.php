<?php

namespace SpomkyLabs\JOSE\Compression;

/**
 * This interface is used by all compression methods
 */
interface CompressionManagerInterface
{
    /**
     * This method will try to fing an CompressionInterface object able to support the compression method
     *
     * @param  string                    $name The name of the compression method
     * @return CompressionInterface|null If the compression method is supported, return CompressionInterface object, else null
     */
    public function getCompressionMethod($name);
}
