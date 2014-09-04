<?php

namespace SpomkyLabs\JOSE\Compression;

/**
 * This interface is used by all compression methods
 */
interface CompressionInterface
{
    /**
     * @return boolean Return the name of the method supported
     */
    public function getMethod();

    /**
     * Compress the data
     * @param  string $data The data to compress
     * @return string The compressed data
     */
    public function compress($data);

    /**
     * Uncompress the data
     * @param  string $data The data to uncompress
     * @return string The uncompressed data
     */
    public function uncompress($data);
}
