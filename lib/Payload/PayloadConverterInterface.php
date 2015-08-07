<?php

namespace SpomkyLabs\Jose\Payload;

interface PayloadConverterInterface
{
    /**
     * @param array $header
     * @param mixed $payload
     *
     * @return bool
     */
    public function isPayloadToStringSupported(array $header, $payload);

    /**
     * @param array  $header
     * @param string $content
     *
     * @return bool
     */
    public function isStringToPayloadSupported(array $header, $content);

    /**
     * @param array $header
     * @param mixed $payload
     *
     * @return string
     */
    public function convertPayloadToString(array &$header, $payload);

    /**
     * @param array  $header
     * @param string $content
     *
     * @return mixed
     */
    public function convertStringToPayload(array $header, $content);
}
