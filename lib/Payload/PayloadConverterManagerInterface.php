<?php

namespace SpomkyLabs\Jose\Payload;

interface PayloadConverterManagerInterface
{
    /**
     * @param \SpomkyLabs\Jose\Payload\PayloadConverterInterface $converter
     *
     * @return $this
     */
    public function addConverter(PayloadConverterInterface $converter);

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
