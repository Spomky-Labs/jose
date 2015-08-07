<?php

namespace SpomkyLabs\Jose\Payload;

class PayloadConverterManager implements PayloadConverterManagerInterface
{
    /**
     * @var \SpomkyLabs\Jose\Payload\PayloadConverterInterface[]
     */
    private $converters = array();

    /**
     * @return \SpomkyLabs\Jose\Payload\PayloadConverterInterface[]
     */
    private function getConverters()
    {
        return $this->converters;
    }

    /**
     * {@inheritdoc}
     */
    public function addConverter(PayloadConverterInterface $converter)
    {
        $this->converters[] = $converter;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function convertPayloadToString(array &$header, $payload)
    {
        foreach ($this->getConverters() as $converter) {
            $header = array();
            if ($converter->isPayloadToStringSupported($header, $payload)) {
                return $converter->convertPayloadToString($header, $payload);
            }
        }
        $result = json_encode($payload);
        if (false !== $result) {
            return $result;
        }
        throw new \InvalidArgumentException('Unsupported input type.');
    }

    /**
     * {@inheritdoc}
     */
    public function convertStringToPayload(array $header, $content)
    {
        foreach ($this->getConverters() as $converter) {
            if ($converter->isStringToPayloadSupported($header, $content)) {
                return $converter->convertStringToPayload($header, $content);
            }
        }

        $result = json_decode($content, true);
        if (is_null($result) && json_encode(null) !== $content) {
            return $content;
        }

        return $result;
    }
}
