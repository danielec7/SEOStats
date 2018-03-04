<?php

namespace Ijanki\SEOStats\Mozscape;

use GuzzleHttp\ClientInterface;

/**
 * Class MozscapeClient
 * @package Ijanki\SEOStats\Mozscape
 */
class MozscapeClient
{
    /**
     * Endpoint for mozsscape url-metrics
     */
    const URL_METRICS = 'http://lsapi.seomoz.com/linkscape/url-metrics/';

    /**
     * @var ClientInterface
     */
    private $client;
    /**
     * @var string
     */
    private $accessID;
    /**
     * @var string
     */
    private $secretKey;

    /**
     * @var string
     */
    private $signature;
    /**
     * @var string
     */
    private $expires;

    /**
     * MozscapeClient constructor.
     * @param ClientInterface $client
     * @param string $accessID
     * @param string $secretKey
     */
    public function __construct(string $accessID, string $secretKey, ClientInterface $client = null)
    {
        $this->accessID = $accessID;
        $this->secretKey = $secretKey;
        if (null === $client) {
            $this->client = new \GuzzleHttp\Client();
        }
    }

    /**
     * @param $domains
     * @return array
     * @throws \Exception
     * @see https://moz.com/help/guides/moz-api/mozscape/api-reference/url-metrics
     */
    public function getFreeStats($domains): array
    {
        $cols = 1 + 4 + 32 + 128 + 512 + 1024 + 2048 + 16384 + 32768 + 536870912 + 34359738368 + 68719476736 + 144115188075855872;

        $metrics = $this->urlMetrics($domains, $cols);

        if (count($metrics) == 1) {

            return $metrics[0];
        }

        return $metrics;
    }

    /**
     * @param $domains
     * @return array
     * @throws \Exception
     */
    public function getDomainAuthority($domains)
    {
        $metrics = $this->urlMetrics($domains, '68719476736');

        if (count($metrics) == 1) {

            return $metrics[0]['pda'];
        }

        return $metrics;
    }

    /**
     * @param $domains
     * @param $cols
     * @return array
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    private function urlMetrics($domains, $cols): array
    {
        $this->updateSignature();

        if (!is_array($domains)) {
            $response = $this->client->request(
                'GET',
                self::URL_METRICS . $domains,
                [
                    'query' => [
                        'Cols' => $cols,
                        'AccessID' => $this->accessID,
                        'Expires' => $this->expires,
                        'Signature' => $this->signature,
                    ],
                ]
            );
        } else {
            $response = $this->client->request(
                'POST',
                self::URL_METRICS,
                [
                    'query' => [
                        'Cols' => $cols,
                        'AccessID' => $this->accessID,
                        'Expires' => $this->expires,
                        'Signature' => $this->signature,
                    ],
                    'body' => json_encode($domains),
                ]
            );
        }

        $result = json_decode((string)$response->getBody(), true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \Exception("Cannot parse Mozscape response");
        }

        return $result;
    }

    /**
     * Get auth signature
     */
    private function updateSignature()
    {
        // Set your expires times for several minutes into the future.
        // An expires time excessively far in the future will not be honored by the Mozscape API.
        $this->expires = time() + 300;

        // Put each parameter on a new line.
        $stringToSign = $this->accessID."\n".$this->expires;

        // Get the "raw" or binary output of the hmac hash.
        $binarySignature = hash_hmac('sha1', $stringToSign, $this->secretKey, true);

        // Base64-encode it and then url-encode that.
        $this->signature = base64_encode($binarySignature);
    }
}
