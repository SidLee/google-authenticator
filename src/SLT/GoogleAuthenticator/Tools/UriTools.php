<?php
/**
 * Google Authenticator Library
 *
 * @package SLT\GoogleAuthenticator
 * @author Andrew Moore <amoore@sidleetechnologies.com>
 * @copyright Copyright (c) 2013, Andrew Moore
 * @license MIT License - http://www.opensource.org/licenses/mit-license.php
 */
namespace SLT\GoogleAuthenticator\Tools;

use InvalidArgumentException;

/**
 * Common code for creating a GAuth Uri
 *
 * @package SLT\GoogleAuthenticator\Tools
 * @author Andrew Moore <amoore@sidleetechnologies.com>
 */
final class UriTools
{
    /**
     * @var array Default Uri Values
     */
    private static $defaultValues = array(
        'algorithm' => 'SHA1',
        'digits'    => 6,
        'period'    => 30,
    );

    /**
     * @param string $authType Authenticator Type
     * @param string $label Label of the authenticator
     * @param array $parameters Array of additional parameters
     * @param bool $includeDefaultValues Set this to true to include default values
     * @return string
     * @throws \InvalidArgumentException
     */
    public static function createUriFromParams($authType, $label, $parameters, $includeDefaultValues = false)
    {
        if (!in_array($authType, array('hotp', 'totp'))) {
            throw new InvalidArgumentException(sprintf(
                'Invalid value for $authType, got "%s", expecting either "hotp" or "totp"',
                $authType
            ));
        } elseif ($authType == 'hotp' && !isset($parameters['counter'])) {
            throw new InvalidArgumentException('Missing REQUIRED parameter "counter" for $authType "hotp"');
        }

        if (isset($parameters['algorithm'])) {
            $parameters['algorithm'] = strtoupper($parameters['algorithm']);
        }

        $uri = sprintf('otpauth://%s/%s?', $authType, rawurlencode($label));

        if ($includeDefaultValues === false) {
            foreach (static::$defaultValues as $key => $value) {
                if (!isset($parameters[$key])) {
                    continue;
                }

                if ($parameters[$key] == $value) {
                    unset($parameters[$key]);
                }
            }
        }

        $uri .= http_build_query($parameters);

        return $uri;
    }

    /**
     * Prevent class construction
     */
    private function __construct()
    {
    }
}