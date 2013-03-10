<?php
/**
 * Google Authenticator Library
 *
 * @package SLT\GoogleAuthenticator
 * @author Andrew Moore <amoore@sidleetechnologies.com>
 * @copyright Copyright (c) 2013, Andrew Moore
 * @license MIT License - http://www.opensource.org/licenses/mit-license.php
 */
namespace SLT\GoogleAuthenticator;

use InvalidArgumentException;
use Rych\OTP\Seed;
use Rych\OTP\OTP;

/**
 * Factory methods for Google Authenticator instances
 *
 * @package SLT\GoogleAuthenticator
 * @author Andrew Moore <amoore@sidleetechnologies.com>
 */
final class Factory
{
    /**
     * Creates a new HOTP Google Authenticator
     *
     * @param string $label Desired Label
     * @return HOTP
     */
    public static function newEventBasedAuthenticator($label)
    {
        return new HOTP(self::generateSecret(), array(
            'label' => $label,
        ));
    }

    /**
     * Creates a new TOTP Google Authenticator
     *
     * @param string $label Desired Label
     * @return TOTP
     */
    public static function newTimeBasedAuthenticator($label)
    {
        return new TOTP(self::generateSecret(), array(
            'label' => $label,
        ));
    }

    /**
     * Generates a new random secret
     *
     * @return Seed The generated secret
     */
    private static function generateSecret()
    {
        return Seed::generate(8);
    }

    /**
     * Initializes an OTPAuth from the passed Uri
     *
     * @param string $uri Uri from which to create an instance from
     * @return OTP|IGoogleAuthenticator
     * @throws \InvalidArgumentException
     */
    public static function fromUri($uri)
    {
        $uriData = @parse_url($uri);

        if ($uriData === false ||
            !isset($uriData['scheme']) ||
            strtolower($uriData['scheme']) != 'otpauth' ||
            !isset($uriData['host']) ||
            !in_array(strtolower($uriData['host']), array('totp', 'hotp')) ||
            !isset($uriData['path']) ||
            !isset($uriData['query'])
        ) {
            throw new InvalidArgumentException('Invalid GAuth Uri');
        }

        $options = array(
            'label' => ltrim(urldecode($uriData['path']), '/')
        );

        $queryValues = array();
        parse_str($uriData['query'], $queryValues);
        array_change_key_case($queryValues, CASE_LOWER);

        $type = $uriData['host'];
        $period = 30;
        $digits = 6;
        $algorithm = 'sha1';

        $class = '\SLT\GoogleAuthenticator\HOTP';

        switch ($type) {
            case 'totp':
                $class = '\SLT\GoogleAuthenticator\TOTP';

                if (isset($queryValues['period'])) {
                    if (!is_numeric($queryValues['period'])) {
                        throw new InvalidArgumentException('Invalid GAuth Uri');
                    }

                    $period = intval($queryValues['period']);

                    if ($period < 1) {
                        throw new InvalidArgumentException('Invalid GAuth Uri');
                    }
                }

                $options['timestep'] = $period;
                break;

            case 'hotp':
                $class = '\SLT\GoogleAuthenticator\HOTP';

                if (!isset($queryValues['counter']) || !is_numeric($queryValues['counter'])) {
                    throw new InvalidArgumentException('Invalid GAuth Uri');
                }

                $options['counter'] = intval($queryValues['counter']);
                break;
        }

        if (isset($queryValues['digits'])) {
            $digits = $queryValues['digits'];

            if (!in_array($digits, array(6, 8))) {
                throw new InvalidArgumentException('Invalid GAuth Uri');
            }

            $digits = intval($digits);
        }

        $options['digits'] = $digits;

        if (isset($queryValues['algorithm'])) {
            $algorithm = strtolower($queryValues['algorithm']);

            if (!in_array($algorithm, array('sha1', 'sha256', 'sha512'))) {
                throw new InvalidArgumentException('Invalid GAuth Uri');
            }
        }

        $options['algorithm'] = $algorithm;

        $secret = new Seed();
        $secret->setValue($queryValues['secret'], Seed::FORMAT_BASE32);

        return new $class($secret, $options);
    }

    /**
     * Prevent class construction
     */
    private function __construct()
    {
    }
}