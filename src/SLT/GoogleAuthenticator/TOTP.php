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

use Rych\OTP\TOTP as TOTPBase;
use Rych\OTP\Seed;
use SLT\GoogleAuthenticator\Tools\UriTools;

/**
 * Event-Based Google Authenticator
 *
 * @package SLT\GoogleAuthenticator
 * @author Andrew Moore <amoore@sidleetechnologies.com>
 */
class TOTP extends TOTPBase implements IGoogleAuthenticator
{
    /** @var string The label of this authenticator */
    protected $label;

    /**
     * Class constructor
     *
     * @param string|\Rych\OTP\Seed $secret The shared secret key as a string or
     * an instance of {@link \Rych\OTP\Seed}
     * @param array $options An array of configuration options.
     * @return \SLT\GoogleAuthenticator\TOTP
     */
    public function __construct($secret, array $options = array())
    {
        $options = array_merge(
            array(
                'label' => 'Google Event-Based Authenticator'
            ),
            array_change_key_case($options, CASE_LOWER)
        );

        $this->setLabel($options['label']);

        parent::__construct($secret, $options);
    }


    /**
     * Gets the label (display name) of this authenticator
     *
     * @return string
     */
    public function getLabel()
    {
        return $this->label;
    }

    /**
     * Sets the label of this authenticator
     *
     * @param string $label The label of this authenticator
     * @return void
     */
    public function setLabel($label)
    {
        $this->label = $label;
    }

    /**
     * Gets the Uri representing this authenticator
     *
     * @param bool $includeDefaultValues Set this to true to include default values
     * @return string The Uri representing this authenticator
     */
    public function toUri($includeDefaultValues = false)
    {
        /** @var $secret Seed */
        $secret = $this->getSecret();

        return UriTools::createUriFromParams(
            'totp',
            $this->label,
            array(
                'secret'    => $secret->getValue(Seed::FORMAT_BASE32),
                'algorithm' => $this->getHashFunction(),
                'digits'    => $this->getDigits(),
                'period'    => $this->getTimeStep()
            ),
            $includeDefaultValues
        );
    }
}