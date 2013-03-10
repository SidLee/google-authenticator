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

use Rych\OTP\HOTP as HOTPBase;
use Rych\OTP\Seed;
use SLT\GoogleAuthenticator\Tools\UriTools;

/**
 * Event-Based Google Authenticator
 *
 * @package SLT\GoogleAuthenticator
 * @author Andrew Moore <amoore@sidleetechnologies.com>
 */
class HOTP extends HOTPBase implements IGoogleAuthenticator
{
    /** @var string The label of this authenticator */
    protected $label;

    /** @var int Current counter */
    protected $counter;

    /**
     * Class constructor
     *
     * @param string|\Rych\OTP\Seed $secret The shared secret key as a string or
     * an instance of {@link \Rych\OTP\Seed}
     * @param array $options An array of configuration options.
     * @return \SLT\GoogleAuthenticator\HOTP
     */
    public function __construct($secret, array $options = array())
    {
        $options = array_merge(
            array(
                'label'   => 'Google Event-Based Authenticator',
                'counter' => 0
            ),
            array_change_key_case($options, CASE_LOWER)
        );

        $this->setLabel($options['label']);
        $this->setCounter($options['counter']);

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
     * Gets the counter value of this authenticator
     *
     * @return string
     */
    public function getCounter()
    {
        return $this->label;
    }

    /**
     * Sets the counter value of this authenticator
     *
     * @param string $label The label of this authenticator
     * @return void
     */
    public function setCounter($label)
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
            'hotp',
            $this->label,
            array(
                'secret'    => $secret->getValue(Seed::FORMAT_BASE32),
                'algorithm' => $this->getHashFunction(),
                'digits'    => $this->getDigits(),
                'counter'   => $this->getCounter()
            ),
            $includeDefaultValues
        );
    }

    /**
     * Validate an OTP
     *
     * @param string $otp The OTP value.
     * @param null|integer $counter The counter value. Defaults to $this->getCounter().
     * @return boolean Returns true if the supplied counter value is valid
     *     within the configured counter window, false otherwise.
     */
    public function validate($otp, $counter = null)
    {
        if ($counter === null) {
            $counter = $this->getCounter();
        }

        return parent::validate($otp, $counter);
    }

    /**
     * Generate a one-time password from a given counter value
     *
     * @param null|integer $counter The counter value. Defaults to $this->getCounter().
     * @return string Returns the generated one-time password.
     */
    public function calculate($counter = null)
    {
        if ($counter === null) {
            $counter = $this->getCounter();
        }

        return parent::calculate($counter);
    }


}