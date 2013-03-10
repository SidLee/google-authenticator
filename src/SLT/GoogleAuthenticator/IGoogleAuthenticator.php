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

/**
 * Interface defining various methods related to the Google Authenticator framework
 *
 * @package SLT\GoogleAuthenticator
 * @author Andrew Moore <amoore@sidleetechnologies.com>
 */
interface IGoogleAuthenticator
{
    /**
     * Gets the label (display name) of this authenticator
     *
     * @return string
     */
    public function getLabel();

    /**
     * Sets the label of this authenticator
     *
     * @param string $label The label of this authenticator
     * @return void
     */
    public function setLabel($label);

    /**
     * Gets the Uri representing this authenticator
     *
     * @param bool $includeDefaultValues Set this to true to include default values
     * @return string The Uri representing this authenticator
     */
    public function toUri($includeDefaultValues = false);
}