<?php

namespace IsEmail;

/**
 * EmailValidator
 *
 * @author Eduardo Gulias Davis <me@egulias.com>
 */
class EmailValidator
{

    protected $parser;
    protected $warnings = array();
    protected $error;
    protected $threshold = 70;
    protected $emailParts = array();

    public function __construct()
    {
        $this->parser = new EmailParser(new EmailLexer());
    }

    public function isValid($email, $checkDNS = false, $strict = false)
    {
        try {
            $this->parser->parse((string)$email);
            $this->emailParts = explode('@', $email);
            $this->warnings = $this->parser->getWarnings();
        } catch (\Exception $e) {
            return false;
        }

        if ($checkDNS) {
            $dns = $this->checkDNS();
        }
        if ($this->hasWarnings() && ((int) max($this->warnings) > $this->threshold)) {
            $this->error = "ERR_DEPREC_REACHED";
            return false;
        }

        return ($strict) ? (!$this->hasWarnings() && $dns) : true;
    }

    /**
     * hasWarnings
     *
     * @return boolean
     */
    public function hasWarnings()
    {
        return !empty($this->warnings);
    }

    /**
     * getWarnings
     *
     * @return array
     */
    public function getWarnings()
    {
        return $this->warnings;
    }

    /**
     * getError
     *
     * @return string
     */
    public function getError()
    {
        return $this->error;
    }

    /**
     * setThreshols
     *
     * @param int $threshold
     *
     * @return EmailValidator
     */
    public function setThreshold($threshold)
    {
        $this->threshold = (int) $threshold;

        return $this;
    }

    /**
     * getThreshold
     *
     * @return int
     */
    public function getThreshold()
    {
        return $this->threshold;
    }

    protected function checkDNS()
    {
        $checked = false;
        if (!function_exists('dns_get_record') && (
            in_array(self::DNSWARN_NO_RECORD, $this->warnings) &&
            in_array(self::DNSWARN_NO_MX_RECORD, $this->warnings)
        )) {
            return $checked;
        }

            // http://tools.ietf.org/html/rfc5321#section-2.3.5
            //   Names that can
            //   be resolved to MX RRs or address (i.e., A or AAAA) RRs (as discussed
            //   in Section 5) are permitted, as are CNAME RRs whose targets can be
            //   resolved, in turn, to MX or address RRs.
            //
            // http://tools.ietf.org/html/rfc5321#section-5.1
            //   The lookup first attempts to locate an MX record associated with the
            //   name.  If a CNAME record is found, the resulting name is processed as
            //   if it were the initial name. ... If an empty list of MXs is returned,
            //   the address is treated as if it was associated with an implicit MX
            //   RR, with a preference of 0, pointing to that host.
            //
            // is_email() author's note: We will regard the existence of a CNAME to be
            // sufficient evidence of the domain's existence. For performance reasons
            // we will not repeat the DNS lookup for the CNAME's target, but we will
            // raise a warning because we didn't immediately find an MX record.
        //if ($this->elementCount === 0) {
        //    // Checking TLD DNS seems to work only if you explicitly check from the root
        //    $this->parseData[self::COMPONENT_DOMAIN] .= '.';
        //}

        // Not using checkdnsrr because of a suspected bug in PHP 5.3 (http://bugs.php.net/bug.php?id=51844)
        $result = @dns_get_record($this->emailParts[1], DNS_MX);
        $checked = true;
        if ((is_bool($result) && !(bool) $result)) {
            // Domain can't be found in DNS
            $this->warnings[] = self::DNSWARN_NO_RECORD;
            $checked = false;
        } elseif (count($result) === 0) {
            // MX-record for domain can't be found
            $this->warnings[] = self::DNSWARN_NO_MX_RECORD;

            $result = @dns_get_record($this->emailParts[1], DNS_A + DNS_CNAME);
            if (count($result) === 0) {
                // No usable records for the domain can be found
                $this->warnings[] = self::DNSWARN_NO_RECORD;
            }
            $checked = false;
        }


        // Check for TLD addresses
        // -----------------------
        // TLD addresses are specifically allowed in RFC 5321 but they are
        // unusual to say the least. We will allocate a separate
        // status to these addresses on the basis that they are more likely
        // to be typos than genuine addresses (unless we've already
        // established that the domain does have an MX record)
        //
        // http://tools.ietf.org/html/rfc5321#section-2.3.5
        //   In the case
        //   of a top-level domain used by itself in an email address, a single
        //   string is used without any dots.  This makes the requirement,
        //   described in more detail below, that only fully-qualified domain
        //   names appear in SMTP transactions on the public Internet,
        //   particularly important where top-level domains are involved.
        //
        // TLD format
        // ----------
        // The format of TLDs has changed a number of times. The standards
        // used by IANA have been largely ignored by ICANN, leading to
        // confusion over the standards being followed. These are not defined
        // anywhere, except as a general component of a DNS host name (a label).
        // However, this could potentially lead to 123.123.123.123 being a
        // valid DNS name (rather than an IP address) and thereby creating
        // an ambiguity. The most authoritative statement on TLD formats that
        // the author can find is in a (rejected!) erratum to RFC 1123
        // submitted by John Klensin, the author of RFC 5321:
        //
        // http://www.rfc-editor.org/errata_search.php?rfc=1123&eid=1353
        //   However, a valid host name can never have the dotted-decimal
        //   form #.#.#.#, since this change does not permit the highest-level
        //   component label to start with a digit even if it is not all-numeric.
        if (!$checked && (!in_array(self::DNSWARN_NO_RECORD, $this->warnings) &&
            !in_array(self::DNSWARN_NO_MX_RECORD, $this->warnings))
        ) {

            if (in_array(RFC5322_DOMAINLITERAL)) {
                $this->warnings[] = self::RFC5321_TLD;
            }

            //@TODO review how to test TLD
            //if (isset($this->atomList[self::COMPONENT_DOMAIN][$this->elementCount][0]) &&
            //    is_numeric($this->atomList[self::COMPONENT_DOMAIN][$this->elementCount][0])
            //) {
            //    $this->warnings[] = self::RFC5321_TLDNUMERIC;
            //}
        }
        return $checked;
    }
}
