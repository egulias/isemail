<?php
class EmailValidator
{
    const VALID_CATEGORY = 1;

    const DNSWARN = 7;
    const RFC5321 = 15;
    const CFWS    = 31;
    const DEPREC  = 63;
    const RFC5322 = 127;
    const ERR     = 255;

    // Address is valid
    const VALID   = 0;

    // Address is valid but a DNS check was not successful
    const DNSWARN_NO_MX_RECORD    = 5;
    const DNSWARN_NO_RECORD       = 6;

    // Address is valid for SMTP but has unusual elements
    const RFC5321_TLD             = 9;
    const RFC5321_TLDNUMERIC      = 10;
    const RFC5321_QUOTEDSTRING    = 11;
    const RFC5321_ADDRESSLITERAL  = 12;
    const RFC5321_IPV6DEPRECATED  = 13;

    // function control
    const THRESHOLD               = 16;

    // Address is valid within the message but cannot be used unmodified for the envelope
    const CFWS_COMMENT            = 17;
    const CFWS_FWS                = 18;

    // Address contains deprecated elements but may still be valid in restricted contexts
    const DEPREC_LOCALPART        = 33;
    const DEPREC_FWS              = 34;
    const DEPREC_QTEXT            = 35;
    const DEPREC_QP               = 36;
    const DEPREC_COMMENT          = 37;
    const DEPREC_CTEXT            = 38;
    const DEPREC_CFWS_NEAR_AT     = 49;

    // The address is only valid according to the broad definition of RFC 5322. It is otherwise invalid.
    const RFC5322_DOMAIN          = 65;
    const RFC5322_TOOLONG         = 66;
    const RFC5322_LOCAL_TOOLONG   = 67;
    const RFC5322_DOMAIN_TOOLONG  = 68;
    const RFC5322_LABEL_TOOLONG   = 69;
    const RFC5322_DOMAINLITERAL   = 70;
    const RFC5322_DOMLIT_OBSDTEXT = 71;
    const RFC5322_IPV6_GRPCOUNT   = 72;
    const RFC5322_IPV6_2X2XCOLON  = 73;
    const RFC5322_IPV6_BADCHAR    = 74;
    const RFC5322_IPV6_MAXGRPS    = 75;
    const RFC5322_IPV6_COLONSTRT  = 76;
    const RFC5322_IPV6_COLONEND   = 77;

    // Address is invalid for any purpose
    const ERR_CONSECUTIVEATS     = 128;
    const ERR_EXPECTING_DTEXT    = 129;
    const ERR_NOLOCALPART        = 130;
    const ERR_NODOMAIN           = 131;
    const ERR_CONSECUTIVEDOTS    = 132;
    const ERR_ATEXT_AFTER_CFWS   = 133;
    const ERR_ATEXT_AFTER_QS     = 134;
    const ERR_ATEXT_AFTER_DOMLIT = 135;
    const ERR_EXPECTING_QPAIR    = 136;
    const ERR_EXPECTING_ATEXT    = 137;
    const ERR_EXPECTING_QTEXT    = 138;
    const ERR_EXPECTING_CTEXT    = 139;
    const ERR_BACKSLASHEND       = 140;
    const ERR_DOT_START          = 141;
    const ERR_DOT_END            = 142;
    const ERR_DOMAINHYPHENSTART  = 143;
    const ERR_DOMAINHYPHENEND    = 144;
    const ERR_UNCLOSEDQUOTEDSTR  = 145;
    const ERR_UNCLOSEDCOMMENT    = 146;
    const ERR_UNCLOSEDDOMLIT     = 147;
    const ERR_FWS_CRLF_X2        = 148;
    const ERR_FWS_CRLF_END       = 149;
    const ERR_CR_NO_LF           = 150;
    // End of generated code


    // Email parts
    const COMPONENT_LOCALPART  = 1;
    const COMPONENT_DOMAIN     = 2;
    const COMPONENT_LITERAL    = 4;

    const CONTEXT_COMMENT      = 8;
    const CONTEXT_FWS          = 16;
    const CONTEXT_QUOTEDSTRING = 32;
    const CONTEXT_QUOTEDPAIR   = 64;

    // Miscellaneous string constants
    const STRING_AT               = '@';
    const STRING_BACKSLASH        = '\\';
    const STRING_DOT              = '.';
    const STRING_DQUOTE           = '"';
    const STRING_OPENPARENTHESIS  = '(';
    const STRING_CLOSEPARENTHESIS = ')';
    const STRING_OPENSQBRACKET    = '[';
    const STRING_CLOSESQBRACKET   = ']';
    const STRING_HYPHEN           = '-';
    const STRING_COLON            = ':';
    const STRING_DOUBLECOLON      = '::';
    const STRING_SP               = ' ';
    const STRING_HTAB             = "\t";
    const STRING_CR               = "\r";
    const STRING_LF               = "\n";
    const STRING_IPV6TAG          = 'IPv6:';

    /**
     * US-ASCII visible characters not valid for atext (@link http://tools.ietf.org/html/rfc5322#section-3.2.3)
     *
     * @var array
     */
    public $specialCharacters = array(
        '(', ')', '<', '>', '[', ']', ':', ';', '@', '\\', ',', '.', '"'
    );

    protected $elementCount  = 0;
    protected $elementLength = 0;

    /**
     * For the components of the address
     *
     * @var array
     */
    protected $parseData = array(
        self::COMPONENT_LOCALPART => '',
        self::COMPONENT_DOMAIN    => ''
    );

    /**
     * For the dot-atom elements of the address
     *
     * @var array
     */
    protected $atomList = array(
        self::COMPONENT_LOCALPART => array(''),
        self::COMPONENT_DOMAIN    => array('')
    );

    protected $errors   = array();
    protected $warnings = array();

    public function __construct()
    {

    }

    public function isValid($value, $checkDNS = false, $strict = false)
    {
        $this->errors   = array();
        $this->warnings = array();

        $result = $this->isEmail($value, $checkDNS);

        if ($strict) {
            return $result && !$this->hasWarnings();
        }

        return $result;
    }

    public function getErrors()
    {
        return $this->errors;
    }

    public function hasErrors()
    {
        return !empty($this->errors);
    }

    public function getWarnings()
    {
        return $this->warnings;
    }

    public function hasWarnings()
    {
        return !empty($this->warnings);
    }

    /**
     * Check that an email address conforms to RFCs 5321, 5322 and others
     *
     * As of Version 3.0, we are now distinguishing clearly between a Mailbox
     * as defined by RFC 5321 and an addr-spec as defined by RFC 5322. Depending
     * on the context, either can be regarded as a valid email address. The
     * RFC 5321 Mailbox specification is more restrictive (comments, white space
     * and obsolete forms are not allowed)
     *
     * Check that $email is a valid address. Read the following RFCs to understand the constraints:
     *  @link(http://tools.ietf.org/html/rfc5321)
     *  @link(http://tools.ietf.org/html/rfc5322)
     *  @link(http://tools.ietf.org/html/rfc4291#section-2.2)
     *  @link(http://tools.ietf.org/html/rfc1123#section-2.1)
     *  @link(http://tools.ietf.org/html/rfc3696) (guidance only)
     *
     * @param string  $value       The email address to check
     * @param Boolean $checkDNS    If true then a DNS check for MX records will be made
     *
     * @return mixed
     */
    public function isEmail($value, $checkDNS = false)
    {
        // Omit validation is there is more than one `@` character
        if (substr_count($value, self::STRING_AT) !== 1) {
            $this->errors[] = self::ERR_CONSECUTIVEATS;
        } elseif (
            substr_count($value, self::STRING_OPENPARENTHESIS) !== substr_count($value, self::STRING_CLOSEPARENTHESIS)
        ) {
            $this->errors[] = self::ERR_UNCLOSEDCOMMENT;
        } else {
            $actualContext = self::COMPONENT_LOCALPART; // Where we are
            $contextPrev   = self::COMPONENT_LOCALPART; // Where we just came from
            $contextStack  = array($actualContext);     // Where we have been

            $token     =
            $tokenPrev = '';

            // Hyphen cannot occur at the end of a subdomain
            $hyphenFlag = false;

            // CFWS can only appear at the end of the element
            $endOfElement = false;

            // Parse the address into components, character by character
            $rawLength = strlen($value);
            for ($i = 0; $i < $rawLength; $i++) {
                // The current character
                $token = $value[$i];

                switch ($actualContext) {
                    //-------------------------------------------------------------
                    // local-part
                    //-------------------------------------------------------------
                    case self::COMPONENT_LOCALPART:
                        // http://tools.ietf.org/html/rfc5322#section-3.4.1
                        //   local-part      =   dot-atom / quoted-string / obs-local-part
                        //
                        //   dot-atom        =   [CFWS] dot-atom-text [CFWS]
                        //
                        //   dot-atom-text   =   1*atext *("." 1*atext)
                        //
                        //   quoted-string   =   [CFWS]
                        //                       DQUOTE *([FWS] qcontent) [FWS] DQUOTE
                        //                       [CFWS]
                        //
                        //   obs-local-part  =   word *("." word)
                        //
                        //   word            =   atom / quoted-string
                        //
                        //   atom            =   [CFWS] 1*atext [CFWS]
                        switch ($token) {
                            // Comment
                            case self::STRING_OPENPARENTHESIS:
                                if ($this->elementLength === 0) {
                                    // Comments are OK at the beginning of an element
                                    $this->warnings[] =
                                        $this->elementCount === 0 ? self::CFWS_COMMENT : self::DEPREC_COMMENT;
                                } else {
                                    $this->warnings[] = self::CFWS_COMMENT;

                                    // We can't start a comment in the middle of an element, so this better be the end
                                    $endOfElement     = true;
                                }

                                $contextStack[] = $actualContext;
                                $actualContext  = self::CONTEXT_COMMENT;
                                break;
                            // Next dot-atom element
                            case self::STRING_DOT:
                                if ($this->elementLength === 0) {
                                    // Another dot, already? Fatal error
                                    $this->errors[] =
                                        $this->elementCount === 0 ? self::ERR_DOT_START : self::ERR_CONSECUTIVEDOTS;
                                } else {
                                    // The entire local-part can be a quoted string for RFC 5321
                                    // If it's just one atom that is quoted then it's an RFC 5322 obsolete form
                                    if ($endOfElement) {
                                        $this->warnings[] = self::DEPREC_LOCALPART;
                                    }
                                }

                                $this->parseData[self::COMPONENT_LOCALPART] .= $token;

                                if (!isset($this->atomList[self::COMPONENT_LOCALPART][$this->elementCount])) {
                                    $this->atomList[self::COMPONENT_LOCALPART][$this->elementCount] = '';
                                }
                                $this->atomList[self::COMPONENT_LOCALPART][$this->elementCount] = '';

                                $this->elementLength = 0;
                                ++$this->elementCount;

                                // CFWS & quoted strings are OK again
                                //now we're at the beginning of an element (although they are obsolete forms)
                                $endOfElement = false;

                                break;
                            // Quoted string
                            case self::STRING_DQUOTE:
                                if ($this->elementLength === 0) {
                                    // The entire local-part can be a quoted string for RFC 5321
                                    // If it's just one atom that is quoted then it's an RFC 5322 obsolete form
                                    $this->warnings[] =
                                        $this->elementCount === 0 ? self::RFC5321_QUOTEDSTRING : self::DEPREC_LOCALPART;

                                    $contextStack[] = $actualContext;
                                    $actualContext  = self::CONTEXT_QUOTEDSTRING;

                                    $this->parseData[self::COMPONENT_LOCALPART] .= $token;

                                    if (!isset($this->atomList[self::COMPONENT_LOCALPART][$this->elementCount])) {
                                        $this->atomList[self::COMPONENT_LOCALPART][$this->elementCount] = '';
                                    }
                                    $this->atomList[self::COMPONENT_LOCALPART][$this->elementCount] .= $token;

                                    ++$this->elementLength;

                                    // Quoted string must be the entire element
                                    $endOfElement   = true;
                                } else {
                                    // Fatal error
                                    $this->errors[] = self::ERR_EXPECTING_ATEXT;
                                }

                                break;
                            // Folding White Space
                            case self::STRING_CR:
                            case self::STRING_SP:
                            case self::STRING_HTAB:
                                if (
                                    ($token === self::STRING_CR) &&
                                    ((++$i === $rawLength) || ($value[$i] !== self::STRING_LF))
                                ) {
                                    // Fatal error
                                    $this->errors[] = self::ERR_CR_NO_LF;
                                    break;
                                }

                                if ($this->elementLength === 0) {
                                    $this->warnings[] = $this->elementCount === 0 ? self::CFWS_FWS : self::DEPREC_FWS;
                                } else {
                                    // We can't start FWS in the middle of an element, so this better be the end
                                    $endOfElement = true;
                                }

                                $contextStack[] = $actualContext;
                                $actualContext  = self::CONTEXT_FWS;
                                $tokenPrev      = $token;

                                break;
                            // @
                            case self::STRING_AT:
                                if ($this->parseData[self::COMPONENT_LOCALPART] === '') {
                                    // Fatal error
                                    $this->errors[] = self::ERR_NOLOCALPART;
                                } elseif ($this->elementLength === 0) {
                                    // Fatal error
                                    $this->errors[] = self::ERR_DOT_END;
                                } elseif (strlen($this->parseData[self::COMPONENT_LOCALPART]) > 64) {
                                    // http://tools.ietf.org/html/rfc5321#section-4.5.3.1.1
                                    //   The maximum total length of a user name or other local-part is 64
                                    //   octets.
                                    $this->warnings[] = self::RFC5322_LOCAL_TOOLONG;
                                } elseif (
                                    ($contextPrev === self::CONTEXT_COMMENT) || ($contextPrev === self::CONTEXT_FWS)
                                ) {
                                    // http://tools.ietf.org/html/rfc5322#section-3.4.1
                                    //   Comments and folding white space
                                    //   SHOULD NOT be used around the "@" in the addr-spec.
                                    //
                                    // http://tools.ietf.org/html/rfc2119
                                    // 4. SHOULD NOT   This phrase, or the phrase "NOT RECOMMENDED" mean that
                                    //    there may exist valid reasons in particular circumstances when the
                                    //    particular behavior is acceptable or even useful, but the full
                                    //    implications should be understood and the case carefully weighed
                                    //    before implementing any behavior described with this label.
                                    $this->warnings[] = self::DEPREC_CFWS_NEAR_AT;
                                }

                                // Clear everything down for the domain parsing
                                // Where we are
                                $actualContext = self::COMPONENT_DOMAIN;
                                // Where we have been
                                $contextStack  = array($actualContext);

                                $this->elementCount  = 0;
                                $this->elementLength = 0;

                                // CFWS can only appear at the end of the element
                                $endOfElement = false;

                                break;
                            // atext
                            default:
                                // http://tools.ietf.org/html/rfc5322#section-3.2.3
                                //    atext           =   ALPHA / DIGIT /    ; Printable US-ASCII
                                //                        "!" / "#" /        ;  characters not including
                                //                        "$" / "%" /        ;  specials.  Used for atoms.
                                //                        "&" / "'" /
                                //                        "*" / "+" /
                                //                        "-" / "/" /
                                //                        "=" / "?" /
                                //                        "^" / "_" /
                                //                        "`" / "{" /
                                //                        "|" / "}" /
                                //                        "~"
                                if ($endOfElement) {
                                    // We have encountered atext where it is no longer valid
                                    switch ($contextPrev) {
                                        case self::CONTEXT_COMMENT:
                                        case self::CONTEXT_FWS:
                                            $this->errors[] = self::ERR_ATEXT_AFTER_CFWS;
                                            break;
                                        case self::CONTEXT_QUOTEDSTRING:
                                            $this->errors[] = self::ERR_ATEXT_AFTER_QS;
                                            break;
                                        default:
                                            throw new \Exception(
                                                "More atext found where none is allowed, but unrecognised prior context:
                                                $contextPrev"
                                            );
                                    }
                                } else {
                                    $ord = ord($token);
                                    if ($ord < 33 || $ord > 126 || $ord === 10 ||
                                        in_array($token, $this->specialCharacters)
                                    ) {
                                        // Fatal error
                                        $this->errors[]  = self::ERR_EXPECTING_ATEXT;
                                    }
                                    $contextPrev = $actualContext;

                                    $this->parseData[self::COMPONENT_LOCALPART] .= $token;

                                    if (!isset($this->atomList[self::COMPONENT_LOCALPART][$this->elementCount])) {
                                        $this->atomList[self::COMPONENT_LOCALPART][$this->elementCount] = '';
                                    }
                                    $this->atomList[self::COMPONENT_LOCALPART][$this->elementCount] .= $token;

                                    ++$this->elementLength;
                                }
                        }
                        break;
                    //-------------------------------------------------------------
                    // Domain
                    //-------------------------------------------------------------
                    case self::COMPONENT_DOMAIN:
                        // http://tools.ietf.org/html/rfc5322#section-3.4.1
                        //   domain          =   dot-atom / domain-literal / obs-domain
                        //
                        //   dot-atom        =   [CFWS] dot-atom-text [CFWS]
                        //
                        //   dot-atom-text   =   1*atext *("." 1*atext)
                        //
                        //   domain-literal  =   [CFWS] "[" *([FWS] dtext) [FWS] "]" [CFWS]
                        //
                        //   dtext           =   %d33-90 /          ; Printable US-ASCII
                        //                       %d94-126 /         ;  characters not including
                        //                       obs-dtext          ;  "[", "]", or "\"
                        //
                        //   obs-domain      =   atom *("." atom)
                        //
                        //   atom            =   [CFWS] 1*atext [CFWS]


                        // http://tools.ietf.org/html/rfc5321#section-4.1.2
                        //   Mailbox        = Local-part "@" ( Domain / address-literal )
                        //
                        //   Domain         = sub-domain *("." sub-domain)
                        //
                        //   address-literal  = "[" ( IPv4-address-literal /
                        //                    IPv6-address-literal /
                        //                    General-address-literal ) "]"
                        //                    ; See Section 4.1.3

                        // http://tools.ietf.org/html/rfc5322#section-3.4.1
                        //      Note: A liberal syntax for the domain portion of addr-spec is
                        //      given here.  However, the domain portion contains addressing
                        //      information specified by and used in other protocols (e.g.,
                        //      [RFC1034], [RFC1035], [RFC1123], [RFC5321]).  It is therefore
                        //      incumbent upon implementations to conform to the syntax of
                        //      addresses for the context in which they are used.
                        // is_email() author's note: it's not clear how to interpret this in
                        // the context of a general email address validator. The conclusion I
                        // have reached is this: "addressing information" must comply with
                        // RFC 5321 (and in turn RFC 1035), anything that is "semantically
                        // invisible" must comply only with RFC 5322.
                        switch ($token) {
                            // Comment
                            case self::STRING_OPENPARENTHESIS:
                                if ($this->elementLength === 0) {
                                    // Comments at the start of the domain are deprecated in the text
                                    // Comments at the start of a subdomain are obs-domain
                                    // (http://tools.ietf.org/html/rfc5322#section-3.4.1)
                                    $this->warnings[] =
                                        $this->elementCount === 0 ? self::DEPREC_CFWS_NEAR_AT : self::DEPREC_COMMENT;
                                } else {
                                    $this->warnings[] = self::CFWS_COMMENT;

                                    // We can't start a comment in the middle of an element, so this better be the end
                                    $endOfElement = true;
                                }

                                $contextStack[] = $actualContext;
                                $actualContext  = self::CONTEXT_COMMENT;
                                break;
                            // Next dot-atom element
                            case self::STRING_DOT:
                                if ($this->elementLength === 0) {
                                    // Another dot, already?
                                    // Fatal error
                                    $this->errors[] =
                                        $this->elementCount === 0 ? self::ERR_DOT_START : self::ERR_CONSECUTIVEDOTS;
                                } elseif ($hyphenFlag) {
                                    // Previous subdomain ended in a hyphen
                                    // Fatal error
                                    $this->errors[] = self::ERR_DOMAINHYPHENEND;
                                } else {
                                    // Nowhere in RFC 5321 does it say explicitly that the
                                    // domain part of a Mailbox must be a valid domain according
                                    // to the DNS standards set out in RFC 1035, but this *is*
                                    // implied in several places. For instance, wherever the idea
                                    // of host routing is discussed the RFC says that the domain
                                    // must be looked up in the DNS. This would be nonsense unless
                                    // the domain was designed to be a valid DNS domain. Hence we
                                    // must conclude that the RFC 1035 restriction on label length
                                    // also applies to RFC 5321 domains.
                                    //
                                    // http://tools.ietf.org/html/rfc1035#section-2.3.4
                                    // labels          63 octets or less
                                    if ($this->elementLength > 63) {
                                        $this->warnings[] = self::RFC5322_LABEL_TOOLONG;
                                    }
                                }
                                $this->parseData[self::COMPONENT_DOMAIN] .= $token;

                                if (!isset($this->atomList[self::COMPONENT_DOMAIN][$this->elementCount])) {
                                    $this->atomList[self::COMPONENT_DOMAIN][$this->elementCount] = '';
                                }
                                $this->atomList[self::COMPONENT_DOMAIN][$this->elementCount] = '';

                                $this->elementLength = 0;
                                ++$this->elementCount;

                                // CFWS is OK again now we're at the beginning of an element
                                //(although it may be obsolete CFWS)
                                $endOfElement = false;

                                break;
                            // Domain literal
                            case self::STRING_OPENSQBRACKET:
                                if ($this->parseData[self::COMPONENT_DOMAIN] === '') {
                                    ++$this->elementLength;
                                    $contextStack[] = $actualContext;
                                    $actualContext  = self::COMPONENT_LITERAL;

                                    $this->parseData[self::COMPONENT_LITERAL] = '';
                                    $this->parseData[self::COMPONENT_DOMAIN] .= $token;

                                    if (!isset($this->atomList[self::COMPONENT_DOMAIN][$this->elementCount])) {
                                        $this->atomList[self::COMPONENT_DOMAIN][$this->elementCount] = '';
                                    }
                                    $this->atomList[self::COMPONENT_DOMAIN][$this->elementCount] .= $token;

                                    // Domain literal must be the only component
                                    $endOfElement = true;
                                } else {
                                    // Fatal error
                                    $this->errors[] = self::ERR_EXPECTING_ATEXT;
                                }

                                break;
                            // Folding White Space
                            case self::STRING_CR:
                            case self::STRING_SP:
                            case self::STRING_HTAB:
                                if (($token === self::STRING_CR) &&
                                    ((++$i === $rawLength) || ($value[$i] !== self::STRING_LF))
                                ) {
                                    // Fatal error
                                    $this->errors[] = self::ERR_CR_NO_LF;
                                    break;
                                }

                                if ($this->elementLength === 0) {
                                    $this->warnings[] =
                                        $this->elementCount === 0 ? self::DEPREC_CFWS_NEAR_AT : self::DEPREC_FWS;
                                } else {
                                    $this->warnings[] = self::CFWS_FWS;

                                    // We can't start FWS in the middle of an element, so this better be the end
                                    $endOfElement = true;
                                }

                                $contextStack[] = $actualContext;
                                $actualContext  = self::CONTEXT_FWS;
                                $tokenPrev      = $token;
                                break;
                            // atext
                            default:
                                // RFC 5322 allows any atext...
                                // http://tools.ietf.org/html/rfc5322#section-3.2.3
                                //    atext           =   ALPHA / DIGIT /    ; Printable US-ASCII
                                //                        "!" / "#" /        ;  characters not including
                                //                        "$" / "%" /        ;  specials.  Used for atoms.
                                //                        "&" / "'" /
                                //                        "*" / "+" /
                                //                        "-" / "/" /
                                //                        "=" / "?" /
                                //                        "^" / "_" /
                                //                        "`" / "{" /
                                //                        "|" / "}" /
                                //                        "~"

                                // But RFC 5321 only allows letter-digit-hyphen
                                //  to comply with DNS rules (RFCs 1034 & 1123)
                                // http://tools.ietf.org/html/rfc5321#section-4.1.2
                                //   sub-domain     = Let-dig [Ldh-str]
                                //
                                //   Let-dig        = ALPHA / DIGIT
                                //
                                //   Ldh-str        = *( ALPHA / DIGIT / "-" ) Let-dig
                                //
                                if ($endOfElement) {
                                    // We have encountered atext where it is no longer valid
                                    switch ($contextPrev) {
                                        case self::CONTEXT_COMMENT:
                                        case self::CONTEXT_FWS:
                                            $this->errors[] = self::ERR_ATEXT_AFTER_CFWS;
                                            break;
                                        case self::COMPONENT_LITERAL:
                                            $this->errors[] = self::ERR_ATEXT_AFTER_DOMLIT;
                                            break;
                                        default:
                                            throw new \Exception(
                                                "More atext found where none is allowed, but unrecognised prior context:
                                                $contextPrev"
                                            );
                                    }
                                }

                                // Assume this token isn't a hyphen unless we discover it is
                                $hyphenFlag = false;

                                $ord = ord($token);
                                if ($ord < 33 || $ord > 126 || in_array($token, $this->specialCharacters)) {
                                    // Fatal error
                                    $this->errors[] = self::ERR_EXPECTING_ATEXT;
                                } elseif ($token === self::STRING_HYPHEN) {
                                    if ($this->elementLength === 0) {
                                        // Hyphens can't be at the beginning of a subdomain
                                        // Fatal error
                                        $this->errors[] = self::ERR_DOMAINHYPHENSTART;
                                    }

                                    $hyphenFlag = true;
                                } elseif (!(($ord > 47 && $ord < 58) || ($ord > 64 && $ord < 91) ||
                                    ($ord > 96 && $ord < 123))
                                ) {
                                    // Not an RFC 5321 subdomain, but still OK by RFC 5322
                                    $this->warnings[] = self::RFC5322_DOMAIN;
                                }

                                $this->parseData[self::COMPONENT_DOMAIN] .= $token;

                                if (!isset($this->atomList[self::COMPONENT_DOMAIN][$this->elementCount])) {
                                    $this->atomList[self::COMPONENT_DOMAIN][$this->elementCount] = '';
                                }
                                $this->atomList[self::COMPONENT_DOMAIN][$this->elementCount] .= $token;

                                ++$this->elementLength;
                        }

                        break;
                    //-------------------------------------------------------------
                    // Domain literal
                    //-------------------------------------------------------------
                    case self::COMPONENT_LITERAL:
                        // http://tools.ietf.org/html/rfc5322#section-3.4.1
                        //   domain-literal  =   [CFWS] "[" *([FWS] dtext) [FWS] "]" [CFWS]
                        //
                        //   dtext           =   %d33-90 /          ; Printable US-ASCII
                        //                       %d94-126 /         ;  characters not including
                        //                       obs-dtext          ;  "[", "]", or "\"
                        //
                        //   obs-dtext       =   obs-NO-WS-CTL / quoted-pair
                        switch ($token) {
                            // End of domain literal
                            case self::STRING_CLOSESQBRACKET:
                                if (!$this->hasWarnings() || ((int) max($this->warnings) < self::DEPREC)) {
                                    // Could be a valid RFC 5321 address literal, so let's check

                                    // http://tools.ietf.org/html/rfc5321#section-4.1.2
                                    //   address-literal  = "[" ( IPv4-address-literal /
                                    //                    IPv6-address-literal /
                                    //                    General-address-literal ) "]"
                                    //                    ; See Section 4.1.3
                                    //
                                    // http://tools.ietf.org/html/rfc5321#section-4.1.3
                                    //   IPv4-address-literal  = Snum 3("."  Snum)
                                    //
                                    //   IPv6-address-literal  = "IPv6:" IPv6-addr
                                    //
                                    //   General-address-literal  = Standardized-tag ":" 1*dcontent
                                    //
                                    //   Standardized-tag  = Ldh-str
                                    //                     ; Standardized-tag MUST be specified in a
                                    //                     ; Standards-Track RFC and registered with IANA
                                    //
                                    //   dcontent       = %d33-90 / ; Printable US-ASCII
                                    //                  %d94-126 ; excl. "[", "\", "]"
                                    //
                                    //   Snum           = 1*3DIGIT
                                    //                  ; representing a decimal integer
                                    //                  ; value in the range 0 through 255
                                    //
                                    //   IPv6-addr      = IPv6-full / IPv6-comp / IPv6v4-full / IPv6v4-comp
                                    //
                                    //   IPv6-hex       = 1*4HEXDIG
                                    //
                                    //   IPv6-full      = IPv6-hex 7(":" IPv6-hex)
                                    //
                                    //   IPv6-comp      = [IPv6-hex *5(":" IPv6-hex)] "::"
                                    //                  [IPv6-hex *5(":" IPv6-hex)]
                                    //                  ; The "::" represents at least 2 16-bit groups of
                                    //                  ; zeros.  No more than 6 groups in addition to the
                                    //                  ; "::" may be present.
                                    //
                                    //   IPv6v4-full    = IPv6-hex 5(":" IPv6-hex) ":" IPv4-address-literal
                                    //
                                    //   IPv6v4-comp    = [IPv6-hex *3(":" IPv6-hex)] "::"
                                    //                  [IPv6-hex *3(":" IPv6-hex) ":"]
                                    //                  IPv4-address-literal
                                    //                  ; The "::" represents at least 2 16-bit groups of
                                    //                  ; zeros.  No more than 4 groups in addition to the
                                    //                  ; "::" and IPv4-address-literal may be present.
                                    //
                                    // is_email() author's note: We can't use ip2long() to validate
                                    // IPv4 addresses because it accepts abbreviated addresses
                                    // (xxx.xxx.xxx), expanding the last group to complete the address.
                                    // filter_var() validates IPv6 address inconsistently (up to PHP 5.3.3
                                    // at least) -- see http://bugs.php.net/bug.php?id=53236 for example
                                    $max_groups = 8;
                                    $matchesIP  = array();
                                    /*.mixed.*/
                                    $index = false;
                                    $addressLiteral = $this->parseData[self::COMPONENT_LITERAL];

                                    // Extract IPv4 part from the end of the address-literal (if there is one)
                                    if (
                                        preg_match(
                                            '/\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/',
                                            $addressLiteral,
                                            $matchesIP
                                        ) > 0
                                    ) {
                                        $index = strrpos($addressLiteral, $matchesIP[0]);
                                        if ($index !== 0) {
                                            // Convert IPv4 part to IPv6 format for further testing
                                            $addressLiteral = substr($addressLiteral, 0, $index) . '0:0';
                                        }
                                    }

                                    if ($index === 0) {
                                        // Nothing there except a valid IPv4 address, so...
                                        $this->warnings[] = self::RFC5321_ADDRESSLITERAL;
                                    } elseif (strncasecmp($addressLiteral, self::STRING_IPV6TAG, 5) !== 0) {
                                        $this->warnings[] = self::RFC5322_DOMAINLITERAL;
                                    } else {
                                        $IPv6       = substr($addressLiteral, 5);
                                        // Revision 2.7: Daniel Marschall's new IPv6 testing strategy
                                        $matchesIP  = explode(self::STRING_COLON, $IPv6);
                                        $groupCount = count($matchesIP);
                                        $index      = strpos($IPv6, self::STRING_DOUBLECOLON);

                                        if ($index === false) {
                                            // We need exactly the right number of groups
                                            if ($groupCount !== $max_groups) {
                                                $this->warnings[] = self::RFC5322_IPV6_GRPCOUNT;
                                            }
                                        } else {
                                            if ($index !== strrpos($IPv6, self::STRING_DOUBLECOLON)) {
                                                $this->warnings[] = self::RFC5322_IPV6_2X2XCOLON;
                                            } else {
                                                if ($index === 0 || $index === (strlen($IPv6) - 2)) {
                                                    // RFC 4291 allows :: at the start or end of an address
                                                    //with 7 other groups in addition
                                                    ++$max_groups;
                                                }

                                                if ($groupCount > $max_groups) {
                                                    $this->warnings[] = self::RFC5322_IPV6_MAXGRPS;
                                                } elseif ($groupCount === $max_groups) {
                                                    // Eliding a single "::"
                                                    $this->warnings[] = self::RFC5321_IPV6DEPRECATED;
                                                }
                                            }
                                        }

                                        // Revision 2.7: Daniel Marschall's new IPv6 testing strategy
                                        if ($IPv6{0} === self::STRING_COLON && $IPv6{1} !== self::STRING_COLON) {
                                            // Address starts with a single colon
                                            $this->warnings[] = self::RFC5322_IPV6_COLONSTRT;
                                        } elseif (substr($IPv6, -1, 1) === self::STRING_COLON &&
                                            substr($IPv6, -2, 2) !== self::STRING_DOUBLECOLON
                                        ) {
                                            // Address ends with a single colon
                                            $this->warnings[] = self::RFC5322_IPV6_COLONEND;
                                        } elseif (count(
                                            preg_grep('/^[0-9A-Fa-f]{0,4}$/', $matchesIP, PREG_GREP_INVERT)
                                        ) !== 0
                                        ) {
                                            // Check for unmatched characters
                                            $this->warnings[] = self::RFC5322_IPV6_BADCHAR;
                                        } else {
                                            $this->warnings[] = self::RFC5321_ADDRESSLITERAL;
                                        }
                                    }
                                } else {
                                    $this->warnings[] = self::RFC5322_DOMAINLITERAL;
                                }

                                $contextPrev   = $actualContext;
                                $actualContext = (int) array_pop($contextStack);

                                $this->parseData[self::COMPONENT_DOMAIN] .= $token;

                                if (!isset($this->atomList[self::COMPONENT_DOMAIN][$this->elementCount])) {
                                    $this->atomList[self::COMPONENT_DOMAIN][$this->elementCount] = '';
                                }
                                $this->atomList[self::COMPONENT_DOMAIN][$this->elementCount] .= $token;

                                ++$this->elementLength;
                                break;
                            case self::STRING_BACKSLASH:
                                $this->warnings[] = self::RFC5322_DOMLIT_OBSDTEXT;

                                $contextStack[] = $actualContext;
                                $actualContext   = self::CONTEXT_QUOTEDPAIR;
                                break;
                            // Folding White Space
                            case self::STRING_CR:
                            case self::STRING_SP:
                            case self::STRING_HTAB:
                                if (($token === self::STRING_CR) &&
                                    ((++$i === $rawLength) || ($value[$i] !== self::STRING_LF))
                                ) {
                                    // Fatal error
                                    $this->errors[] = self::ERR_CR_NO_LF;
                                    break;
                                }

                                $this->warnings[] = self::CFWS_FWS;

                                $contextStack[] = $actualContext;
                                $actualContext  = self::CONTEXT_FWS;
                                $tokenPrev      = $token;
                                break;
                            // dtext
                            default:
                                // http://tools.ietf.org/html/rfc5322#section-3.4.1
                                //   dtext           =   %d33-90 /          ; Printable US-ASCII
                                //                       %d94-126 /         ;  characters not including
                                //                       obs-dtext          ;  "[", "]", or "\"
                                //
                                //   obs-dtext       =   obs-NO-WS-CTL / quoted-pair
                                //
                                //   obs-NO-WS-CTL   =   %d1-8 /            ; US-ASCII control
                                //                       %d11 /             ;  characters that do not
                                //                       %d12 /             ;  include the carriage
                                //                       %d14-31 /          ;  return, line feed, and
                                //                       %d127              ;  white space characters
                                $ord = ord($token);

                                // CR, LF, SP & HTAB have already been parsed above
                                if ($ord > 127 || $ord === 0 || $token === self::STRING_OPENSQBRACKET) {
                                    // Fatal error
                                    $this->errors[]  = self::ERR_EXPECTING_DTEXT;
                                    break;
                                } elseif ($ord < 33 || $ord === 127) {
                                    $this->warnings[] = self::RFC5322_DOMLIT_OBSDTEXT;
                                }

                                $this->parseData[self::COMPONENT_LITERAL] .= $token;
                                $this->parseData[self::COMPONENT_DOMAIN]  .= $token;

                                if (!isset($this->atomList[self::COMPONENT_DOMAIN][$this->elementCount])) {
                                    $this->atomList[self::COMPONENT_DOMAIN][$this->elementCount] = '';
                                }
                                $this->atomList[self::COMPONENT_DOMAIN][$this->elementCount] .= $token;

                                ++$this->elementLength;
                        }

                        break;
                    //-------------------------------------------------------------
                    // Quoted string
                    //-------------------------------------------------------------
                    case self::CONTEXT_QUOTEDSTRING:
                        // http://tools.ietf.org/html/rfc5322#section-3.2.4
                        //   quoted-string   =   [CFWS]
                        //                       DQUOTE *([FWS] qcontent) [FWS] DQUOTE
                        //                       [CFWS]
                        //
                        //   qcontent        =   qtext / quoted-pair
                        switch ($token) {
                            // Quoted pair
                            case self::STRING_BACKSLASH:
                                $contextStack[] = $actualContext;
                                $actualContext  = self::CONTEXT_QUOTEDPAIR;
                                break;
                            // Folding White Space
                            // Inside a quoted string, spaces are allowed as regular characters.
                            // It's only FWS if we include HTAB or CRLF
                            case self::STRING_CR:
                            case self::STRING_HTAB:
                                if (($token === self::STRING_CR) &&
                                    ((++$i === $rawLength) || ($value[$i] !== self::STRING_LF))
                                ) {
                                    // Fatal error
                                    $this->errors[] = self::ERR_CR_NO_LF;
                                    break;
                                }

                                // http://tools.ietf.org/html/rfc5322#section-3.2.2
                                //   Runs of FWS, comment, or CFWS that occur between lexical tokens in a
                                //   structured header field are semantically interpreted as a single
                                //   space character.

                                // http://tools.ietf.org/html/rfc5322#section-3.2.4
                                //   the CRLF in any FWS/CFWS that appears within the quoted-string [is]
                                //   semantically "invisible" and therefore not part of the quoted-string
                                $this->warnings[] = self::CFWS_FWS;

                                $contextStack[] = $actualContext;
                                $actualContext  = self::CONTEXT_FWS;
                                $tokenPrev      = $token;

                                $this->parseData[self::COMPONENT_LOCALPART] .= self::STRING_SP;

                                if (!isset($this->atomList[self::COMPONENT_LOCALPART][$this->elementCount])) {
                                    $this->atomList[self::COMPONENT_LOCALPART][$this->elementCount] = '';
                                }
                                $this->atomList[self::COMPONENT_LOCALPART][$this->elementCount] .= self::STRING_SP;

                                ++$this->elementLength;
                                break;
                            // End of quoted string
                            case self::STRING_DQUOTE:
                                $contextPrev   = $actualContext;
                                $actualContext = (int) array_pop($contextStack);

                                $this->parseData[self::COMPONENT_LOCALPART] .= $token;

                                if (!isset($this->atomList[self::COMPONENT_LOCALPART][$this->elementCount])) {
                                    $this->atomList[self::COMPONENT_LOCALPART][$this->elementCount] = '';
                                }
                                $this->atomList[self::COMPONENT_LOCALPART][$this->elementCount] .= $token;

                                ++$this->elementLength;
                                break;
                            // qtext
                            default:
                                // http://tools.ietf.org/html/rfc5322#section-3.2.4
                                //   qtext           =   %d33 /             ; Printable US-ASCII
                                //                       %d35-91 /          ;  characters not including
                                //                       %d93-126 /         ;  "\" or the quote character
                                //                       obs-qtext
                                //
                                //   obs-qtext       =   obs-NO-WS-CTL
                                //
                                //   obs-NO-WS-CTL   =   %d1-8 /            ; US-ASCII control
                                //                       %d11 /             ;  characters that do not
                                //                       %d12 /             ;  include the carriage
                                //                       %d14-31 /          ;  return, line feed, and
                                //                       %d127              ;  white space characters
                                $ord = ord($token);

                                if ($ord > 127 || $ord === 0 || $ord === 10) {
                                    // Fatal error
                                    $this->errors[]  = self::ERR_EXPECTING_QTEXT;
                                } elseif ($ord < 32 || $ord === 127) {
                                    // Fatal error
                                    $this->warnings[] = self::DEPREC_QTEXT;
                                }

                                $this->parseData[self::COMPONENT_LOCALPART] .= $token;

                                if (!isset($this->atomList[self::COMPONENT_LOCALPART][$this->elementCount])) {
                                    $this->atomList[self::COMPONENT_LOCALPART][$this->elementCount] = '';
                                }
                                $this->atomList[self::COMPONENT_LOCALPART][$this->elementCount] .= $token;

                                ++$this->elementLength;
                        }

                        // @Todo
                        // http://tools.ietf.org/html/rfc5322#section-3.4.1
                        //   If the
                        //   string can be represented as a dot-atom (that is, it contains no
                        //   characters other than atext characters or "." surrounded by atext
                        //   characters), then the dot-atom form SHOULD be used and the quoted-
                        //   string form SHOULD NOT be used.
                        break;
                    //-------------------------------------------------------------
                    // Quoted pair
                    //-------------------------------------------------------------
                    case self::CONTEXT_QUOTEDPAIR:
                        // http://tools.ietf.org/html/rfc5322#section-3.2.1
                        //   quoted-pair     =   ("\" (VCHAR / WSP)) / obs-qp
                        //
                        //   VCHAR           =  %d33-126            ; visible (printing) characters
                        //   WSP             =  SP / HTAB           ; white space
                        //
                        //   obs-qp          =   "\" (%d0 / obs-NO-WS-CTL / LF / CR)
                        //
                        //   obs-NO-WS-CTL   =   %d1-8 /            ; US-ASCII control
                        //                       %d11 /             ;  characters that do not
                        //                       %d12 /             ;  include the carriage
                        //                       %d14-31 /          ;  return, line feed, and
                        //                       %d127              ;  white space characters
                        //
                        // i.e. obs-qp       =  "\" (%d0-8, %d10-31 / %d127)
                        $ord = ord($token);
                        if ($ord > 127) {
                            // Fatal error
                            $this->errors[]  = self::ERR_EXPECTING_QPAIR;
                        } elseif (($ord < 31 && $ord !== 9) || $ord === 127) {
                            // SP & HTAB are allowed
                            $this->warnings[] = self::DEPREC_QP;
                        }

                        // At this point we know where this qpair occurred so
                        // we could check to see if the character actually
                        // needed to be quoted at all.
                        // http://tools.ietf.org/html/rfc5321#section-4.1.2
                        //   the sending system SHOULD transmit the
                        //   form that uses the minimum quoting possible.

                        // @Todo: check whether the character needs to be quoted (escaped) in this context

                        $contextPrev   = $actualContext;
                        $actualContext = (int) array_pop($contextStack); // End of qpair

                        $token         = self::STRING_BACKSLASH . $token;

                        switch ($actualContext) {
                            case self::CONTEXT_COMMENT:
                                break;
                            case self::CONTEXT_QUOTEDSTRING:
                                $this->parseData[self::COMPONENT_LOCALPART] .= $token;

                                if (!isset($this->atomList[self::COMPONENT_LOCALPART][$this->elementCount])) {
                                    $this->atomList[self::COMPONENT_LOCALPART][$this->elementCount] = '';
                                }
                                $this->atomList[self::COMPONENT_LOCALPART][$this->elementCount] .= $token;

                                // The maximum sizes specified by RFC 5321 are octet counts,
                                // so we must include the backslash
                                $this->elementLength += 2;
                                break;
                            case self::COMPONENT_LITERAL:
                                $this->parseData[self::COMPONENT_DOMAIN] .= $token;

                                if (!isset($this->atomList[self::COMPONENT_DOMAIN][$this->elementCount])) {
                                    $this->atomList[self::COMPONENT_DOMAIN][$this->elementCount] = '';
                                }
                                $this->atomList[self::COMPONENT_DOMAIN][$this->elementCount] .= $token;

                                // The maximum sizes specified by RFC 5321 are octet counts,
                                // so we must include the backslash
                                $this->elementLength += 2;
                                break;
                            default:
                                die("Quoted pair logic invoked in an invalid context: $actualContext");
                        }

                        break;
                    //-------------------------------------------------------------
                    // Comment
                    //-------------------------------------------------------------
                    case self::CONTEXT_COMMENT:
                        // http://tools.ietf.org/html/rfc5322#section-3.2.2
                        //   comment        =   "(" *([FWS] ccontent) [FWS] ")"
                        //
                        //   content        =   ctext / quoted-pair / comment
                        switch ($token) {
                            // Nested comment
                            case self::STRING_OPENPARENTHESIS:
                                // Nested comments are OK
                                $contextStack[] = $actualContext;
                                $actualContext  = self::CONTEXT_COMMENT;
                                break;
                            // End of comment
                            case self::STRING_CLOSEPARENTHESIS:
                                $contextPrev   = $actualContext;
                                $actualContext = (int) array_pop($contextStack);

                                // http://tools.ietf.org/html/rfc5322#section-3.2.2
                                //   Runs of FWS, comment, or CFWS that occur between lexical tokens in a
                                //   structured header field are semantically interpreted as a single
                                //   space character.
                                //
                                // is_email() author's note: This *cannot* mean that we must add a
                                // space to the address wherever CFWS appears. This would result in
                                // any addr-spec that had CFWS outside a quoted string being invalid
                                // for RFC 5321.
                                /*
                                // @todo
                                if (($actualContext === self::COMPONENT_LOCALPART) ||
                                    ($actualContext === self::COMPONENT_DOMAIN)
                                ) {
                                    $this->parseData[$actualContext] .= self::STRING_SP;

                                    if (!isset($this->atomList[$actualContext][$this->elementCount])) {
                                        $this->atomList[$actualContext][$this->elementCount] = '';
                                    }
                                    $this->atomList[$actualContext][$element_count] .= self::STRING_SP;

                                    ++$this->elementLength;
                                }
                                */
                                break;
                            // Quoted pair
                            case self::STRING_BACKSLASH:
                                $contextStack[] = $actualContext;
                                $actualContext  = self::CONTEXT_QUOTEDPAIR;
                                break;
                            // Folding White Space
                            case self::STRING_CR:
                            case self::STRING_SP:
                            case self::STRING_HTAB:
                                if (($token === self::STRING_CR) &&
                                    ((++$i === $rawLength) || ($value[$i] !== self::STRING_LF))
                                ) {
                                    // Fatal error
                                    $this->errors[] = self::ERR_CR_NO_LF;
                                    break;
                                }

                                $this->warnings[] = self::CFWS_FWS;

                                $contextStack[] = $actualContext;
                                $actualContext  = self::CONTEXT_FWS;
                                $tokenPrev      = $token;
                                break;
                            // ctext
                            default:
                                // http://tools.ietf.org/html/rfc5322#section-3.2.3
                                //   ctext           =   %d33-39 /          ; Printable US-ASCII
                                //                       %d42-91 /          ;  characters not including
                                //                       %d93-126 /         ;  "(", ")", or "\"
                                //                       obs-ctext
                                //
                                //   obs-ctext       =   obs-NO-WS-CTL
                                //
                                //   obs-NO-WS-CTL   =   %d1-8 /            ; US-ASCII control
                                //                       %d11 /             ;  characters that do not
                                //                       %d12 /             ;  include the carriage
                                //                       %d14-31 /          ;  return, line feed, and
                                //                       %d127              ;  white space characters
                                $ord = ord($token);
                                if ($ord > 127 || $ord === 0 || $ord === 10) {
                                    // Fatal error
                                    $this->errors[] = self::ERR_EXPECTING_CTEXT;
                                    break;
                                } elseif ($ord < 32 || $ord === 127) {
                                    $this->warnings[] = self::DEPREC_CTEXT;
                                }
                        }

                        break;
                    //-------------------------------------------------------------
                    // Folding White Space
                    //-------------------------------------------------------------
                    case self::CONTEXT_FWS:
                        // http://tools.ietf.org/html/rfc5322#section-3.2.2
                        //   FWS             =   ([*WSP CRLF] 1*WSP) /  obs-FWS
                        //                                          ; Folding white space

                        // But note the erratum:
                        // http://www.rfc-editor.org/errata_search.php?rfc=5322&eid=1908:
                        //   In the obsolete syntax, any amount of folding white space MAY be
                        //   inserted where the obs-FWS rule is allowed.  This creates the
                        //   possibility of having two consecutive "folds" in a line, and
                        //   therefore the possibility that a line which makes up a folded header
                        //   field could be composed entirely of white space.
                        //
                        //   obs-FWS         =   1*([CRLF] WSP)
                        if ($tokenPrev === self::STRING_CR) {
                            if ($token === self::STRING_CR) {
                                // Fatal error
                                $this->errors[] = self::ERR_FWS_CRLF_X2;
                                break;
                            }

                            if (isset($crlf_count) && ++$crlf_count > 1) {
                                // Multiple folds = obsolete FWS
                                $this->warnings[] = self::DEPREC_FWS;
                            } else {
                                $crlf_count = 1;
                            }
                        }

                        switch ($token) {
                            case self::STRING_CR:
                                if ((++$i === $rawLength) || ($value[$i] !== self::STRING_LF)) {
                                    // Fatal error
                                    $this->errors[] = self::ERR_CR_NO_LF;
                                }

                                break;
                            case self::STRING_SP:
                            case self::STRING_HTAB:
                                break;
                            default:
                                if ($tokenPrev === self::STRING_CR) {
                                    // Fatal error
                                    $this->errors[] = self::ERR_FWS_CRLF_END;
                                    break;
                                }

                                if (isset($crlf_count)) {
                                    unset($crlf_count);
                                }

                                $contextPrev   = $actualContext;
                                $actualContext = (int) array_pop($contextStack);    // End of FWS

                                // http://tools.ietf.org/html/rfc5322#section-3.2.2
                                //   Runs of FWS, comment, or CFWS that occur between lexical tokens in a
                                //   structured header field are semantically interpreted as a single
                                //   space character.
                                //
                                // is_email() author's note: This *cannot* mean that we must add a
                                // space to the address wherever CFWS appears. This would result in
                                // any addr-spec that had CFWS outside a quoted string being invalid
                                // for RFC 5321.
                                /*
                                // @todo
                                  if (($actualContext === self::COMPONENT_LOCALPART) ||
                                      ($actualContext === self::COMPONENT_DOMAIN)
                                  ) {
                                    $this->parseData[$actualContext] .= self::STRING_SP;

                                    if (!isset($this->atomList[$actualContext][$this->elementCount])) {
                                        $this->atomList[$actualContext][$this->elementCount] = '';
                                    }
                                    $this->atomList[$actualContext][$element_count] .= self::STRING_SP;

                                    ++$this->elementLength;
                                }
                                */
                                // Look at this token again in the parent context
                                --$i;
                        }

                        $tokenPrev = $token;
                        break;
                    //-------------------------------------------------------------
                    // A context we aren't expecting
                    //-------------------------------------------------------------
                    default:
                        die("Unknown context: $actualContext");
                }

                // No point going on if we've got a fatal error
                if ($this->hasErrors()) {
                    break;
                }
            }

            // Some simple final tests
            if (!$this->hasErrors()) {
                if ($actualContext === self::CONTEXT_QUOTEDSTRING) {
                    // Fatal error
                    $this->errors[] = self::ERR_UNCLOSEDQUOTEDSTR;
                } elseif ($actualContext === self::CONTEXT_QUOTEDPAIR) {
                    // Fatal error
                    $this->errors[] = self::ERR_BACKSLASHEND;
                } elseif ($actualContext === self::CONTEXT_COMMENT) {
                    // Fatal error
                    $this->errors[] = self::ERR_UNCLOSEDCOMMENT;
                } elseif ($actualContext === self::COMPONENT_LITERAL) {
                    // Fatal error
                    $this->errors[] = self::ERR_UNCLOSEDDOMLIT;
                } elseif ($token === self::STRING_CR) {
                    // Fatal error
                    $this->errors[] = self::ERR_FWS_CRLF_END;
                } elseif ($this->parseData[self::COMPONENT_DOMAIN] === '') {
                    // Fatal error
                    $this->errors[] = self::ERR_NODOMAIN;
                } elseif ($this->elementLength === 0) {
                    // Fatal error
                    $this->errors[] = self::ERR_DOT_END;
                } elseif ($hyphenFlag) {
                    // Fatal error
                    $this->errors[] = self::ERR_DOMAINHYPHENEND;
                } elseif (strlen($this->parseData[self::COMPONENT_DOMAIN]) > 255) {
                    // http://tools.ietf.org/html/rfc5321#section-4.5.3.1.2
                    //   The maximum total length of a domain name or number is 255 octets.
                    $this->warnings[] = self::RFC5322_DOMAIN_TOOLONG;
                } elseif (strlen(
                    $this->parseData[self::COMPONENT_LOCALPART].self::STRING_AT.$this->parseData[self::COMPONENT_DOMAIN]
                ) > 254) {
                    // http://tools.ietf.org/html/rfc5321#section-4.1.2
                    //   Forward-path   = Path
                    //
                    //   Path           = "<" [ A-d-l ":" ] Mailbox ">"
                    //
                    // http://tools.ietf.org/html/rfc5321#section-4.5.3.1.3
                    //   The maximum total length of a reverse-path or forward-path is 256
                    //   octets (including the punctuation and element separators).
                    //
                    // Thus, even without (obsolete) routing information, the Mailbox can
                    // only be 254 characters long. This is confirmed by this verified
                    // erratum to RFC 3696:
                    //
                    // http://www.rfc-editor.org/errata_search.php?rfc=3696&eid=1690
                    //   However, there is a restriction in RFC 2821 on the length of an
                    //   address in MAIL and RCPT commands of 254 characters.  Since addresses
                    //   that do not fit in those fields are not normally useful, the upper
                    //   limit on address lengths should normally be considered to be 254.
                    //
                    // http://tools.ietf.org/html/rfc1035#section-2.3.4
                    $this->warnings[] = self::RFC5322_TOOLONG;
                } elseif ($this->elementLength >= 63) {
                    // labels          63 octets or less
                    $this->warnings[] = self::RFC5322_LABEL_TOOLONG;
                }
            }

            if (!$this->hasErrors() && $checkDNS) {
                // Check DNS?
                $this->checkDNS();
            }
        }

        if (!$this->hasErrors()) {
            $status = self::VALID;
        } else {
            $status = array_unique($this->errors);
            $status = (int) max($status);
        }

        $this->parseData['status'] = $status;

        return $status < self::THRESHOLD;
    }

    protected function checkDNS()
    {
        $checked = false;
        if (function_exists('dns_get_record') && (
            !in_array(self::DNSWARN_NO_RECORD, $this->warnings) &&
            !in_array(self::DNSWARN_NO_MX_RECORD, $this->warnings)
        )) {
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
            if ($this->elementCount === 0) {
                // Checking TLD DNS seems to work only if you explicitly check from the root
                $this->parseData[self::COMPONENT_DOMAIN] .= '.';
            }

            // Not using checkdnsrr because of a suspected bug in PHP 5.3 (http://bugs.php.net/bug.php?id=51844)
            $result = @dns_get_record($this->parseData[self::COMPONENT_DOMAIN], DNS_MX);
            if ((is_bool($result) && !(bool) $result)) {
                // Domain can't be found in DNS
                $this->warnings[] = self::DNSWARN_NO_RECORD;
            } else {
                if (count($result) === 0) {
                    // MX-record for domain can't be found
                    $this->warnings[] = self::DNSWARN_NO_MX_RECORD;

                    $result = @dns_get_record($this->parseData[self::COMPONENT_DOMAIN], DNS_A + DNS_CNAME);
                    if (count($result) === 0) {
                        // No usable records for the domain can be found
                        $this->warnings[] = self::DNSWARN_NO_RECORD;
                    }
                } else {
                    $checked = true;
                }
            }
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
            if ($this->elementCount === 0) {
                $this->warnings[] = self::RFC5321_TLD;
            }

            if (isset($this->atomList[self::COMPONENT_DOMAIN][$this->elementCount][0]) &&
                is_numeric($this->atomList[self::COMPONENT_DOMAIN][$this->elementCount][0])
            ) {
                $this->warnings[] = self::RFC5321_TLDNUMERIC;
            }
        }
    }
}
