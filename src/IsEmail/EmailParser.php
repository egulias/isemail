<?php

namespace IsEmail;

use JMS\Parser\AbstractParser;

/**
 * EmailParser
 *
 * @author Eduardo Gulias Davis <me@egulias.com>
 */
class EmailParser extends AbstractParser
{
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
    const DEPREC                  = 63;

    // The address is only valid according to the broad definition of RFC 5322. It is otherwise invalid.
    const RFC5322_LOCAL_TOOLONG   = 64;
    const RFC5322_LABEL_TOOLONG   = 63;
    const RFC5322_DOMAIN          = 65;
    const RFC5322_TOOLONG         = 66;
    const RFC5322_DOMAIN_TOOLONG  = 255;
    const RFC5322_DOMAINLITERAL   = 70;
    const RFC5322_DOMLIT_OBSDTEXT = 71;
    const RFC5322_IPV6_GRPCOUNT   = 72;
    const RFC5322_IPV6_2X2XCOLON  = 73;
    const RFC5322_IPV6_BADCHAR    = 74;
    const RFC5322_IPV6_MAXGRPS    = 75;
    const RFC5322_IPV6_COLONSTRT  = 76;
    const RFC5322_IPV6_COLONEND   = 77;
    const RFC5321_QUOTEDSTRING    = 78;
    const RFC5321_IPV6DEPRECATED  = 13;

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

    protected $warnings = array();
    protected $localPart = '';
    protected $domainPart = '';
    protected $index = 0;

    /**
     *  {@inherit}
     */
    public function parseInternal()
    {
        $this->lexer->moveNext();
        if ($this->lexer->token[0] === EmailLexer::S_AT) {
            throw new \InvalidArgumentException('ERR_NOLOCALPART');
        }
        $this->parseLocalPart();
        $this->parseDomainPart();

        if (strlen($this->localPart . '@' . $this->domainPart) > 254) {
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
        }

        return array('local' => $this->localPart, 'domain' => $this->domainPart);
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

    public function getParsedDomainPart()
    {
        return $this->domainPart;
    }

    /**
     * parseDomainPart
     *
     */
    private function parseDomainPart()
    {
        $domain = '';
        $this->lexer->moveNext();
        if ($this->lexer->token[0] === EmailLexer::S_AT) {
            throw new \InvalidArgumentException('ERR_CONSECUTIVEATS');
        }
        if ($this->lexer->token[0] === EmailLexer::S_DOT) {
            throw new \InvalidArgumentException('ERR_DOT_START');
        }
        if ($this->lexer->token[0] === EmailLexer::S_EMPTY) {
            throw new \InvalidArgumentException('ERR_NODOMAIN');
        }
        // Comments at the start of the domain are deprecated in the text
        // Comments at the start of a subdomain are obs-domain
        // (http://tools.ietf.org/html/rfc5322#section-3.4.1)
        if ($this->lexer->token[0] === EmailLexer::S_OPENPARENTHESIS) {
            $this->warnings[] = self::DEPREC_COMMENT;
            $this->parseComments();
        }

        do {
            $prev = $this->lexer->getPrevious();
            if ($this->lexer->token[0] === EmailLexer::S_OPENQBRACKET && $prev[0] !== EmailLexer::S_AT) {
                throw new \InvalidArgumentException('ERR_EXPECTING_ATEXT');
            }
            if ($this->lexer->token[0] === EmailLexer::S_OPENPARENTHESIS) {
                //$this->warnings[] = self::CFWS_COMMENT;
                $this->parseComments();
                $this->lexer->moveNext();
            }
            if ($this->lexer->token[0] === EmailLexer::S_DOT && $this->lexer->isNext(EmailLexer::S_DOT)) {
                throw new \InvalidArgumentException('ERR_CONSECUTIVEDOTS');
            }
            if ($this->lexer->token[0] === EmailLexer::S_HYPHEN && $this->lexer->isNext(EmailLexer::S_DOT)) {
                throw new \InvalidArgumentException('ERR_DOMAINHYPHENEND');
            }
            if ($this->lexer->token[0] === EmailLexer::S_OPENQBRACKET) {
                try {
                    $this->lexer->find(EmailLexer::S_CLOSEQBRACKET);
                } catch (\RuntimeException $e) {
                    throw new \InvalidArgumentException('ERR_EXPECTING_DOMLIT_CLOSE');
                }
                $this->parseDomainLiteral();
            }

            if ($this->lexer->token[0] === EmailLexer::S_OPENBRACKET) {
                try {
                    $this->lexer->find(EmailLexer::S_CLOSEBRACKET);
                } catch (\RuntimeException $e) {
                    throw new \InvalidArgumentException('ERR_EXPECTING_DOMLIT_CLOSE');
                }
                $this->parseDomainLiteral();
            }

            if ($this->lexer->token[0] === EmailLexer::S_BACKSLASH && $this->lexer->isNext(EmailLexer::GENERIC)) {
                throw new \InvalidArgumentException('ERR_EXPECTING_ATEXT');
            }

            if (
                $this->lexer->token[0] === EmailLexer::S_DOT &&
                $prev[0] === EmailLexer::GENERIC &&
                strlen($prev[2]) > 63
            ) {
                $this->warnings[] = self::RFC5322_LABEL_TOOLONG;
            }

            if (
                $this->lexer->token[0] === EmailLexer::S_SP ||
                $this->lexer->token[0] === EmailLexer::S_HTAB ||
                $this->lexer->token[0] === EmailLexer::S_CR ||
                $this->lexer->token[0] === EmailLexer::S_LF ||
                $this->lexer->token[0] === EmailLexer::CRLF
            ) {
                $this->parseFWS();
            }
            $domain .= $this->lexer->token[2];
            $this->lexer->moveNext();
        } while ($this->lexer->token);

        $last = $this->lexer->getPrevious();
        $length = strlen($last[2]);

        if ($last[0] === EmailLexer::S_DOT) {
            throw new \InvalidArgumentException('ERR_DOT_END');
        }
        if ($last[0] === EmailLexer::S_HYPHEN) {
            throw new \InvalidArgumentException('ERR_DOMAINHYPHENEND');
        }
        if ($length > 254) {
            $this->warnings[] = self::RFC5322_DOMAIN_TOOLONG;
        }
        if ($last[0] === EmailLexer::S_CR) {
            throw new \InvalidArgumentException('ERR_FWS_CRLF_END');
        }
        $this->domainPart = $domain;
    }

    private function parseDomainLiteral()
    {
        $IPv6TAG = false;
        $addressLiteral = '';
        if ($this->lexer->isNext(EmailLexer::S_COLON)) {
            // Address starts with a single colon
            $this->warnings[] = self::RFC5322_IPV6_COLONSTRT;
        }
        if ($this->lexer->isNext(EmailLexer::S_IPV6TAG)) {
            try {
                $lexer = clone $this->lexer;
                $lexer->moveNext();
                if ($lexer->isNext(EmailLexer::S_DOUBLECOLON)) {
                    $this->warnings[] = self::RFC5322_IPV6_COLONSTRT;
                }
            } catch (\Exception $e) {
                break;
            }

        }
        do {
            if ($this->lexer->token[0] === EmailLexer::C_NUL) {
                throw new \InvalidArgumentException('ERR_EXPECTING_DTEXT');
            } elseif (
                $this->lexer->token[0] === EmailLexer::INVALID ||
                $this->lexer->token[0] === EmailLexer::C_DEL   ||
                $this->lexer->token[0] === EmailLexer::S_LF
            ) {
                $this->warnings[] = self::RFC5322_DOMLIT_OBSDTEXT;
            }
            if ($this->lexer->isNextAny(array(EmailLexer::S_OPENQBRACKET, EmailLexer::S_OPENBRACKET))) {
                throw new \InvalidArgumentException('ERR_EXPECTING_DTEXT');
            }
            if ($this->lexer->isNextAny(array(EmailLexer::S_HTAB, EmailLexer::S_SP))) {
                $this->warnings[] = self::CFWS_FWS;
                $this->parseFWS();
            }
            if ($this->lexer->isNext(EmailLexer::S_CR)) {
                throw new \InvalidArgumentException("ERR_CR_NO_LF");
            }
            if ($this->lexer->token[0] === EmailLexer::S_BACKSLASH) {
                $this->warnings[] = self::RFC5322_DOMLIT_OBSDTEXT;
                $addressLiteral .= $this->lexer->token[2];
                $this->lexer->moveNext();
                $this->validateQuotedPair();
            }
            if ($this->lexer->token[0] === EmailLexer::S_CLOSEQBRACKET) {
                break;
            }
            if (
                $this->lexer->token[0] === EmailLexer::S_SP ||
                $this->lexer->token[0] === EmailLexer::S_HTAB ||
                $this->lexer->token[0] === EmailLexer::CRLF
            ) {
                $this->parseFWS();
            }
            if ($this->lexer->token[0] === EmailLexer::S_IPV6TAG) {
                $IPv6TAG = true;
            }
            $addressLiteral .= $this->lexer->token[2];

        } while ($this->lexer->moveNext());
        // Revision 2.7: Daniel Marschall's new IPv6 testing strategy
        $prev = $this->lexer->getPrevious();
        if ($prev[0] === EmailLexer::S_COLON) {
            // Address ends with a single colon
            $this->warnings[] = self::RFC5322_IPV6_COLONEND;
        }

        $addressLiteral = str_replace('[', '', $addressLiteral);

        $maxGroups = 8;
        $matchesIP  = array();
        $index = 0;

        // Extract IPv4 part from the end of the address-literal (if there is one)
        if (preg_match(
            '/\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/',
            $addressLiteral,
            $matchesIP
        ) > 0
        ) {
            $index = strrpos($addressLiteral, $matchesIP[0]);
            if ($index === 0) {
                $this->warnings[] = EmailValidator::RFC5321_ADDRESSLITERAL;
                return;
            }
            // Convert IPv4 part to IPv6 format for further testing
            $addressLiteral = substr($addressLiteral, 0, $index) . '0:0';
        }

        if (!$IPv6TAG) {
            $this->warnings[] = self::RFC5322_DOMAINLITERAL;
            return;
        }

        $this->warnings[] = EmailValidator::RFC5321_ADDRESSLITERAL;

        $IPv6       = substr($addressLiteral, 5);
        //Daniel Marschall's new IPv6 testing strategy
        $matchesIP  = explode(':', $IPv6);
        $groupCount = count($matchesIP);
        $colons     = strpos($IPv6, '::');
        $matches = array();

        if (count(preg_grep('/^[0-9A-Fa-f]{0,4}$/', $matchesIP, PREG_GREP_INVERT)) !== 0) {
            // Check for unmatched characters
            $this->warnings[] = self::RFC5322_IPV6_BADCHAR;
        }

        if ($colons === false) {
            // We need exactly the right number of groups
            if ($groupCount !== $maxGroups) {
                $this->warnings[] = self::RFC5322_IPV6_GRPCOUNT;
            }
        } else {
            if ($colons !== strrpos($IPv6, '::')) {
                $this->warnings[] = self::RFC5322_IPV6_2X2XCOLON;
            } else {
                if ($colons === 0 || $colons === (strlen($IPv6) - 2)) {
                    // RFC 4291 allows :: at the start or end of an address
                    //with 7 other groups in addition
                    ++$maxGroups;
                }

                if ($groupCount > $maxGroups) {
                    $this->warnings[] = self::RFC5322_IPV6_MAXGRPS;
                } elseif ($groupCount === $maxGroups) {
                    // Eliding a single "::"
                    $this->warnings[] = self::RFC5321_IPV6DEPRECATED;
                }
            }
        }


        return $addressLiteral;
    }

    /**
     * validateQuotedPair
     *
     * @TODO This needs to be reviewed
     */
    private function validateQuotedPair()
    {
        if (!($this->lexer->token[0] === EmailLexer::INVALID  || $this->lexer->token[0] === EmailLexer::C_DEL)) {
            throw new \InvalidArgumentException('ERR_EXPECTING_QPAIR');
        }
        // SP & HTAB are allowed
        $this->warnings[] = self::DEPREC_QP;
    }

    private function parseLocalPart()
    {
        $closingQuote = false;
        while ($this->lexer->token[0] !== EmailLexer::S_AT) {
            $previous = $this->lexer->getPrevious();
            if ($this->lexer->token[0] === EmailLexer::S_DOT && !$this->lexer->getPrevious()) {
                throw new \InvalidArgumentException('ERR_DOT_START');
            }
            if ($this->lexer->token[0] === EmailLexer::S_DQUOTE) {
                if (!$closingQuote) {
                    if ($this->lexer->isNext(EmailLexer::GENERIC) && $previous[0] === EmailLexer::GENERIC) {
                        throw new \InvalidArgumentException('ERR_EXPECTING_ATEXT');
                    }
                    $this->warnings[] = EmailValidator::RFC5321_QUOTEDSTRING;
                    try {
                        $this->lexer->find(EmailLexer::S_DQUOTE);
                        $closingQuote = true;
                    } catch (\Exception $e) {
                        throw new \InvalidArgumentException('ERR_UNCLOSEDQUOTEDSTR');
                    }
                }
                //if ($previous[0] != EmailLexer::S_BACKSLASH) {
                //    throw new \InvalidArgumentException('ERR_EXPECTING_ATEXT');
                //}
                //$this->warnings[] = self::DEPREC_LOCALPART;
            }
            //Comments
            if ($this->lexer->token[0] === EmailLexer::S_OPENPARENTHESIS) {
                $this->parseComments();
            }

            if ($this->lexer->token[0] === EmailLexer::S_DOT && $this->lexer->isNext(EmailLexer::S_DOT)) {
                throw new \InvalidArgumentException('ERR_CONSECUTIVEDOTS');
            }

            if ($this->lexer->token[0] === EmailLexer::S_DOT && $this->lexer->isNext(EmailLexer::S_AT)) {
                throw new \InvalidArgumentException('ERR_DOT_END');
            }

            if ($this->lexer->token[0] === EmailLexer::S_BACKSLASH) {
                //if ($this->lexer->isNextAny(array(EmailLexer::S_SP, EmailLexer::S_HTAB, EmailLexer::C_DEL))) {
                //    $this->warnings[] = self::DEPREC_QP;
                //}
                if ($this->lexer->isNext(EmailLexer::GENERIC)) {
                    throw new \InvalidArgumentException('ERR_EXPECTING_ATEXT');
                }
            }

            if ($this->lexer->isNextAny(
                array(
                    EmailLexer::INVALID, EmailLexer::S_LOWERTHAN, EmailLexer::S_GREATERTHAN
                )
            )
            ) {
                throw new \InvalidArgumentException('ERR_EXPECTING_ATEXT');
            }

            if (
                $this->lexer->token[0] === EmailLexer::S_SP ||
                $this->lexer->token[0] === EmailLexer::S_HTAB ||
                $this->lexer->token[0] === EmailLexer::S_CR ||
                $this->lexer->token[0] === EmailLexer::S_LF ||
                $this->lexer->token[0] === EmailLexer::CRLF
            ) {
                $this->parseFWS();
            }

            $this->lexer->moveNext();
        }

        $prev = $this->lexer->getPrevious();
        if ($prev[1] > self::RFC5322_LOCAL_TOOLONG) {
            $this->warnings[] = self::RFC5322_LOCAL_TOOLONG;
        }
    }

    /**
     * parseComments
     *
     * @return string the the comment
     */
    private function parseComments()
    {
        $this->warnings[] = self::CFWS_COMMENT;
        while (!$this->lexer->isNext(EmailLexer::S_CLOSEPARENTHESIS)) {
            try {
                $this->lexer->find(EmailLexer::S_CLOSEPARENTHESIS);
            } catch (\RuntimeException $e) {
                throw new \InvalidArgumentException('ERR_UNCLOSEDCOMMENT');
            }
            //$this->lexer->moveNext();

            //scaping in a comment
            if ($this->lexer->token[0] === EmailLexer::S_BACKSLASH) {
                if ($this->lexer->isNextAny(array(EmailLexer::S_SP, EmailLexer::S_HTAB, EmailLexer::C_DEL))) {
                    $this->warnings[] = self::DEPREC_QP;
                }
            }
            $this->lexer->moveNext();
        }
        $this->lexer->moveNext();
        if ($this->lexer->isNext(EmailLexer::GENERIC)) {
            throw new \InvalidArgumentException('ERR_EXPECTING_ATEXT');
        }

        if ($this->lexer->isNext(EmailLexer::S_AT)) {
            $this->warnings[] = self::DEPREC_CFWS_NEAR_AT;
        }
    }

    /**
     * parseFWS
     *
     * @throw InvalidArgumentException
     */
    private function parseFWS()
    {
        $previous = $this->lexer->getPrevious();

        if ($this->lexer->token[0] === EmailLexer::CRLF && $this->lexer->isNext(EmailLexer::CRLF)) {
            throw new \InvalidArgumentException("ERR_FWS_CRLF_X2");
        }
        if ($this->lexer->token[0] === EmailLexer::S_CR) {
            throw new \InvalidArgumentException("ERR_CR_NO_LF");
        }
        if (
            !$this->lexer->isNextAny(array(EmailLexer::S_SP, EmailLexer::S_HTAB)) &&
            $this->lexer->token[0] === EmailLexer::CRLF ) {
            throw new \InvalidArgumentException("ERR_FWS_CRLF_END");
        }
        if ($this->lexer->isNext(EmailLexer::GENERIC) && $this->lexer->token[0] !== EmailLexer::S_SP) {
            throw new \InvalidArgumentException("ERR_ATEXT_AFTER_CFWS");
        }
        if ($this->lexer->token[0] === EmailLexer::S_LF || $this->lexer->token[0] === EmailLexer::C_NUL) {
            throw new \InvalidArgumentException('ERR_EXPECTING_CTEXT');
        }

        if ($this->lexer->isNext(EmailLexer::S_AT) || $previous[0]  === EmailLexer::S_AT) {
            $this->warnings[] = self::DEPREC_CFWS_NEAR_AT;
        } else {
            $this->warnings[] = self::CFWS_FWS;
        }

    }
}
