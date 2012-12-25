<?php

namespace IsEmail;

use JMS\Parser\AbstractParser;

class EmailParser extends AbstractParser
{
    // Address contains deprecated elements but may still be valid in restricted contexts
    const DEPREC_LOCALPART        = 33;
    const DEPREC_FWS              = 34;
    const DEPREC_QTEXT            = 35;
    const DEPREC_QP               = 36;
    const DEPREC_COMMENT          = 37;
    const DEPREC_CTEXT            = 38;
    const DEPREC_CFWS_NEAR_AT     = 49;

    // The address is only valid according to the broad definition of RFC 5322. It is otherwise invalid.
    const RFC5322_LOCAL_TOOLONG   = 64;
    const RFC5322_LABEL_TOOLONG   = 63;
    const RFC5322_DOMAIN          = 65;
    const RFC5322_TOOLONG         = 66;
    const RFC5322_DOMAIN_TOOLONG  = 68;
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


    protected $warnings = array();
    protected $index = 0;

    /**
     *  {@inherit}
     */
    public function parseInternal()
    {
        echo 'EmailParser' . PHP_EOL;
        $this->lexer->moveNext();
        if ($this->lexer->token[0] === EmailLexer::S_AT) {
            throw new \InvalidArgumentException("ERR_NOLOCALPART");
        }
        $this->parseLocalPart();
        $this->parseDomainPart();

        die('end');
        return array('p');

    }

    private function parseDomainPart()
    {
        $legth = 0;
        $this->lexer->moveNext();
        $legth++;
        if ($this->lexer->token[0] === EmailLexer::S_AT) {
            throw new \InvalidArgumentException("ERR_CONSECUTIVEATS");
        }
        if ($this->lexer->token[0] === EmailLexer::S_DOT) {
            throw new \InvalidArgumentException("ERR_DOT_START");
        }
        // Comments at the start of the domain are deprecated in the text
        // Comments at the start of a subdomain are obs-domain
        // (http://tools.ietf.org/html/rfc5322#section-3.4.1)
        if ($this->lexer->token[0] === EmailLexer::S_OPENPARENTHESIS) {
            $this->warnings[] = self::DEPREC_COMMENT;
            $this->lexer->moveNext();
            $legth++;
        }
        if ($this->lexer->token[0] === EmailLexer::S_OPENQBRACKET) {
            throw new \InvalidArgumentException("ERR_EXPECTING_ATEXT");
        }

        do {
            $prev = $this->lexer->getPrevious();
            if ($this->lexer->token[0] === EmailLexer::S_OPENPARENTHESIS) {
                $this->warnings[] = self::CFWS_COMMENT;
                $this->parseComments();
            }
            if ($this->lexer->token[0] === EmailLexer::S_DOT && $this->isNext(EmailLexer::S_DOT)) {
                throw new \InvalidArgumentException("ERR_CONSECUTIVEDOTS");
            }
            if ($prev[0] === EmailLexer::S_HYPHEN) {
                throw new \InvalidArgumentException("ERR_DOMAINHYPHENEND");
            }
            if ($this->lexer->token[0] === EmailLexer::S_OPENQBRACKET) {
                //throw new \InvalidArgumentException("ERR_EXPECTING_ATEXT");
                $this->parseDomainLiteral();
            }
            $legth++;

        } while ($this->lexer->moveNext());

        if ($legth > self::RFC5322_LABEL_TOOLONG) {
            $this->warnings[] = self::RFC5322_LOCAL_TOOLONG;
        }
    }

    private function parseDomainLiteral()
    {
    }

    private function parseLocalPart()
    {
        $legth = 0;
        while ($this->lexer->token[0] !== EmailLexer::S_AT) {
            var_dump($this->lexer->token);
            if ($this->lexer->token[0] === EmailLexer::S_DOT && $this->index == 0) {
                throw new \InvalidArgumentException("ERR_DOT_START");
            }
            if ($this->lexer->token[0] === EmailLexer::S_DQUOTE) {
                if ($this->index > 0) {
                    throw new \InvalidArgumentException("ERR_EXPECTING_ATEXT");
                }
                if ($this->index == 0) {
                    $this->warnings[] = self::RFC5321_QUOTEDSTRING;
                }
                $this->warnings[] = self::DEPREC_LOCALPART;
            }
            //Comments
            if ($this->lexer->token[0] === EmailLexer::S_OPENPARENTHESIS) {
                $this->parseComments();
            } elseif ($this->lexer->token[0] === EmailLexer::S_DOT) {
                if ($this->lexer->isNext(EmailLexer::S_DOT)) {
                    throw new \InvalidArgumentException("ERR_CONSECUTIVEDOTS");
                } elseif ($this->lexer->isNext(EmailLexer::S_AT)) {
                    throw new \InvalidArgumentException("ERR_DOT_END");
                }
            }

            if ($this->isCRLF()) {
                die('p');
                $this->parseFWS();
            }

            $this->index++;
            $legth++;
            $this->lexer->moveNext();
        }

        if ($legth > self::RFC5322_LOCAL_TOOLONG) {
            $this->warnings[] = self::RFC5322_LOCAL_TOOLONG;
        }

    }

    private function parseComments()
    {
        $this->warnings[] = self::CFWS_COMMENT;
        while (!$this->lexer->isNext(EmailLexer::S_CLOSEPARENTHESIS)) {
            try {
                $this->lexer->find(EmailLexer::S_CLOSEPARENTHESIS);
            } catch (\RuntimeException $e) {
                throw new \InvalidArgumentException(
                    sprintf("Expected %s, but found none", EmailLexer::S_CLOSEPARENTHESIS)
                );
            }
            $this->lexer->moveNext();

            //scaping in a comment
            if ($this->lexer->token[0] === EmailLexer::S_BACKSLASH) {
                if ($this->lexer->isNextAny(array(EmailLexer::S_SP, EmailLexer::S_HTAB, EmailLexer::C_DEL))) {
                    $this->warnings[] = self::DEPREC_QP;
                }
                $this->parseFWS();
            }
        }

        $this->cFWSNearAt();
    }

    private function parseFWS()
    {
        if ($this->lexer->token[0] === EmailLexer::S_SP || $this->lexer->token[0] === EmailLexer::S_HTAB) {
            $this->warnings[] = self::CFWS_FWS;
        } elseif ($this->isCRLF()) {
            throw new \InvalidArgumentException("ERR_CR_NO_LF");
        } elseif ($this->lexer->token[0] === EmailLexer::S_CR && $this->lexer->token[0] === EmailLexer::S_CR) {
            throw new \InvalidArgumentException("ERR_FWS_CRLF_X2");
        } elseif ($this->lexer->token[0] === EmailLexer::S_LF || $this->lexer->token[0] === EmailLexer::C_NUL) {
            throw new \InvalidArgumentException("ERR_EXPECTING_CTEXT");
        } elseif (!$this->lexer->isNext(EmailLexer::S_SP) && !$this->lexer->isNext(EmailLexer::S_HTAB)) {
            throw new \InvalidArgumentException("ERR_FWS_CRLF_END");
        }

        $this->cFWSNearAt();

    }

    private function cFWSNearAt()
    {
        if ($this->lexer->isNext(EmailLexer::S_AT)) {
            $this->warnings[] = self::DEPREC_CFWS_NEAR_AT;
        }
    }

    private function isCRLF()
    {
        if ($this->lexer->token[0] === EmailLexer::S_CR && !$this->lexer->isNext(EmailLexer::S_LF)) {
            return true;
        }

        return false;
    }
}
