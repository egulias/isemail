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


    protected $warnings = array();

    /**
     *  {@inherit}
     */
    public function parseInternal()
    {
        while (!$this->lexer->isNext(258)) {
            $this->lexer->moveNext();
            if ($this->lexer->token[0] === EmailLexer::S_DOT) {
                throw new \InvalidArgumentException("ERR_DOT_START");
            }
            if ($this->lexer->token[0] === EmailLexer::S_AT) {
                return;
            }
            $this->parseLocalPart();
        }

    }

    private function parseLocalPart()
    {
        $lexer = clone $this->lexer;

        //Comments
        if ($lexer->token[0] === EmailLexer::S_OPENPARENTHESIS) {
            $this->parseComments();
        } elseif ($lexer->token[0] === EmailLexer::S_DOT) {
            if ($lexer->isNext(EmailLexer::S_DOT)) {
                throw new \InvalidArgumentException("ERR_CONSECUTIVEDOTS");
            } elseif ($lexer->isNext(EmailLexer::S_AT)) {
                throw new \InvalidArgumentException("ERR_DOT_END");
            }
        }
    }

    private function parseComments()
    {
        $lexer = clone $this->lexer;
        $this->warnings[] = self::CFWS_COMMENT;
        while (!$lexer->isNext(EmailLexer::S_CLOSEPARENTHESIS)) {
            try {
                $lexer->find(EmailLexer::S_CLOSEPARENTHESIS);
            } catch (\RuntimeException $e) {
                throw new \InvalidArgumentException(
                    sprintf("Expected %s, but found none", EmailLexer::S_CLOSEPARENTHESIS)
                );
            }
            $lexer->moveNext();

            //scaping in a comment
            if ($lexer->token[0] === EmailLexer::S_BACKSLASH) {
                if ($lexer->isNextAny(array(EmailLexer::S_SP, EmailLexer::S_HTAB, EmailLexer::C_DEL))) {
                    $this->warnings[] = self::DEPREC_QP;
                }
            } elseif ($lexer->token[0] === EmailLexer::S_SP || $lexer->token[0] === EmailLexer::S_HTAB) {
                $this->warnings[] = self::CFWS_FWS;
            } elseif ($lexer->token[0] === EmailLexer::S_CR && !$lexer->isNext(EmailLexer::S_LF)) {
                throw new \InvalidArgumentException("ERR_CR_NO_LF");
            } elseif ($lexer->token[0] === EmailLexer::S_LF || $lexer->token[0] === EmailLexer::C_NUL) {
                throw new \InvalidArgumentException("ERR_EXPECTING_CTEXT");
            }
        }
    }
}
