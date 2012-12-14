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

    const STRING_AT               = 256;//'@';
    const STRING_BACKSLASH        = 257;//'\\';
    const STRING_DOT              = 258;//'.';
    const STRING_DQUOTE           = 259;//'"';
    const STRING_OPENPARENTHESIS  = 260;//'(';
    const STRING_CLOSEPARENTHESIS = 261;//')';
    const STRING_OPENSQBRACKET    = 262;//'[';
    const STRING_CLOSESQBRACKET   = 263;//']';
    const STRING_HYPHEN           = 264;//'-';
    const STRING_COLON            = 265;//':';
    const STRING_DOUBLECOLON      = 266;//'::';
    const STRING_SP               = 267;//' ';
    const STRING_HTAB             = 268;//"\t";
    const STRING_CR               = 269;//"\r";
    const STRING_LF               = 270;//"\n";
    const STRING_IPV6TAG          = 271;//'IPv6:';
    const STRING_LOWERTHAN        = 272;
    const STRING_GREATERTHAN      = 273;
    const STRING_COMMA            = 274;

    /**
     * US-ASCII visible characters not valid for atext (@link http://tools.ietf.org/html/rfc5322#section-3.2.3)
     *
     * @var array
     */
    protected $specialCharacters = array(
        '('  => self::STRING_OPENPARENTHESIS,
        ')'  => self::STRING_CLOSEPARENTHESIS,
        '<'  => self::STRING_LOWERTHAN,
        '>'  => self::STRING_GREATERTHAN,
        '['  => self::STRING_OPENBRACKET,
        ']'  => self::STRING_CLOSEBRACKET,
        ':'  => self::STRING_COLON,
        ';'  => self::STRING_SEMICOLON,
        '@'  => self::STRING_AT,
        '\\' => self::STRNG_BACKSLASH,
        ','  => self::STRING_COMMA,
        '.'  => self::STRING_DOT,
        '"'  => self::STRING_DQUOTE
    );

    /**
     *  {@inherit}
     */
    public function parseInternal()
    {

    }
}
