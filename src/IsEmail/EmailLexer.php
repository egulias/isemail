<?php

namespace IsEmail;

use JMS\Parser\AbstractLexer;

class EmailLexer extends AbstractLexer
{
    const S_AT               = 256;//'@';
    const S_BACKSLASH        = 257;//'\\';
    const S_DOT              = 258;//'.';
    const S_DQUOTE           = 259;//'"';
    const S_OPENPARENTHESIS  = 260;//'(';
    const S_CLOSEPARENTHESIS = 261;//')';
    const S_OPENBRACKET      = 262;//'[';
    const S_CLOSEBRACKET     = 263;//']';
    const S_HYPHEN           = 264;//'-';
    const S_COLON            = 265;//':';
    const S_DOUBLECOLON      = 266;//'::';
    const S_SP               = 267;//' ';
    const S_HTAB             = 268;//"\t";
    const S_CR               = 269;//"\r";
    const S_LF               = 270;//"\n";
    const S_IPV6TAG          = 271;//'IPv6:';
    const S_LOWERTHAN        = 272;//'<'
    const S_GREATERTHAN      = 273;//'>'
    const S_COMMA            = 274;//','
    const S_SEMICOLON        = 274;//';'

    /**
     * US-ASCII visible characters not valid for atext (@link http://tools.ietf.org/html/rfc5322#section-3.2.3)
     *
     * @var array
     */
    protected $nameValue = array(
        '('    => self::S_OPENPARENTHESIS,
        ')'    => self::S_CLOSEPARENTHESIS,
        '<'    => self::S_LOWERTHAN,
        '>'    => self::S_GREATERTHAN,
        '['    => self::S_OPENBRACKET,
        ']'    => self::S_CLOSEBRACKET,
        ':'    => self::S_COLON,
        ';'    => self::S_SEMICOLON,
        '@'    => self::S_AT,
        '\\'   => self::S_BACKSLASH,
        ','    => self::S_COMMA,
        '.'    => self::S_DOT,
        '"'    => self::S_DQUOTE,
        '-'    => self::S_HYPHEN,
        '::'   => self::S_DOUBLECOLON,
        ' '    => self::S_SP,
        '\t'   => self::S_HTAB,
        '\r'   => self::S_CR,
        '\n'   => self::S_LF,
        'IPv6' => self::S_IPV6TAG,
        '<'    => self::S_LOWERTHAN,
        '>'    => self::S_GREATERTHAN,
    );

    public function getName($type)
    {
        if (isset($this->nameValue[$type])) {
            $ref = new \ReflectionClass($this);
            foreach ($ref->getConstants() as $name => $value) {
                if ($value === $this->nameValue[$type]) {
                    return $name;
                }
            }
        }

        throw new \InvalidArgumentException(sprintf('There is no token with value %s.', json_encode($value)));
    }

    /**
     * {@inherit}
     */
    protected function getRegex()
    {
        return '/\w+/';
    }

    /**
     * {@inherit}
     */
    protected function determineTypeAndValue($value)
    {
        if (isset($this->nameValue[$value])) {
            return array($value, $this->nameValue[$value]);
        }

        throw new \InvalidArgumentException(sprintf('There is no token with value %s.', json_encode($value)));
    }
}
