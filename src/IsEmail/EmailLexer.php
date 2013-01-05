<?php

namespace IsEmail;

use JMS\Parser\AbstractLexer;

class EmailLexer extends AbstractLexer
{
    //ASCII values
    const C_DEL = 127;
    const C_NUL = 0;


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
    const S_SEMICOLON        = 275;//';'
    const S_OPENQBRACKET     = 276;//'[';
    const S_CLOSEQBRACKET    = 277;//']';
    const S_EMPTY            = 278;//'';

    /**
     * US-ASCII visible characters not valid for atext (@link http://tools.ietf.org/html/rfc5322#section-3.2.3)
     *
     * @var array
     */
    protected $charValue = array(
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
        '{'    => self::S_OPENQBRACKET,
        '}'    => self::S_CLOSEQBRACKET,
        ''     => self::S_EMPTY
    );

    protected $previous;

    public function setInput($str)
    {
        $tokens = str_split($str);

        $this->tokens = array();
        foreach ($tokens as $i => $chr) {
            $token = array();
            $token[1] = $i;
            list($token[2], $token[0]) = $this->determineTypeAndValue($chr);
            $this->tokens[] = $token;
        }
        $this->reset();
    }

    public function getName($type)
    {
        $ref = new \ReflectionClass($this);
        foreach ($ref->getConstants() as $name => $value) {
            if ($value === $type) {
                return $name;
            }
        }
        if ($type <= 127) {
            return chr($type);
        }

        throw new \InvalidArgumentException(sprintf('There is no token with value %s.', json_encode($type)));
    }

    public function find($type)
    {
        $search = clone $this;
        $search->skipUntil($type);
    }

    /**
     * getPrevious
     *
     * @return array token
     */
    public function getPrevious()
    {
        return $this->previous;
    }

    /**
     * moveNext
     *
     * @return mixed
     */
    public function moveNext()
    {
        $this->previous = $this->token;

        return parent::moveNext();
    }

    public function isNext($type)
    {
        $type = array_search($type, $this->charValue);

        return parent::isNext($type);
    }

    public function isNextAny(array $types)
    {
        foreach ($types as $i => $type) {
            $types[$i] = array_search($type, $this->charValue);
        }

        return parent::isNextAny($types);
    }

    /**
     * {@inherit}
     */
    protected function getRegex()
    {
        return '//';
    }

    /**
     * {@inherit}
     */
    protected function determineTypeAndValue($value)
    {
        $ascii = ord($value);
        if (isset($this->charValue[$value])) {
            return array($value, $this->charValue[$value]);
        } elseif ($ascii <= 127) {
            return array($value, $ascii);
        }

        throw new \InvalidArgumentException(sprintf('There is no token with value %s.', json_encode($value)));
    }
}
