<?php

namespace IsEmail\Tests;

use IsEmail\EmailLexer;

class EmailLexerTests extends \PHPUnit_Framework_TestCase
{

    public function testLexerExtendsLib()
    {
        $lexer = new EmailLexer();
        $this->assertInstanceOf('JMS\Parser\AbstractLexer', $lexer);
    }

    /**
     *  @dataProvider getTokens
     *
     */
    public function testLexerTokens($str, $token)
    {
        $lexer = new EmailLexer();
        $lexer->setInput($str);
        $lexer->moveNext();
        $this->assertEquals($token, $lexer->token[0]);
    }

    public function getTokens()
    {
        return array(
            array("foo", EmailLexer::GENERIC),
            array("\r", EmailLexer::S_CR),
            array("\t", EmailLexer::S_HTAB),
            array("\r\n", EmailLexer::CRLF),
            array("\n", EmailLexer::S_LF),
            array(" ", EmailLexer::S_SP),
            array("@", EmailLexer::S_AT),
            array("IPv6", EmailLexer::S_IPV6TAG),
            array("::", EmailLexer::S_DOUBLECOLON),
            array(":", EmailLexer::S_COLON),
            array(".", EmailLexer::S_DOT),
            array("\"", EmailLexer::S_DQUOTE),
            array("-", EmailLexer::S_HYPHEN),
            array("\\", EmailLexer::S_BACKSLASH),
            array("(", EmailLexer::S_OPENPARENTHESIS),
            array(")", EmailLexer::S_CLOSEPARENTHESIS),
            array('<', EmailLexer::S_LOWERTHAN),
            array('>', EmailLexer::S_GREATERTHAN),
            array('[', EmailLexer::S_OPENBRACKET),
            array(']', EmailLexer::S_CLOSEBRACKET),
            array(';', EmailLexer::S_SEMICOLON),
            array(',', EmailLexer::S_COMMA),
            array('<', EmailLexer::S_LOWERTHAN),
            array('>', EmailLexer::S_GREATERTHAN),
            array('{', EmailLexer::S_OPENQBRACKET),
            array('}', EmailLexer::S_CLOSEQBRACKET),
            array('',  EmailLexer::S_EMPTY)
        );
    }
}
