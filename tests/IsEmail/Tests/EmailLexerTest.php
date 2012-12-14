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
}
