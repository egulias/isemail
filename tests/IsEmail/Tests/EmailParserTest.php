<?php

namespace IsEmail\Tests;

use IsEmail\EmailParser;

class EmailParserTests extends \PHPUnit_Framework_TestCase
{
    public function testParserExtendsLib()
    {
        $mock = $this->getMock('IsEmail\EmailLexer');
        $parser = new EmailParser($mock);
        $this->assertInstanceOf('JMS\Parser\AbstractParser', $parser);
    }
}
