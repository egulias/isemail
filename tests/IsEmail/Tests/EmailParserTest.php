<?php

namespace IsEmail\Tests;

use IsEmail\EmailParser;

class EmailParserTests extends \PHPUnit_Framework_TestCase
{

    public function testParserExtendsLib()
    {
        $parser = new EmailParser();
        $this->assertInstanceOf('JMS\Parser\AbstractParser', $parser);
    }

    public function testEmailTokens()
    {
        $parser = new EmailParser();

    }
}
