<?php

namespace IsEmail\Tests;

use IsEmail\EmailValidator;

class EmailValidatorTest extends \PHPUnit_Framework_TestCase
{
    protected $validator;

    protected function setUp()
    {
        $this->validator = new EmailValidator();
    }

    protected function tearDown()
    {
        $this->validator = null;
    }

    /**
     * @dataProvider getValidEmails
     */
    public function testValidEmails($email)
    {
        $this->assertTrue($this->validator->isValid($email));
    }

    public function getValidEmails()
    {
        return array(
            array('fabien@symfony.com'),
            array('example@example.co.uk'),
            array('fabien_potencier@example.fr'),
            array('example@localhost'),
            array('example((example))@fakedfake.co.uk'),
        );
    }

    /**
     * @dataProvider getInvalidEmails
     */
    public function testInvalidEmails($email)
    {
        $this->assertFalse($this->validator->isValid($email));
    }

    public function getInvalidEmails()
    {
        return array(
            array('example.@example.co.uk'),
            array('(fabien_potencier@example.fr)'),
            array('example(example)example@example.co.uk'),
            array('.example@localhost'),
            array('ex\ample@localhost'),
            array('example@local\host'),
            array('example@localhost.'),
        );
    }
}
