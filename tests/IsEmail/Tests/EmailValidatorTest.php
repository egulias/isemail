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
    public function estInvalidEmails($email)
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

    /**
     * @dataProvider getInvalidEmailsWithErrors
     */
    public function testInvalidEmailsWithErrorsCheck($errors, $email)
    {
        $this->assertFalse($this->validator->isValid($email));

        $this->assertEquals($errors, $this->validator->getError());
    }

    public function getInvalidEmailsWithErrors()
    {
        return array(
            array(EmailValidator::ERR_NOLOCALPART, '@example.co.uk'),
            array(EmailValidator::ERR_NODOMAIN, 'example@'),
            array(EmailValidator::ERR_DOMAINHYPHENEND, 'example@example-.co.uk'),
            array(EmailValidator::ERR_DOMAINHYPHENEND, 'example@example-'),
            array(EmailValidator::ERR_CONSECUTIVEATS, 'example@@example.co.uk'),
            array(EmailValidator::ERR_CONSECUTIVEDOTS, 'example..example@example.co.uk'),
            array(EmailValidator::ERR_CONSECUTIVEDOTS, 'example@example..co.uk'),
            array(EmailValidator::ERR_EXPECTING_ATEXT, '<fabien_potencier>@example.fr'),
            array(EmailValidator::ERR_DOT_START, '.example@localhost'),
            array(EmailValidator::ERR_DOT_START, 'example@.localhost'),
            array(EmailValidator::ERR_DOT_END, 'example@localhost.'),
            array(EmailValidator::ERR_DOT_END, 'example.@example.co.uk'),
            array(EmailValidator::ERR_UNCLOSEDCOMMENT, '(example@localhost'),
            array(EmailValidator::ERR_UNCLOSEDQUOTEDSTR, '"example@localhost'),
            array(EmailValidator::ERR_EXPECTING_ATEXT, 'exa"mple@localhost'),
            //This was the original. But atext is not allowed after \n
            //array(EmailValidator::ERR_EXPECTING_ATEXT, "exampl\ne@example.co.uk"),
            array(EmailValidator::ERR_ATEXT_AFTER_CFWS, "exampl\ne@example.co.uk"),
            array(EmailValidator::ERR_EXPECTING_DTEXT, "example@[[]"),
            array(EmailValidator::ERR_ATEXT_AFTER_CFWS, "exampl\te@example.co.uk"),
            array(EmailValidator::ERR_CR_NO_LF, "example@exa\rmple.co.uk"),
            array(EmailValidator::ERR_CR_NO_LF, "example@[\r]"),
            array(EmailValidator::ERR_CR_NO_LF, "exam\rple@example.co.uk"),
            array(EmailValidator::ERR_CR_NO_LF, "\"\r\"@localhost"),
        );
    }
}
