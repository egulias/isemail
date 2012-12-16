<?php

namespace IsEmail;

/**
 * EmailValidator
 *
 * @author Eduardo Gulias Davis <me@egulias.com>
 */
class EmailValidator
{

    protected $parser;
    protected $warnings = array();
    protected $error = array();

    public function __construct()
    {
        $this->parser = new EmailParser(new EmailLexer());
    }

    public function isValid($email, $checkDNS = false, $strict = false)
    {
        try {
            $this->warnings = $this->parser->parse((string)$email);
        } catch (\Exception $e) {
            $this->error = $e->getMessage();
            var_dump($this->error);
            return false;
        }

        if ($checkDNS) {
            $this->checkDNS();
        }

        return ($strict) ? (true && empty($this->warnings)) : true;
    }

    public function getWarnings()
    {
        return $this->warnings;
    }

    public function getError()
    {
        return $this->error;
    }

    protected function checkDNS()
    {
        $this->warnings[] = 'DNS ERROR';
    }
}
