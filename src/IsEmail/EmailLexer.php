<?php

namespace IsEmail;

use JMS\Parser\AbstractLexer;

class EmailLexer extends AbstractLexer
{

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
        $ref = new \ReflectionClass($this);
        foreach ($ref->getConstants() as $name => $val) {
            if ($value === $val) {
                return array($val, $name);
            }
        }

        throw new \InvalidArgumentException(sprintf('There is no token with value %s.', json_encode($value)));
    }
}
