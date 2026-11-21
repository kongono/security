<?php

declare(strict_types=1);

namespace Kongono\Security;

enum PrincipalKind: string
{
    case Human = 'human';
    case Service = 'service';
    case Agent = 'agent';
    case System = 'system';
}
