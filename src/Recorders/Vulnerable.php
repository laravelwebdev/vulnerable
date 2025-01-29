<?php

declare(strict_types=1);

namespace HT\Pulse\Vulnerable\Recorders;

use Illuminate\Support\Facades\Process;
use Laravel\Pulse\Events\SharedBeat;
use Laravel\Pulse\Pulse;
use RuntimeException;

final class Vulnerable
{
    public string $listen = SharedBeat::class;

    public function __construct(protected Pulse $pulse)
    {
    }

    public function record(SharedBeat $event): void
    {
        if ($event->time !== $event->time->startOfDay()) {
            return;
        }

        $composer = config('app.composer');
        $devFlag = $this->option('dev') ? '' : '--no-dev';
        // shell_exec('composer2 update');
        $process = Process::fromShellCommandline("$composer audit -f json --locked $devFlag", base_path(), ['COMPOSER_HOME' => '../../.cache/composer']);
        
        $result = $process->run();
        /**
         * @link https://github.com/composer/composer/issues/7323
         */
        if ($result->failed() && '' !== $result->errorOutput()) {
            throw new RuntimeException(message: 'Composer audit failed: '.$result->errorOutput());
        }

        $this->pulse->set(type: 'vulnerable', key: 'result', value: $result->output());
    }
}
