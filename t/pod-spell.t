use strict;
use warnings;
use Test::More;

eval "use Test::Spelling";
plan skip_all => "Test::Spelling required for testing POD spelling" if $@;

my @ignore = ("Fandi\xf1o", "API", "CPAN", "GitHub", "bugtracking", "IETF", "OpenSSH",
              "FreeBSD", "OpenBSD", "Noria", "LF", "POSIX", "plink", "PuTTY", "Rolsky",
              "SFTP", "STDERR", "STDOUT", "STDIN", "Tectia", "Trott", "UTF", "VMS",
              "Incrementing", "autodie", "autodisconnect", "backend", "canonicalise",
              "de", "facto", "dualvar", "ffs", "zfs", "hardcode", "hardlink", "filename",
              "libssh", "login", "overpassed", "passphrase", "pipelined", "plugable",
              "pre", "realpath", "runtime", "sftp", "stderr", "subdirectories", "tectia",
              "username", "unix", "versa", "wildcard", "wildcards", "wishlist",
               "deserialization", "resumable", "mkpath", "att", "fxp", "HP", "UX");

local $ENV{LC_ALL} = 'C';
add_stopwords(@ignore);
all_pod_files_spelling_ok();

