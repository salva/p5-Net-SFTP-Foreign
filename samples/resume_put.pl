#!/usr/bin/perl

use strict;
use warnings;

use Net::SFTP::Foreign;

my $base;

sub reset_local {
    $base = join '', map { chr rand 256 } 0..10000;
    create_file(@_);
}

sub create_file {
    my ($len, $name) = @_;
    open my $fh, '>', $name;
    binmode $fh;
    while ($len > 0) {
	print $fh substr $base, 0, $len;
	$len -= length $base
    }
    close $fh;
}

open STDERR, ">/tmp/err";
$Net::SFTP::Foreign::debug = 3+32+128+4096+16384;

my $len = shift;
$| = 1;
my $pwd = `pwd`;
chomp $pwd;

while (1) {
    my $s;
    reset_local($len, "local.txt");
    for (1..100) {
	my $remote = 1 + int rand $len;
	print "$remote ";
	print STDERR "\n\n############################## $remote ################################\n\n";
	$s //= Net::SFTP::Foreign->new('localhost');
	$s->setcwd($pwd);
	
	create_file($remote, "remote.txt");
	$s->put("local.txt", "remote.txt", resume => 1);
	if ($s->error) {
	    undef $s;
	    next
	}
	my $bytes = (stat "remote.txt")[7];
	die "failed for bytes $bytes" if $bytes != $len;
    }
}
