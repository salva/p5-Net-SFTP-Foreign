use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub mkpath {
    (@_ >= 2 and @_ <= 3)
        or croak 'Usage: $sftp->mkpath($path [, $attrs])';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $path, $attrs) = @_;
    $sftp->_clear_error_and_status;

    $path =~ s{^(/*)}{};
    my $start = $1;
    my @path;
    while (1) {
	my $p = "$start$path";
	$debug and $debug & 8192 and _debug "checking $p";
	if ($sftp->test_d($p)) {
	    $debug and $debug & 8192 and _debug "$p is a dir";
	    last;
	}
	unless (length $path) {
	    $sftp->_set_error(SFTP_ERR_REMOTE_MKDIR_FAILED,
                              "Unable to make path, bad root");
	    return undef;
	}
	unshift @path, $p;
	$path =~ s{/*[^/]*$}{};
    }
    for my $p (@path) {
	$debug and $debug & 8192 and _debug "mkdir $p";
	if ($p =~ m{^(?:.*/)?\.{1,2}$} or $p =~ m{/$}) {
	    $debug and $debug & 8192 and _debug "$p is a symbolic dir, skipping";
	    unless ($sftp->test_d($p)) {
		$debug and $debug & 8192 and _debug "symbolic dir $p can not be checked";
		$sftp->{_error} or
		    $sftp->_set_error(SFTP_ERR_REMOTE_MKDIR_FAILED,
				      "Unable to make path, bad name");
		return undef;
	    }
	}
	else {
	    $sftp->mkdir($p, $attrs)
                or return undef;
	}
    }
    1;
}

1;
