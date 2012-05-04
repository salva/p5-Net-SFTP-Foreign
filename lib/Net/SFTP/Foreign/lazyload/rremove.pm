use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub rremove {
    @_ >= 2 or croak 'Usage: $sftp->rremove($dirs, %opts)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $dirs, %opts) = @_;

    my $on_error = delete $opts{on_error};
    local $sftp->{_autodie} if $on_error;
    my $wanted = _gen_wanted( delete $opts{wanted},
			      delete $opts{no_wanted});

    %opts and _croak_bad_options(keys %opts);

    my $count = 0;

    my @dirs;
    $sftp->find( $dirs,
		 on_error => $on_error,
		 atomic_readdir => 1,
		 wanted => sub {
		     my $e = $_[1];
		     my $fn = $e->{filename};
		     if (_is_dir($e->{a}->perm)) {
			 push @dirs, $e;
		     }
		     else {
			 if (!$wanted or $wanted->($sftp, $e)) {
			     if ($sftp->remove($fn)) {
				 $count++;
			     }
			     else {
				 $sftp->_call_on_error($on_error, $e);
			     }
			 }
		     }
		 } );

    _sort_entries(\@dirs);

    while (@dirs) {
	my $e = pop @dirs;
	if (!$wanted or $wanted->($sftp, $e)) {
	    if ($sftp->rmdir($e->{filename})) {
		$count++;
	    }
	    else {
		$sftp->_call_on_error($on_error, $e);
	    }
	}
    }

    return $count;
}

1;
