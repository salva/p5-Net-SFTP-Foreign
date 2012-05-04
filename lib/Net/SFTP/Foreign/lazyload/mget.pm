use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub mget {
    @_ >= 2 or croak 'Usage: $sftp->mget($remote, $localdir, %opts)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $remote, $localdir, %opts) = @_;

    defined $remote or croak "remote pattern is undefined";

    my $on_error = $opts{on_error};
    local $sftp->{_autodie} if $on_error;
    my $ignore_links = delete $opts{ignore_links};

    my %glob_opts = (map { $_ => delete $opts{$_} }
		     qw(on_error follow_links ignore_case
                        wanted no_wanted strict_leading_dot));

    my %get_symlink_opts = (map { $_ => $opts{$_} }
			    qw(overwrite numbered));

    my %get_opts = (map { $_ => delete $opts{$_} }
		    qw(umask perm copy_perm copy_time block_size queue_size
                       overwrite conversion resume numbered atomic best_effort));

    %opts and _croak_bad_options(keys %opts);

    my @remote = map $sftp->glob($_, %glob_opts), _ensure_list $remote;

    my $count = 0;

    require File::Spec;
    for my $e (@remote) {
	my $perm = $e->{a}->perm;
	if (_is_dir($perm)) {
	    $sftp->_set_error(SFTP_ERR_REMOTE_BAD_OBJECT,
			      "Remote object '$e->{filename}' is a directory");
	}
	else {
	    my $fn = $e->{filename};
	    my ($local) = $fn =~ m{([^\\/]*)$};

	    $local = File::Spec->catfile($localdir, $local)
		if defined $localdir;

	    if (_is_lnk($perm)) {
		next if $ignore_links;
		$sftp->get_symlink($fn, $local, %get_symlink_opts);
	    }
	    else {
		$sftp->get($fn, $local, %get_opts);
	    }
	}
	$count++ unless $sftp->{_error};
	$sftp->_call_on_error($on_error, $e);
    }
    $count;
}

1;
