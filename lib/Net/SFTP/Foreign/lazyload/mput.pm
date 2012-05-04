use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub mput {
    @_ >= 2 or croak 'Usage: $sftp->mput($local, $remotedir, %opts)';

    my ($sftp, $local, $remotedir, %opts) = @_;

    defined $local or die "local pattern is undefined";

    my $on_error = $opts{on_error};
    local $sftp->{_autodie} if $on_error;
    my $ignore_links = delete $opts{ignore_links};

    my %glob_opts = (map { $_ => delete $opts{$_} }
		     qw(on_error follow_links ignore_case
                        wanted no_wanted strict_leading_dot));
    my %put_symlink_opts = (map { $_ => $opts{$_} }
			    qw(overwrite numbered));

    my %put_opts = (map { $_ => delete $opts{$_} }
		    qw(umask perm copy_perm copy_time block_size queue_size
                       overwrite conversion resume numbered late_set_perm
                       atomic best_effort sparse));

    %opts and _croak_bad_options(keys %opts);

    require Net::SFTP::Foreign::Local;
    my $lfs = Net::SFTP::Foreign::Local->new;
    my @local = map $lfs->glob($_, %glob_opts), _ensure_list $local;

    my $count = 0;
    require File::Spec;
    for my $e (@local) {
	my $perm = $e->{a}->perm;
	if (_is_dir($perm)) {
	    $sftp->_set_error(SFTP_ERR_REMOTE_BAD_OBJECT,
			      "Remote object '$e->{filename}' is a directory");
	}
	else {
	    my $fn = $e->{filename};
	    my $remote = (File::Spec->splitpath($fn))[2];
	    $remote = $sftp->join($remotedir, $remote)
		if defined $remotedir;

	    if (_is_lnk($perm)) {
		next if $ignore_links;
		$sftp->put_symlink($fn, $remote, %put_symlink_opts);
	    }
	    else {
		$sftp->put($fn, $remote, %put_opts);
	    }
	}
	$count++ unless $sftp->{_error};
	$sftp->_call_on_error($on_error, $e);
    }
    $count;
}

1;
