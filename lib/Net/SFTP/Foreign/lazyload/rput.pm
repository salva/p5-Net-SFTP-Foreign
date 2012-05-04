use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub rput {
    @_ >= 2 or croak 'Usage: $sftp->rput($local, $remote, %opts)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $local, $remote, %opts) = @_;

    defined $local or croak "local path is undefined";
    $remote = '.' unless defined $remote;

    # my $cb = delete $opts{callback};
    my $umask = delete $opts{umask};
    my $copy_perm = delete $opts{exists $opts{copy_perm} ? 'copy_perm' : 'copy_perms'};
    my $copy_time = delete $opts{copy_time};

    my $newer_only = delete $opts{newer_only};
    my $on_error = delete $opts{on_error};
    local $sftp->{_autodie} if $on_error;
    my $ignore_links = delete $opts{ignore_links};

    my $wanted = _gen_wanted( delete $opts{wanted},
			      delete $opts{no_wanted} );

    my %put_opts = (map { $_ => delete $opts{$_} }
		    qw(block_size queue_size overwrite
                       conversion resume numbered
                       late_set_perm atomic best_effort
                       sparse));

    my %put_symlink_opts = (map { $_ => $put_opts{$_} }
                            qw(overwrite numbered));

    %opts and _croak_bad_options(keys %opts);

    require Net::SFTP::Foreign::Local;
    my $lfs = Net::SFTP::Foreign::Local->new;

    $local = $lfs->join($local, './');
    my $relocal;
    if ($local =~ m|^\./?$|) {
	$relocal = qr/^(.*)$/;
    }
    else {
	my $qlocal = quotemeta $local;
	$relocal = qr/^$qlocal(.*)$/i;
    }

    $copy_perm = 1 unless defined $copy_perm;
    $copy_time = 1 unless defined $copy_time;

    $umask = umask unless defined $umask;
    my $mask = ~$umask;

    if ($on_error) {
	my $on_error1 = $on_error;
	$on_error = sub {
	    my $lfs = shift;
	    $sftp->_copy_error($lfs);
	    $sftp->_call_on_error($on_error1, @_);
	}
    }

    my $count = 0;
    $lfs->find( [$local],
		descend => sub {
		    my $e = $_[1];
		    # print "descend: $e->{filename}\n";
		    if (!$wanted or $wanted->($lfs, $e)) {
			my $fn = $e->{filename};
			$debug and $debug & 32768 and _debug "rput handling $fn";
			if ($fn =~ $relocal) {
			    my $rpath = $sftp->join($remote, File::Spec->splitdir($1));
			    $debug and $debug & 32768 and _debug "rpath: $rpath";
			    if ($sftp->test_d($rpath)) {
				$lfs->_set_error(SFTP_ERR_REMOTE_ALREADY_EXISTS,
						 "Remote directory '$rpath' already exists");
				$lfs->_call_on_error($on_error, $e);
				return 1;
			    }
			    else {
				my $a = Net::SFTP::Foreign::Attributes->new;
				$a->set_perm(($copy_perm ? $e->{a}->perm & 0777 : 0777) & $mask);
				if ($sftp->mkdir($rpath, $a)) {
				    $count++;
				    return 1;
				}
				else {
				    $lfs->_copy_error($sftp);
				}
			    }
			}
			else {
			    $lfs->_set_error(SFTP_ERR_LOCAL_BAD_PATH,
					      "Bad local path '$fn'");
			}
			$lfs->_call_on_error($on_error, $e);
		    }
		    return undef;
		},
		wanted => sub {
		    my $e = $_[1];
		    # print "file fn:$e->{filename}, a:$e->{a}\n";
		    unless (_is_dir($e->{a}->perm)) {
			if (!$wanted or $wanted->($lfs, $e)) {
			    my $fn = $e->{filename};
			    $debug and $debug & 32768 and _debug "rput handling $fn";
			    if ($fn =~ $relocal) {
				my (undef, $d, $f) = File::Spec->splitpath($1);
				my $rpath = $sftp->join($remote, File::Spec->splitdir($d), $f);
				if (_is_lnk($e->{a}->perm) and !$ignore_links) {
				    if ($sftp->put_symlink($fn, $rpath,
                                                           %put_symlink_opts)) {
					$count++;
					return undef;
				    }
				    $lfs->_copy_error($sftp);
				}
				elsif (_is_reg($e->{a}->perm)) {
				    my $ra;
				    if ( $newer_only and
					 $ra = $sftp->stat($rpath) and
					 $ra->mtime >= $e->{a}->mtime) {
					$lfs->_set_error(SFTP_ERR_REMOTE_ALREADY_EXISTS,
							 "Newer remote file '$rpath' already exists");
				    }
				    else {
					if ($sftp->put($fn, $rpath,
						       perm => ($copy_perm ? $e->{a}->perm : 0777) & $mask,
						       copy_time => $copy_time,
                                                       %put_opts)) {
					    $count++;
					    return undef;
					}
					$lfs->_copy_error($sftp);
				    }
				}
				else {
				    $lfs->_set_error(SFTP_ERR_LOCAL_BAD_OBJECT,
						      ( $ignore_links
							? "Local file '$fn' is not regular file or directory"
							: "Local file '$fn' is not regular file, directory or link"));
				}
			    }
			    else {
				$lfs->_set_error(SFTP_ERR_LOCAL_BAD_PATH,
						  "Bad local path '$fn'");
			    }
			    $lfs->_call_on_error($on_error, $e);
			}
		    }
		    return undef;
		} );

    return $count;
}

1;
