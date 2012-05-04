use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub rget {
    @_ >= 2 or croak 'Usage: $sftp->rget($remote, $local, %opts)';
    ${^TAINT} and &_catch_tainted_args;
    my ($sftp, $remote, $local, %opts) = @_;

    defined $remote or croak "remote file path is undefined";
    $local = File::Spec->curdir unless defined $local;

    # my $cb = delete $opts{callback};
    my $umask = delete $opts{umask};
    my $copy_perm = delete $opts{exists $opts{copy_perm} ? 'copy_perm' : 'copy_perms'};
    my $copy_time = delete $opts{copy_time};
    my $newer_only = delete $opts{newer_only};
    my $on_error = delete $opts{on_error};
    local $sftp->{_autodie} if $on_error;
    my $ignore_links = delete $opts{ignore_links};

    # my $relative_links = delete $opts{relative_links};

    my $wanted = _gen_wanted( delete $opts{wanted},
			      delete $opts{no_wanted} );

    my %get_opts = (map { $_ => delete $opts{$_} }
                    qw(block_size queue_size overwrite conversion
                       resume numbered atomic best_effort));

    if ($get_opts{resume} and $get_opts{conversion}) {
        carp "resume option is useless when data conversion has also been requested";
        delete $get_opts{resume};
    }

    my %get_symlink_opts = (map { $_ => $get_opts{$_} }
                            qw(overwrite numbered));

    %opts and _croak_bad_options(keys %opts);

    $remote = $sftp->join($remote, './');
    my $qremote = quotemeta $remote;
    my $reremote = qr/^$qremote(.*)$/i;

    my $save = _umask_save_and_set $umask;

    $copy_perm = 1 unless defined $copy_perm;
    $copy_time = 1 unless defined $copy_time;

    require File::Spec;

    my $count = 0;
    $sftp->find( [$remote],
		 descend => sub {
		     my $e = $_[1];
		     # print "descend: $e->{filename}\n";
		     if (!$wanted or $wanted->($sftp, $e)) {
			 my $fn = $e->{filename};
			 if ($fn =~ $reremote) {
			     my $lpath = File::Spec->catdir($local, $1);
                             ($lpath) = $lpath =~ /(.*)/ if ${^TAINT};
			     if (-d $lpath) {
				 $sftp->_set_error(SFTP_ERR_LOCAL_ALREADY_EXISTS,
						   "directory '$lpath' already exists");
				 $sftp->_call_on_error($on_error, $e);
				 return 1;
			     }
			     else {
				 if (CORE::mkdir $lpath, ($copy_perm ? $e->{a}->perm & 0777 : 0777)) {
				     $count++;
				     return 1;
				 }
				 else {
				     $sftp->_set_error(SFTP_ERR_LOCAL_MKDIR_FAILED,
						       "mkdir '$lpath' failed", $!);
				 }
			     }
			 }
			 else {
			     $sftp->_set_error(SFTP_ERR_REMOTE_BAD_PATH,
					       "bad remote path '$fn'");
			 }
			 $sftp->_call_on_error($on_error, $e);
		     }
		     return undef;
		 },
		 wanted => sub {
		     my $e = $_[1];
		     # print "file fn:$e->{filename}, a:$e->{a}\n";
		     unless (_is_dir($e->{a}->perm)) {
			 if (!$wanted or $wanted->($sftp, $e)) {
			     my $fn = $e->{filename};
			     if ($fn =~ $reremote) {
				 my $lpath = File::Spec->catfile($local, $1);
                                 ($lpath) = $lpath =~ /(.*)/ if ${^TAINT};
				 if (_is_lnk($e->{a}->perm) and !$ignore_links) {
				     if ($sftp->get_symlink($fn, $lpath,
							    copy_time => $copy_time,
                                                            %get_symlink_opts)) {
					 $count++;
					 return undef;
				     }
				 }
				 elsif (_is_reg($e->{a}->perm)) {
				     if ($newer_only and -e $lpath
					 and (CORE::stat _)[9] >= $e->{a}->mtime) {
					 $sftp->_set_error(SFTP_ERR_LOCAL_ALREADY_EXISTS,
							   "newer local file '$lpath' already exists");
				     }
				     else {
					 if ($sftp->get($fn, $lpath,
							copy_perm => $copy_perm,
							copy_time => $copy_time,
                                                        %get_opts)) {
					     $count++;
					     return undef;
					 }
				     }
				 }
				 else {
				     $sftp->_set_error(SFTP_ERR_REMOTE_BAD_OBJECT,
						       ( $ignore_links
							 ? "remote file '$fn' is not regular file or directory"
							 : "remote file '$fn' is not regular file, directory or link"));
				 }
			     }
			     else {
				 $sftp->_set_error(SFTP_ERR_REMOTE_BAD_PATH,
						   "bad remote path '$fn'");
			     }
			     $sftp->_call_on_error($on_error, $e);
			 }
		     }
		     return undef;
		 } );

    return $count;
}

1;
