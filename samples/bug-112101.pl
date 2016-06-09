use Net::SFTP::Foreign;

use strict;
use warnings;

use threads;

$| = 1;

$Net::SFTP::Foreign::debug = -1;

my $host = shift // 'localhost';

my %args = (host => $host,
            timeout => 5);

$args{ssh_cmd} = 'C:\\cygwin\\bin\\ssh.exe' if $^O eq 'MSWin32';

sub sftp_thread {
    my $sftp = Net::SFTP::Foreign->new(%args);
    if($sftp->error) {
        print "Failed to connect: " . $sftp->error . "\n";
        # workaround
        #kill "KILL",$sftp->{pid} if($sftp->{pid} =~ /^\d+$/);
    }
    else {
        print "Connected successfully\n";
    }
}

# without this, main thread dies with "Alarm clock"
#$SIG{ALRM} = 'a';

# start a thread that will take more than 10 seconds to login

my ($t) = threads->create('sftp_thread');

print "Thread started\n";

$t->join();

print "Thread finished\n";

# no problem when not used in separate thread

#&sftp_thread;


