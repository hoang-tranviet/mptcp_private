#!/bin/bash

# If sshd requires password, create new key pair by:
#   ssh-keygen
# then add the public key to authorized key:
#   cat .ssh/authorized_keys >> .ssh/authorized_keys

#echo -e "start rsync"

server=$1
server_alt=$2
id=$3
path=`pwd`
src="foo.data"

dst="./${src}copied."$id

rm $dst 2> /dev/null


#rsync  --progress --partial --append -v  \
rsync  --partial --append --bwlimit=10 --timeout 2 \
	-e "ssh -i /home/vagrant/.ssh/id_rsa" \
	vagrant@$server:$path/$src $dst
if [ "$?" = "0" ] ; then
#	echo "rsync completed"
else
#	echo "rsync to $1 failed. Continue with $2..."
	rsync   --partial --append \
		-e "ssh -i /home/vagrant/.ssh/id_rsa" \
		vagrant@$server_alt:$path/$src $dst
#	echo "done"
fi
