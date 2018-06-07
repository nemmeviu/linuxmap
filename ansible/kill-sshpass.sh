#!/bin/bash

[[ $KILL_TIME ]] || KILL_TIME=1200

SLEEP="yes"
while [ "$SLEEP" == "yes" ]; do
    sleep $KILL_TIME
    SLEEP="no"
done

while ps aux | grep sshpas |grep -v grep ; do
    for sshproc in $(ps aux | grep sshpas |grep -v grep | awk '{print $2}'); do 
	kill "$sshproc"
    done
done

