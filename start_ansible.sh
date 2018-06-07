#!/bin/sh

./ansible/kill_sshpass.sh &

ansible-playbook $1
