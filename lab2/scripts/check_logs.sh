#!/bin/bash -e

PWD=$( cd "$(dirname "$0")" ; pwd -P )

THREADS_DIR=$(readlink -e $PWD/threads)

for THREAD_FOLDER in $THREADS_DIR/*
do
    # Check weak keys
    if [ -e "$THREAD_FOLDER/keys/weak.txt" ]
    then
        echo "# WEAK KEYS FOUND IN $THREAD_FOLDER"
    fi

    THREAD_STDERR=$(cat $THREAD_FOLDER/log/stderr.txt)
    if [ ! "$THREAD_STDERR" = "" ]
    then
        echo "# ERROR FOUND IN $THREAD_FOLDER"
    fi 
done
