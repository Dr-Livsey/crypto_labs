#!/bin/bash -e

THREADS_DIR=$(readlink -e ../threads)

for THREAD_FOLDER in $THREADS_DIR/*
do
    if [ -e "$THREAD_FOLDER/log/semi-weak_keys.txt" ]
    then
        echo "FOUND IN $THREAD_FOLDER"
    fi
done
