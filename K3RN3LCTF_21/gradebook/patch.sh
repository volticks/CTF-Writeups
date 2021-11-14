#!/bin/bash

patchelf ./gradebook --set-interpreter ./ld-2.31.so
patchelf ./gradebook --replace-needed libc.so.6 ./libc.so.6
