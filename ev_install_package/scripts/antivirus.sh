#!/bin/bash

#Reset LD_LIBRARY_PATH variable, as it is set by tomcat
export LD_LIBRARY_PATH=""

sourceFile="$1"

#echo "SourceFile is $sourceFile"
clamdscan "${sourceFile}"
