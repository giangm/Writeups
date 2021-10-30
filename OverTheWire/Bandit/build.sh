#!/bin/bash

## Script to build markdown into PDF

## Verify correct number of command line argument
if [ $# -ne 1 ]; then
    echo "Usage: ./build.sh NAME"
    exit 1
fi

cat HEADER > $1.md && cat README.md >> $1.md

## Create PDF from markdown
pandoc --pdf-engine=pdflatex  ./$1.md -o ./pdf/$1.pdf --from markdown --template eisvogel --listings

rm $1.md