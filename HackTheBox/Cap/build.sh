#!/bin/bash

## Script to build markdown into PDF

## Verify correct number of command line argument
if [ $# -ne 1 ]; then
    echo "Usage: ./build.sh BOX-NAME"
    exit 1
fi

cat HEADER > HTB-$1.md && cat README.md >> HTB-$1.md

## Create PDF from markdown
pandoc --pdf-engine=pdflatex  ./HTB-$1.md -o ./pdf/HTB-$1.pdf --from markdown --template eisvogel --listings