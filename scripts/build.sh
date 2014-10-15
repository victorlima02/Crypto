#!/bin/bash

shopt -s globstar
mkdir build
javac -d build src/**/*.java

