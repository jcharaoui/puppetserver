#!/bin/bash

set -e


echo "Installing Java $JAVA_VERSION on arch $TRAVIS_CPU_ARCH"

sudo rm -rf /usr/local/lib/jvm/
sudo rm -rf /usr/lib/jvm/openjdk-$JAVA_VERSION
sudo apt-get update
sudo apt-get install -y openjdk-$JAVA_VERSION-jdk-headless
export JAVA_HOME=/usr/lib/jvm/java-$JAVA_VERSION-openjdk-$TRAVIS_CPU_ARCH/
