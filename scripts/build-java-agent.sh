#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mvn -B -f java-agent/pom.xml package
mkdir -p bin
cp java-agent/target/traffic-java-agent.jar bin/traffic-java-agent.jar
