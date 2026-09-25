#!/bin/bash
set -e

echo "Building mldsa-provider..."
cd ../../mldsa-provider
mvn clean package
echo "Copying jar to auth_server/providers..."
cp target/mldsa-provider-1.0-SNAPSHOT.jar ../auth_server/providers/
echo "Done!"
