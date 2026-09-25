Write-Host "Building mldsa-provider..."
Set-Location -Path "..\..\mldsa-provider"
mvn clean package
Write-Host "Copying jar to auth_server\providers..."
Copy-Item -Path "target\mldsa-provider-1.0-SNAPSHOT.jar" -Destination "..\auth_server\providers\" -Force
Write-Host "Done!"
