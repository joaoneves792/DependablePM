# DependablePM
Dependable Password Manager (SEC Project)

# Protocol
![Protocol](Protocol.jpg)

# How to compile and execute tests
- Extract zip file contents
- (Optional step - Generate new keypairs) Go to <folder>/CA and run ./generateKeystores.sh
- (Optional step - Copy new Java Keystores) run  
  cp generated-keystores/Client1/Client1.jks ../pm-client/  
  cp generated-keystores/DependablePMServer/DependablePMServer.jks ../pm-server/  
- Go to <folder>/crypto-lib and run 'mvn clean compile install'
- Go to <folder>/pm-server and run 'mvn clean compile install exec:java'
- Go to <folder>/pm-client and run 'mvn test' to run demonstration tests
