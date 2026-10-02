@echo off
REM Build the APIProxy Java (Spring Boot) port using the vendored Maven.
REM   - java/.maven/ is the project-bundled Maven 3.9.16 (no system install needed).
REM   - The JDK on PATH (OpenJDK 25) can compile the Java 21 target.
REM   - FIRST build needs network access to fetch Spring Boot dependencies.
cd /d %~dp0
set MAVEN=%~dp0java\.maven\bin\mvn.cmd
if not exist "%MAVEN%" (echo vendored maven missing & exit /b 1)
"%MAVEN%" -f %~dp0java\pom.xml clean package -DskipTests
if %ERRORLEVEL%==0 (echo BUILD OK: java\target\apiproxy-1.0.0.jar)
