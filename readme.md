**Introduction**:

Secure Ip Detector is a simple application to detect any irregularities in connections to our network. It works by collecting the ip information of a user and comparing the previous/subsequent logins attempts into our network.

**Problem Interpretation**:

My interpretation of the problem is:

  - From a post request containing the fields username, unix_timestamp, event_uuid and ip_address, gather the information
  - Find the IP information using the ip_address
  - Get corresponding data regarding the user from the database
  - Compare previous or next entries, and calculate the speed
  - If the speed is over 500 kmph then mark it as suspicious travel
  - Display the information by sending it back to the call
    - Display the current geo information (lat, lon, radius)
    - If a preceeding time stamp entry exists then display its information including the travel speed and depending upon whether the speed was suspicious also display the TravelToCurrentGeoSuspicious flag
    - If a subsequent(or next) time stamp entry exists then display its information including the travel speed and depending upon whether the speed was suspicious also display the TravelFromCurrentGeoSuspicious flag

**Database**:

I have chosen a very simple sqlite3 database structure. Upon gathering a post request it will store the information sent in a table with fields username, unix_timestamp, event_id, and ip_address.
The database will have no entries at the start of the program.
Event uuid is a unique key for each entry - program sends an error if this is not taken care of

**Instructions to run:**

Please install docker and make sure it is running -
Mac - https://download.docker.com/mac/beta/Docker.dmg
Windows - https://hub.docker.com/editions/community/docker-ce-desktop-windows
Download the image and complete installation. Start docker and wait for it to start.

Once docker is installed please follow the following steps:
  - Please download the zip folder secure_application.zip
  - Unzip the contents
  - Head to the secure_application folder
  - Run the following command to generate a docker image: docker build -t secure_application -f Dockerfile .
  - You can find the image created by running the command: docker image ls
  - Start the docker container using command: docker run -d -p 8080:8080 secure_application:latest
  - Now that the docker service container is up and running you can post to localhost at port 8080 and get response
  - Example post command:
    - curl -X POST -d '{"username":"nikhil","unix_timestamp":1549268400,"event_uuid":"67d4e022-8da7-4a66-a13f-45b4bd248439","ip_address":"192.211.59.138"}' http://localhost:8080

**Third-party softwares**:

To find the ip information I have used the MaxMind Geo IP Database:
https://dev.maxmind.com/geoip/geoip2/geolite2/#IP_Geolocation_Usage
To make use of this database in go I have used the package geoip2:
https://godoc.org/github.com/oschwald/geoip2-golang

For the ip detector database I have used sqlite3 and to make connections to the database I have used the go-sqlite3 package:
https://github.com/mattn/go-sqlite3

**Unit Tests**:

As part of every project, unit testing is required. Key components in the program were fetching information from database, fetching ip information, calculating distance and speed. I have written unit tests for each of these key features in the unit_tests folder.

To run the unit_tests:
go test speed_test.go
go test database_test.go

**Challenges**:

As a software developer, one should always be ready to learn new technologies, especially the ones that are powerful and efficient. With no prior experience in GO, it was a challenge to take up a new language and complete the project. Particularly, in the completion of the project I found it challenging to create a multi stage docker image. To overcome this, I found tutorials that would teach me to create a docker container and run my program from there. Exploring the different command line options with different flags to build an executable helped me solve all my problems.
